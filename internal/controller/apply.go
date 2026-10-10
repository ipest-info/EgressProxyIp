package controller

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/ipest-info/EgressProxyIp/internal/fw"
	"github.com/ipest-info/EgressProxyIp/internal/gost"
	"github.com/ipest-info/EgressProxyIp/internal/health"
	"github.com/ipest-info/EgressProxyIp/internal/model"
	"github.com/ipest-info/EgressProxyIp/internal/store"
)

// Verify 是应用后对真实出口的校验结果。
type Verify struct {
	At       time.Time `json:"at"`
	OK       bool      `json:"ok"`
	Skipped  bool      `json:"skipped"`
	RealIP   string    `json:"realIp,omitempty"`   // 普通进程实际的出口 IP
	RealIPs  []string  `json:"realIps,omitempty"`  // 各回显服务的结果
	DirectIP string    `json:"directIp,omitempty"` // ECS 自身的公网 IP
	Message  string    `json:"message"`
}

// ApplyResult 返回给 WebUI。
type ApplyResult struct {
	Nonce    string    `json:"nonce,omitempty"`
	Deadline time.Time `json:"deadline,omitempty"`
	Verify   *Verify   `json:"verify,omitempty"`
	Message  string    `json:"message"`
}

func (c *Controller) gostConfigPath() string { return filepath.Join(c.opt.RunDir, "gost.json") }

// nodesFor 根据策略与健康状态计算 hop 中的真实节点。
func (c *Controller) nodesFor(st model.State) ([]model.Proxy, bool) {
	cur := ""
	if len(c.hopIDs) > 0 {
		cur = c.hopIDs[0]
	}
	return health.Order(st, c.health, cur)
}

func ids(ps []model.Proxy) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.ID)
	}
	return out
}

// activate 让 st 成为实际生效的配置：启动/重启 gost 并下发规则。调用方持有 c.mu。
func (c *Controller) activate(ctx context.Context, st model.State) error {
	if err := st.Validate(); err != nil {
		return err
	}
	if c.fwErr != nil {
		return c.fwErr
	}
	for id := range c.health {
		if st.FindProxy(id) < 0 {
			delete(c.health, id)
		}
	}
	nodes, down := c.nodesFor(st)
	if err := c.startEngine(ctx, st, nodes); err != nil {
		return err
	}
	c.hopIDs = ids(nodes)
	c.degraded = down && !st.Policy.KillSwitch
	rs := fw.Plan(c.fwInput(ctx, st), true)
	if c.degraded {
		c.log.Warn("全部代理不可用且 kill switch 关闭：暂不拦截流量（直连）")
		c.cleanupRules(ctx, st.Settings)
	} else if err := c.fw.Apply(ctx, rs); err != nil {
		return err
	}
	c.rules = rs
	c.live = &st
	c.engineDown = false
	return nil
}

// deactivate 撤销拦截规则并停止 gost。调用方持有 c.mu。
func (c *Controller) deactivate(ctx context.Context, st model.State) {
	c.cleanupRules(ctx, st.Settings)
	c.rules = fw.Ruleset{}
	if c.engine != nil {
		c.engine.Stop()
	}
	c.live = nil
	c.hopIDs = nil
	c.degraded = false
}

// startEngine 写入 gost 配置并（重新）启动 gost，等待其就绪。
func (c *Controller) startEngine(ctx context.Context, st model.State, nodes []model.Proxy) error {
	cfg := gost.Render(gost.Input{State: st, Nodes: nodes, APIPassword: c.apiPassword})
	if err := store.WriteFile(c.gostConfigPath(), cfg.JSON(), 0o600); err != nil {
		return fmt.Errorf("写入 gost 配置失败: %w", err)
	}
	if c.opt.DryRun {
		c.gostVersion = "dry-run"
		return nil
	}
	v, err := gost.CheckBinary(ctx, st.Settings.GostBin)
	if err != nil {
		c.gostErr = err.Error()
		return err
	}
	c.gostVersion, c.gostErr = v.String(), ""
	if c.engine != nil {
		c.engine.Stop()
	}
	// gost 停止后检查端口是否被其他程序占用。
	for _, p := range []struct {
		proto string
		port  int
		name  string
	}{{"tcp", st.Settings.RedirPort, "TCP 重定向"}, {"udp", st.Settings.TProxyPort, "UDP 透明代理"}, {"tcp", st.Settings.APIPort, "gost API"}, {"tcp", st.Settings.MetricsPort, "gost 指标"}} {
		if p.proto == "udp" && st.Policy.UDPMode != model.UDPProxy {
			continue
		}
		if c.opt.Sys.PortInUse(p.proto, p.port) {
			return fmt.Errorf("%s 端口 %d/%s 已被其他程序占用，请在设置中修改", p.name, p.port, p.proto)
		}
	}
	c.engine = gost.NewProcess(st.Settings.GostBin, c.gostConfigPath(), c.log)
	c.engine.OnExit = c.onEngineExit
	if err := c.engine.Start(); err != nil {
		return err
	}
	c.api = gost.NewAPI(st.Settings.APIPort, c.apiPassword)
	deadline := time.Now().Add(10 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		if !c.engine.Running() {
			return fmt.Errorf("gost 启动后立即退出:\n%s", tail(c.engine.Logs(), 10))
		}
		pctx, cancel := context.WithTimeout(ctx, time.Second)
		last = c.api.Ping(pctx)
		cancel()
		if last == nil && c.opt.Sys.PortInUse("tcp", st.Settings.RedirPort) {
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	c.engine.Stop()
	return fmt.Errorf("gost 未能在 10 秒内就绪: %v\n%s", last, tail(c.engine.Logs(), 10))
}

func tail(lines []string, n int) string {
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// onEngineExit 处理 gost 意外退出：kill switch 关闭时先撤掉规则避免断网，然后退避重启。
func (c *Controller) onEngineExit(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopping || c.live == nil {
		return
	}
	c.engineDown = true
	st := *c.live
	c.Audit.Add("system", "gost 意外退出", fmt.Sprint(err), false)
	if !st.Policy.KillSwitch {
		c.cleanupRules(context.Background(), st.Settings)
	}
	c.restartN++
	delay := time.Duration(1<<min(c.restartN, 6)) * time.Second
	c.log.Warn("将重启 gost", "等待", delay.String())
	time.AfterFunc(delay, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.stopping || c.live == nil || !c.engineDown {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := c.activate(ctx, *c.live); err != nil {
			c.log.Error("重启 gost 失败", "错误", err.Error())
			c.Audit.Add("system", "重启 gost", err.Error(), false)
			return
		}
		c.restartN = 0
		c.Audit.Add("system", "重启 gost", "已恢复", true)
	})
}

// Apply 应用当前编辑的状态。启用出口代理时进入“待确认”，在超时前未确认会自动回滚。
func (c *Controller) Apply(ctx context.Context, skipVerify bool) (*ApplyResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending != nil {
		return nil, errPending
	}
	next := clone(c.state)
	if err := next.Validate(); err != nil {
		return nil, err
	}
	prev := c.applied
	if !next.Enabled {
		c.deactivate(ctx, next)
		c.applied = &store.Applied{State: next, AppliedAt: time.Now()}
		if err := c.store.SaveApplied(c.applied); err != nil {
			return nil, err
		}
		c.Audit.Add("admin", "停用出口代理", "已恢复使用 ECS 自身 IP 出网", true)
		return &ApplyResult{Message: "已停用出口代理，流量恢复直连"}, nil
	}
	if err := c.activate(ctx, next); err != nil {
		c.Audit.Add("admin", "应用配置", err.Error(), false)
		c.restore(ctx, prev)
		return nil, fmt.Errorf("应用失败，已回滚: %w", err)
	}
	v := c.verify(ctx, next, skipVerify)
	c.lastVerify = v
	if !v.OK {
		c.Audit.Add("admin", "应用配置", "出口校验失败: "+v.Message, false)
		c.restore(ctx, prev)
		return &ApplyResult{Verify: v, Message: "出口校验失败，已回滚"}, fmt.Errorf("出口校验失败，已回滚: %s", v.Message)
	}
	p := &pendingApply{nonce: randomHex(12), deadline: time.Now().Add(c.opt.ConfirmTimeout), prev: prev, next: next}
	p.timer = time.AfterFunc(c.opt.ConfirmTimeout, func() { c.timeout(p.nonce) })
	c.pending = p
	c.store.SavePending(&store.Pending{Nonce: p.nonce, Deadline: p.deadline})
	c.Audit.Add("admin", "应用配置", "等待确认: "+v.Message, true)
	return &ApplyResult{Nonce: p.nonce, Deadline: p.deadline, Verify: v, Message: "已生效，请在倒计时结束前确认，否则自动回滚"}, nil
}

// restore 回到 prev（为空则彻底停用）。调用方持有 c.mu。
func (c *Controller) restore(ctx context.Context, prev *store.Applied) {
	if prev == nil || !prev.State.Enabled {
		st := c.state
		if prev != nil {
			st = prev.State
		}
		c.deactivate(ctx, st)
		return
	}
	if err := c.activate(ctx, prev.State); err != nil {
		c.log.Error("回滚到上一次配置失败", "错误", err.Error())
		c.Audit.Add("system", "回滚", err.Error(), false)
		c.failSafe(ctx, prev.State)
	}
}

// Confirm 确认待生效的配置。
func (c *Controller) Confirm(nonce string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.pending
	if p == nil {
		return errors.New("没有待确认的应用（可能已超时回滚）")
	}
	if p.nonce != nonce {
		return errors.New("确认码不匹配")
	}
	p.timer.Stop()
	c.pending = nil
	c.applied = &store.Applied{State: p.next, AppliedAt: time.Now()}
	if err := c.store.SaveApplied(c.applied); err != nil {
		return err
	}
	c.store.SavePending(nil)
	c.Audit.Add("admin", "确认应用", "配置已保存为当前生效配置", true)
	return nil
}

// Revert 立即回滚待确认的配置。
func (c *Controller) Revert(nonce string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.pending
	if p == nil || p.nonce != nonce {
		return errors.New("没有对应的待确认应用")
	}
	p.timer.Stop()
	c.rollbackLocked("admin", "手动回滚")
	return nil
}

func (c *Controller) timeout(nonce string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending == nil || c.pending.nonce != nonce || c.stopping {
		return
	}
	c.rollbackLocked("system", "超时未确认，自动回滚")
}

func (c *Controller) rollbackLocked(actor, reason string) {
	p := c.pending
	c.pending = nil
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c.restore(ctx, p.prev)
	c.store.SavePending(nil)
	c.Audit.Add(actor, "回滚", reason, true)
	c.log.Warn("已回滚到上一次确认的配置", "原因", reason)
}

// verify 校验普通进程的出口 IP 已不再是 ECS 自身的 IP。
func (c *Controller) verify(ctx context.Context, st model.State, skip bool) *Verify {
	v := &Verify{At: time.Now()}
	if skip || c.opt.DryRun {
		v.OK, v.Skipped, v.Message = true, true, "已跳过出口校验"
		return v
	}
	pr := c.prober(st)
	direct := ""
	if c.meta != nil {
		direct = c.meta.PublicIP
	}
	if direct == "" {
		direct = pr.DirectEgress(ctx).Consensus
	}
	v.DirectIP = direct
	real := pr.RealEgress(ctx)
	v.RealIPs, v.RealIP = real.IPs, real.Consensus
	switch {
	case v.RealIP == "" && st.Policy.KillSwitch && len(st.EnabledProxies()) > 0:
		v.Message = "经代理无法访问 IP 回显服务：" + real.Error
	case v.RealIP == "":
		v.Message = "无法获取出口 IP：" + real.Error
	case direct != "" && v.RealIP == direct:
		v.Message = fmt.Sprintf("出口 IP 仍是 ECS 自身的 %s，流量没有经过代理", direct)
	default:
		v.OK = true
		v.Message = fmt.Sprintf("当前出口 IP: %s（ECS 自身 IP: %s）", v.RealIP, orDash(direct))
	}
	return v
}

func orDash(s string) string {
	if s == "" {
		return "未知"
	}
	return s
}

// healthLoop 定期检查已生效配置中的代理，并在需要时切换出口节点。
func (c *Controller) healthLoop() {
	defer c.wg.Done()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-timer.C:
		}
		c.mu.Lock()
		var st *model.State
		if c.live != nil {
			s := clone(*c.live)
			st = &s
		}
		c.mu.Unlock()
		interval := 30 * time.Second
		if st != nil {
			interval = time.Duration(st.Policy.HealthInterval) * time.Second
			if !c.opt.DryRun {
				c.checkHealth(*st)
			}
		}
		timer.Reset(interval)
	}
}

type checkResult struct {
	id      string
	latency time.Duration
	err     error
}

func (c *Controller) checkHealth(st model.State) {
	pr := c.prober(st)
	proxies := st.EnabledProxies()
	ch := make(chan checkResult, len(proxies))
	for _, p := range proxies {
		go func(p model.Proxy) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			lat, err := pr.Health(ctx, p)
			ch <- checkResult{p.ID, lat, err}
		}(p)
	}
	results := make([]checkResult, 0, len(proxies))
	for range proxies {
		results = append(results, <-ch)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.live == nil || c.stopping {
		return
	}
	now := time.Now()
	live := *c.live
	for _, r := range results {
		errStr := ""
		if r.err != nil {
			errStr = r.err.Error()
		}
		prev := c.health[r.id]
		s := health.Observe(prev, r.err == nil, r.latency, errStr, live.Policy.FailThreshold, live.Policy.RecoverThreshold, now)
		c.health[r.id] = s
		if prev.Known && prev.Healthy != s.Healthy {
			name := r.id
			if i := live.FindProxy(r.id); i >= 0 {
				name = live.Proxies[i].Name
			}
			if s.Healthy {
				c.Audit.Add("health", "代理恢复", name, true)
			} else {
				c.Audit.Add("health", "代理不可用", name+": "+errStr, false)
			}
		}
	}
	c.reconcileHop(live)
}

// reconcileHop 让 gost 中的节点顺序与健康状态一致；必要时进入/退出“降级直连”。
func (c *Controller) reconcileHop(st model.State) {
	if c.engineDown {
		return
	}
	nodes, down := c.nodesFor(st)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	newIDs := ids(nodes)
	if strings.Join(newIDs, ",") != strings.Join(c.hopIDs, ",") && c.api != nil {
		if err := c.api.UpdateHop(ctx, gost.RenderHop(st, nodes)); err != nil {
			c.log.Error("更新 gost 出口节点失败", "错误", err.Error())
		} else {
			from, to := c.nameOf(st, c.hopIDs), c.nameOf(st, newIDs)
			c.hopIDs = newIDs
			if len(nodes) == 0 && st.Policy.KillSwitch {
				c.Audit.Add("health", "全部代理不可用", "kill switch 生效，出网已阻断", false)
			} else if from != to {
				c.Audit.Add("health", "切换出口代理", from+" → "+to, true)
			}
		}
	}
	if st.Policy.KillSwitch {
		return
	}
	switch {
	case down && !c.degraded:
		c.degraded = true
		c.cleanupRules(ctx, st.Settings)
		c.Audit.Add("health", "全部代理不可用", "kill switch 已关闭，暂时恢复直连", false)
	case !down && c.degraded:
		if err := c.fw.Apply(ctx, c.rules); err != nil {
			c.log.Error("恢复拦截规则失败", "错误", err.Error())
			return
		}
		c.degraded = false
		c.Audit.Add("health", "代理恢复", "已重新启用出口代理", true)
	}
}

func (c *Controller) nameOf(st model.State, ids []string) string {
	if len(ids) == 0 {
		return "无"
	}
	if i := st.FindProxy(ids[0]); i >= 0 {
		return st.Proxies[i].Name
	}
	return ids[0]
}

// driftLoop 每 30 秒检查规则是否被 firewalld、Docker 或手工操作破坏，并自动修复。
func (c *Controller) driftLoop() {
	defer c.wg.Done()
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-t.C:
		}
		c.mu.Lock()
		if c.live != nil && !c.degraded && c.fw != nil && c.fwErr == nil && !c.opt.DryRun {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			if problems := c.fw.Check(ctx, c.rules); len(problems) > 0 {
				if err := c.fw.Apply(ctx, c.rules); err != nil {
					c.Audit.Add("system", "修复防火墙规则", err.Error(), false)
				} else {
					c.Audit.Add("system", "修复防火墙规则", strings.Join(problems, "；"), true)
				}
			}
			cancel()
		}
		c.mu.Unlock()
	}
}
