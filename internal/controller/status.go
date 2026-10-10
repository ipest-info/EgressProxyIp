package controller

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/ipest-info/EgressProxyIp/internal/aliyun"
	"github.com/ipest-info/EgressProxyIp/internal/fw"
	"github.com/ipest-info/EgressProxyIp/internal/gost"
	"github.com/ipest-info/EgressProxyIp/internal/health"
	"github.com/ipest-info/EgressProxyIp/internal/probe"
)

// Status 是仪表盘展示的运行状态。
type Status struct {
	Enabled     bool                     `json:"enabled"` // 已生效的配置是否启用了出口代理
	Active      bool                     `json:"active"`  // 拦截规则当前是否生效
	Dirty       bool                     `json:"dirty"`   // 有未应用的修改
	DryRun      bool                     `json:"dryRun"`
	Pending     *PendingInfo             `json:"pending,omitempty"`
	Degraded    bool                     `json:"degraded"` // 全部代理不可用，已临时直连
	KillSwitch  bool                     `json:"killSwitch"`
	Mode        string                   `json:"mode"`
	UDPMode     string                   `json:"udpMode"`
	CurrentID   string                   `json:"currentId,omitempty"`
	CurrentName string                   `json:"currentName,omitempty"`
	Blackholed  bool                     `json:"blackholed"` // kill switch 生效，出网被阻断
	Engine      EngineInfo               `json:"engine"`
	Firewall    FirewallInfo             `json:"firewall"`
	Health      map[string]health.Status `json:"health"`
	ECS         *aliyun.Info             `json:"ecs,omitempty"`
	ECSError    string                   `json:"ecsError,omitempty"`
	Conntrack   [2]int                   `json:"conntrack"`
	Traffic     *gost.Traffic            `json:"traffic,omitempty"`
	LastVerify  *Verify                  `json:"lastVerify,omitempty"`
	AppliedAt   time.Time                `json:"appliedAt,omitempty"`
}

// PendingInfo 描述待确认的应用。
type PendingInfo struct {
	Nonce    string    `json:"nonce"`
	Deadline time.Time `json:"deadline"`
}

// EngineInfo 描述 gost 进程。
type EngineInfo struct {
	Running bool      `json:"running"`
	PID     int       `json:"pid,omitempty"`
	Since   time.Time `json:"since,omitempty"`
	Version string    `json:"version,omitempty"`
	Error   string    `json:"error,omitempty"`
}

// FirewallInfo 描述防火墙后端。
type FirewallInfo struct {
	Backend string `json:"backend"`
	Error   string `json:"error,omitempty"`
}

// Status 返回当前运行状态快照。
func (c *Controller) Status(ctx context.Context) Status {
	c.mu.Lock()
	s := Status{
		DryRun:     c.opt.DryRun,
		Dirty:      c.dirtyLocked(),
		Degraded:   c.degraded,
		Health:     map[string]health.Status{},
		ECS:        c.meta,
		ECSError:   c.metaErr,
		LastVerify: c.lastVerify,
	}
	for k, v := range c.health {
		s.Health[k] = v
	}
	if c.applied != nil {
		s.Enabled = c.applied.State.Enabled
		s.AppliedAt = c.applied.AppliedAt
	}
	if c.live != nil {
		s.Active = !c.degraded
		s.KillSwitch = c.live.Policy.KillSwitch
		s.Mode = c.live.Policy.Mode
		s.UDPMode = c.live.Policy.UDPMode
		if len(c.hopIDs) > 0 {
			s.CurrentID = c.hopIDs[0]
			s.CurrentName = c.nameOf(*c.live, c.hopIDs)
		} else {
			s.Blackholed = c.live.Policy.KillSwitch
		}
	}
	if c.pending != nil {
		s.Pending = &PendingInfo{Nonce: c.pending.nonce, Deadline: c.pending.deadline}
	}
	if c.engine != nil {
		running, pid, since, lastErr := c.engine.Info()
		s.Engine = EngineInfo{Running: running, PID: pid, Since: since, Error: lastErr}
	}
	s.Engine.Version = c.gostVersion
	if c.gostErr != "" {
		s.Engine.Error = c.gostErr
	}
	if c.fw != nil {
		s.Firewall.Backend = c.fw.B.Name
	}
	if c.fwErr != nil {
		s.Firewall.Error = c.fwErr.Error()
	}
	metricsPort := 0
	if c.live != nil && s.Engine.Running {
		metricsPort = c.live.Settings.MetricsPort
	}
	c.mu.Unlock()

	s.Conntrack[0], s.Conntrack[1] = c.opt.Sys.Conntrack()
	if metricsPort > 0 {
		tctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		if t, err := gost.FetchTraffic(tctx, metricsPort); err == nil {
			s.Traffic = &t
		}
		cancel()
	}
	return s
}

// EgressReport 是“立即检测出口”的结果。
type EgressReport struct {
	Real   probe.EgressResult `json:"real"`   // 普通进程看到的出口
	Direct probe.EgressResult `json:"direct"` // ECS 自身的出口
	At     time.Time          `json:"at"`
}

// CheckEgress 立即测量真实出口与直连出口。
func (c *Controller) CheckEgress(ctx context.Context) EgressReport {
	st := c.State()
	pr := c.prober(st)
	r := EgressReport{At: time.Now()}
	done := make(chan struct{})
	go func() { r.Direct = pr.DirectEgress(ctx); close(done) }()
	r.Real = pr.RealEgress(ctx)
	<-done
	return r
}

// Preview 是对编辑中状态的预览：gost 配置（已脱敏）和防火墙规则。
type Preview struct {
	GostConfig json.RawMessage `json:"gostConfig"`
	Rules      string          `json:"rules"`
	Bypass     []string        `json:"bypass"`
	Backend    string          `json:"backend"`
	DryRunLog  []string        `json:"dryRunLog,omitempty"`
}

// Preview 生成预览。
func (c *Controller) Preview(ctx context.Context) Preview {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := clone(c.state)
	nodes, _ := c.nodesFor(st)
	cfg := gost.Render(gost.Input{State: st, Nodes: nodes, APIPassword: c.apiPassword}).Redacted()
	in := c.fwInput(ctx, st)
	var bypass []string
	for _, p := range fw.BypassCIDRs(in) {
		bypass = append(bypass, p.String())
	}
	p := Preview{
		GostConfig: json.RawMessage(cfg.JSON()),
		Rules:      fw.Plan(in, st.Enabled).Script(),
		Bypass:     bypass,
	}
	if c.fw != nil {
		p.Backend = c.fw.B.Name
	}
	if c.dry != nil {
		p.DryRunLog = append(p.DryRunLog, c.dry.Cmds...)
		if len(p.DryRunLog) > 200 {
			p.DryRunLog = p.DryRunLog[len(p.DryRunLog)-200:]
		}
	}
	return p
}

// EngineLogs 返回 gost 最近的日志。
func (c *Controller) EngineLogs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.engine == nil {
		return nil
	}
	lines := c.engine.Logs()
	// 隐去 gost 日志中可能出现的 API 密码。
	for i, l := range lines {
		lines[i] = strings.ReplaceAll(l, c.apiPassword, "******")
	}
	return lines
}
