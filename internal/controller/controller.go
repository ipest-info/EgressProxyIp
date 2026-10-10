// Package controller 是 egp 的核心：它串行处理所有变更（应用、确认、回滚、
// 健康切换、引擎重启、规则漂移修复），保证 gost 配置与防火墙规则始终一致。
package controller

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ipest-info/EgressProxyIp/internal/aliyun"
	"github.com/ipest-info/EgressProxyIp/internal/audit"
	"github.com/ipest-info/EgressProxyIp/internal/fw"
	"github.com/ipest-info/EgressProxyIp/internal/gost"
	"github.com/ipest-info/EgressProxyIp/internal/health"
	"github.com/ipest-info/EgressProxyIp/internal/model"
	"github.com/ipest-info/EgressProxyIp/internal/netx"
	"github.com/ipest-info/EgressProxyIp/internal/probe"
	"github.com/ipest-info/EgressProxyIp/internal/store"
	"github.com/ipest-info/EgressProxyIp/internal/sysinfo"
)

// Options 是控制器的启动参数。
type Options struct {
	Dir            string        // 状态目录，例如 /etc/egp
	RunDir         string        // 运行时目录，例如 /run/egp（存放 gost 配置）
	DryRun         bool          // 演示模式：不启动 gost、不修改防火墙，只记录命令
	ConfirmTimeout time.Duration // 应用后等待确认的时间，超时自动回滚
	WebUIPort      int
	Log            *slog.Logger
	Sys            sysinfo.FS
	Runner         fw.Runner // 为空时自动选择
}

// Controller 见包注释。
type Controller struct {
	opt   Options
	log   *slog.Logger
	store *store.Store
	Audit *audit.Log

	mu          sync.Mutex
	state       model.State    // 正在编辑的状态
	applied     *store.Applied // 已确认生效的状态
	live        *model.State   // 当前实际生效的状态（待确认期间与 applied 不同）
	pending     *pendingApply
	fw          *fw.Firewall
	fwErr       error
	dry         *fw.DryRun
	engine      *gost.Process
	api         *gost.API
	apiPassword string
	gostVersion string
	gostErr     string
	health      map[string]health.Status
	hopIDs      []string // 当前 hop 中真实节点的 ID 顺序
	degraded    bool     // kill switch 关闭且全部代理不可用：已临时撤掉拦截规则
	engineDown  bool
	rules       fw.Ruleset
	restartN    int
	meta        *aliyun.Info
	metaErr     string
	lastVerify  *Verify
	stopping    bool
	stopCh      chan struct{}
	wg          sync.WaitGroup
}

type pendingApply struct {
	nonce    string
	deadline time.Time
	prev     *store.Applied
	next     model.State
	timer    *time.Timer
}

// New 创建控制器并加载状态，但不启动任何东西。
func New(opt Options) (*Controller, error) {
	if opt.Log == nil {
		opt.Log = slog.Default()
	}
	if opt.Sys.Root == "" {
		opt.Sys = sysinfo.Host
	}
	if opt.ConfirmTimeout == 0 {
		opt.ConfirmTimeout = 60 * time.Second
	}
	if opt.RunDir == "" {
		opt.RunDir = filepath.Join(opt.Dir, "run")
	}
	st, err := store.New(opt.Dir)
	if err != nil {
		return nil, fmt.Errorf("打开状态目录失败: %w", err)
	}
	if err := os.MkdirAll(opt.RunDir, 0o700); err != nil {
		return nil, fmt.Errorf("创建运行时目录失败: %w", err)
	}
	c := &Controller{
		opt:    opt,
		log:    opt.Log,
		store:  st,
		Audit:  audit.New(filepath.Join(opt.Dir, "audit.log"), 500),
		health: map[string]health.Status{},
		stopCh: make(chan struct{}),
	}
	if c.state, err = st.Load(); err != nil {
		return nil, err
	}
	if c.applied, err = st.LoadApplied(); err != nil {
		return nil, err
	}
	c.apiPassword = randomHex(16)
	return c, nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// State 返回当前编辑中的状态副本。
func (c *Controller) State() model.State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return clone(c.state)
}

// Store 返回底层存储（供 Web 层修改密码等）。
func (c *Controller) Store() *store.Store { return c.store }

func (c *Controller) prober(st model.State) *probe.Prober { return probe.New(st.Settings) }

// initFirewall 选择 iptables 后端。
func (c *Controller) initFirewall(ctx context.Context) {
	if c.opt.DryRun {
		c.dry = &fw.DryRun{}
		c.fw = &fw.Firewall{R: c.dry, B: fw.Backend{Name: "dry-run", IPT: "iptables", IPTRest: "iptables-restore", IP6T: "ip6tables", IP6TRest: "ip6tables-restore"}, Log: c.log, HasIPv6: true}
		return
	}
	r := c.opt.Runner
	if r == nil {
		r = fw.Exec{}
	}
	b, err := fw.DetectBackend(ctx, r)
	c.fw = &fw.Firewall{R: r, B: b, Log: c.log, HasIPv6: b.IP6T != "" && b.IP6TRest != "", RequireIPv6: c.opt.Sys.HasGlobalIPv6()}
	if err != nil {
		c.fwErr = err
		c.log.Error("iptables 不可用", "错误", err.Error())
		return
	}
	c.log.Info("使用 iptables 后端", "后端", b.Name, "命令", b.IPT)
}

// Start 恢复上次确认的配置并启动后台任务。
func (c *Controller) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.initFirewall(ctx)
	c.refreshMeta(ctx)

	if p, _ := c.store.LoadPending(); p != nil {
		// 上次进程在“待确认”期间退出：已确认的配置仍是 applied，直接按它恢复即回滚。
		c.Audit.Add("system", "回滚未确认的应用", "egp 在等待确认期间重启，已恢复到上一次确认的配置", true)
		c.log.Warn("发现未确认的应用，恢复到上一次确认的配置")
		c.store.SavePending(nil)
	}
	if c.applied != nil && c.applied.State.Enabled {
		st := c.applied.State
		if err := c.activate(ctx, st); err != nil {
			c.log.Error("恢复出口代理失败", "错误", err.Error())
			c.Audit.Add("system", "启动时恢复出口代理", err.Error(), false)
			c.failSafe(ctx, st)
		} else {
			c.Audit.Add("system", "启动时恢复出口代理", "已按上一次确认的配置启用", true)
		}
	} else {
		// 未启用：确保没有残留规则（例如上次异常退出留下的）。
		c.cleanupRules(ctx, c.state.Settings)
	}
	c.wg.Add(3)
	go c.healthLoop()
	go c.driftLoop()
	go c.metaLoop()
	return nil
}

// Stop 停止后台任务和 gost。keepRules 为 true 时保留防火墙规则（kill switch 开启时，
// 停止服务后保持断网，避免真实 IP 泄露）。
func (c *Controller) Stop(ctx context.Context) {
	c.mu.Lock()
	c.stopping = true
	close(c.stopCh)
	if c.pending != nil {
		c.pending.timer.Stop()
	}
	keep := c.live != nil && c.live.Enabled && c.live.Policy.KillSwitch
	c.mu.Unlock()
	c.wg.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.engine != nil {
		c.engine.Stop()
	}
	if keep {
		c.log.Warn("kill switch 已开启：停止服务后保留防火墙规则，本机将无法访问互联网。如需恢复直连请执行 egp cleanup")
	} else {
		c.cleanupRules(ctx, c.state.Settings)
	}
}

// failSafe 在激活失败时决定兜底行为：kill switch 开启则仍下发规则（断网而非泄露），否则清理。
func (c *Controller) failSafe(ctx context.Context, st model.State) {
	if st.Enabled && st.Policy.KillSwitch {
		rs := fw.Plan(c.fwInput(ctx, st), true)
		if c.fw != nil && c.fwErr == nil {
			if err := c.fw.Apply(ctx, rs); err == nil {
				c.rules = rs
				c.live = &st
				c.log.Warn("kill switch 生效：引擎不可用，出网流量已被阻断")
				return
			}
		}
	}
	c.cleanupRules(ctx, st.Settings)
	c.live = nil
	c.rules = fw.Ruleset{}
}

func (c *Controller) cleanupRules(ctx context.Context, st model.Settings) {
	if c.fw == nil || c.fwErr != nil {
		return
	}
	// 注意不修改 c.rules：降级直连时需要保留计划中的规则集，以便代理恢复后重新下发。
	base := fw.Ruleset{Mark: st.MarkTProxy, Table: st.RouteTable, Priority: st.RulePriority}
	if err := c.fw.Cleanup(ctx, base); err != nil {
		c.log.Error("清理防火墙规则失败", "错误", err.Error())
	}
}

// fwInput 收集生成防火墙规则所需的主机信息。
func (c *Controller) fwInput(ctx context.Context, st model.State) fw.Input {
	in := fw.Input{
		Settings:          st.Settings,
		Policy:            st.Policy,
		Bypass:            st.Bypass,
		WebUIPort:         c.opt.WebUIPort,
		DirectGroupExists: st.Bypass.DirectGroup != "" && c.opt.Sys.GroupExists(st.Bypass.DirectGroup),
		LocalUDPPorts:     c.opt.Sys.LocalUDPServicePorts(st.Settings.TProxyPort),
	}
	in.AutoCIDRs = append(in.AutoCIDRs, c.opt.Sys.ConnectedSubnets()...)
	for _, a := range c.opt.Sys.ResolverIPs() {
		if !a.IsLoopback() {
			// 系统 DNS 服务器必须直连，否则 gost 解析域名时会形成回环。
			in.AutoCIDRs = append(in.AutoCIDRs, netip.PrefixFrom(a, 32))
		}
	}
	if c.meta != nil && c.meta.VPCCIDR != "" {
		if p, err := model.ParseCIDR(c.meta.VPCCIDR); err == nil {
			in.AutoCIDRs = append(in.AutoCIDRs, p)
		}
	}
	for _, p := range st.EnabledProxies() {
		ep := fw.Endpoint{Port: p.Port}
		if a, err := netip.ParseAddr(p.Host); err == nil {
			ep.IP = a.Unmap()
		}
		in.Proxies = append(in.Proxies, ep)
	}
	return in
}

// refreshMeta 读取阿里云元数据（带自身标记，绕过 egp）。
func (c *Controller) refreshMeta(ctx context.Context) {
	if c.opt.DryRun {
		return
	}
	cl := &aliyun.Client{HTTP: netx.HTTPClient(c.state.Settings.MarkSelf, 3*time.Second)}
	info, err := cl.Fetch(ctx)
	if info != nil {
		c.meta = info
	}
	if err != nil {
		c.metaErr = err.Error()
	} else {
		c.metaErr = ""
	}
}

func (c *Controller) metaLoop() {
	defer c.wg.Done()
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			c.mu.Lock()
			c.refreshMeta(ctx)
			c.mu.Unlock()
			cancel()
		}
	}
}

// errPending 表示上一次应用尚未确认。
var errPending = errors.New("上一次应用尚未确认，请先确认或回滚")

func clone(s model.State) model.State {
	c := s
	c.Proxies = append([]model.Proxy(nil), s.Proxies...)
	c.Bypass.CIDRs = append([]string(nil), s.Bypass.CIDRs...)
	c.Bypass.Domains = append([]string(nil), s.Bypass.Domains...)
	c.Bypass.TCPPorts = append([]int(nil), s.Bypass.TCPPorts...)
	c.Bypass.UDPPorts = append([]int(nil), s.Bypass.UDPPorts...)
	c.Bypass.MgmtPorts = append([]int(nil), s.Bypass.MgmtPorts...)
	c.Settings.EchoURLs = append([]string(nil), s.Settings.EchoURLs...)
	c.FillDefaults()
	return c
}
