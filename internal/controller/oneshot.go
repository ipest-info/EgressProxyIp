package controller

import (
	"context"
	"log/slog"

	"github.com/ipest-info/EgressProxyIp/internal/fw"
	"github.com/ipest-info/EgressProxyIp/internal/model"
	"github.com/ipest-info/EgressProxyIp/internal/store"
)

// loadApplied 读取已确认的配置，没有时返回 nil。
func loadApplied(dir string) (*store.Applied, model.State, error) {
	st, err := store.New(dir)
	if err != nil {
		return nil, model.State{}, err
	}
	cur, err := st.Load()
	if err != nil {
		return nil, cur, err
	}
	a, err := st.LoadApplied()
	return a, cur, err
}

// BootGuard 在开机时、网络就绪之前下发 kill switch 规则，避免 egp 启动前的这段时间
// 流量经 ECS 自身 IP 泄露。此时 gost 尚未运行，被拦截的 TCP 会收到 RST，
// 其他流量被防护链拒绝，即“失败即断网”。
func BootGuard(ctx context.Context, opt Options) (bool, error) {
	a, _, err := loadApplied(opt.Dir)
	if err != nil {
		return false, err
	}
	if a == nil || !a.State.Enabled || !a.State.Policy.KillSwitch {
		return false, nil
	}
	c, err := New(opt)
	if err != nil {
		return false, err
	}
	c.initFirewall(ctx)
	if c.fwErr != nil {
		return false, c.fwErr
	}
	// 开机早期 gost 尚未运行，不做 UDP 透明代理：UDP 由防护链直接拒绝。
	rs := fw.Plan(c.fwInput(ctx, a.State), true).WithoutUDPProxy()
	return true, c.fw.Apply(ctx, rs)
}

// Cleanup 删除 egp 的全部规则（两套 iptables 都清理）。respectKillSwitch 为 true 且
// 已生效的配置开启了 kill switch 时什么都不做，返回 skipped=true。
func Cleanup(ctx context.Context, dir string, log *slog.Logger, respectKillSwitch bool) (skipped bool, err error) {
	a, cur, err := loadApplied(dir)
	if err != nil {
		return false, err
	}
	settings := cur.Settings
	if a != nil {
		settings = a.State.Settings
		if respectKillSwitch && a.State.Enabled && a.State.Policy.KillSwitch {
			return true, nil
		}
	}
	base := fw.Ruleset{Mark: settings.MarkTProxy, Table: settings.RouteTable, Priority: settings.RulePriority}
	return false, fw.CleanupAll(ctx, fw.Exec{}, log, base)
}
