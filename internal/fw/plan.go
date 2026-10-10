// Package fw 生成并下发 egp 的 iptables 规则和策略路由。
//
// 规则全部放在 egp 自己的链（EGP_*）里，父链只插入一条带 "egp" 注释的跳转，
// 因此清理时只需删除跳转并删除这些链，不会影响 ufw、firewalld、Docker 的规则。
package fw

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/ipest-info/EgressProxyIp/internal/model"
)

// egp 拥有的链。
const (
	ChainTCPOut  = "EGP_TCP_OUT"  // nat OUTPUT：TCP 重定向到 gost
	ChainUDPOut  = "EGP_UDP_OUT"  // mangle OUTPUT：给 UDP 打 TPROXY 标记
	ChainUDPPre  = "EGP_UDP_PRE"  // mangle PREROUTING：TPROXY 到 gost
	ChainGuard   = "EGP_GUARD"    // filter OUTPUT：kill switch 防护链
	ChainGuardPX = "EGP_GUARD_PX" // filter：限制“代理标记”流量只能去往上游代理
	ChainGuard6  = "EGP6_GUARD"   // ip6tables filter OUTPUT：阻断 IPv6 出网
	jumpComment  = "egp"
)

// BuiltinCIDRs 是始终直连的网段：本机、私网、阿里云内网服务（100.64.0.0/10 内含
// 元数据 100.100.100.200、内网 DNS 100.100.2.136/138、内网 yum 源等）、链路本地、组播与保留地址。
var BuiltinCIDRs = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
}

// Endpoint 是一个上游代理的地址。IP 无效表示代理以域名配置。
type Endpoint struct {
	IP   netip.Addr
	Port int
}

// Input 是生成规则所需的全部输入，由控制器从状态和主机信息中收集。
type Input struct {
	Settings model.Settings
	Policy   model.Policy
	Bypass   model.Bypass
	// AutoCIDRs 是自动探测到的绕过网段：直连子网、VPC 网段、系统 DNS 服务器。
	AutoCIDRs []netip.Prefix
	// Proxies 是 gost 会连接的上游代理地址（用于 kill switch 防护链）。
	Proxies []Endpoint
	// LocalUDPPorts 是本机对外提供服务的 UDP 端口。
	LocalUDPPorts []int
	// WebUIPort 是 WebUI 端口，其回包永远放行。
	WebUIPort int
	// DirectGroupExists 表示直连用户组存在（不存在时 iptables 会拒绝该规则）。
	DirectGroupExists bool
}

// Chain 是一条链及其规则（每条规则是 "-A 链名" 之后的参数）。
type Chain struct {
	Table string
	Name  string
	Rules [][]string
}

// Jump 是父链中跳转到 egp 链的规则。
type Jump struct {
	Table  string
	Parent string
	Spec   []string // 不含注释部分
}

// Args 返回带注释的完整规则参数（注释放在 -j 之前，与 `iptables -S` 的输出顺序一致）。
func (j Jump) Args() []string {
	var out []string
	for i, a := range j.Spec {
		if a == "-j" {
			out = append(out, "-m", "comment", "--comment", jumpComment)
			out = append(out, j.Spec[i:]...)
			return out
		}
		out = append(out, a)
	}
	return append(out, "-m", "comment", "--comment", jumpComment)
}

// Ruleset 是一次完整的规则计划。
type Ruleset struct {
	V4       []Chain
	V6       []Chain
	Jumps4   []Jump
	Jumps6   []Jump
	TProxy   bool // 是否需要 UDP 透明代理的策略路由
	Mark     uint32
	Table    int
	Priority int
}

// WithoutUDPProxy 去掉 UDP 透明代理相关的链、跳转、防护链中的 TPROXY 放行规则
// 和策略路由。用于开机守护：此时没有引擎，UDP 应由防护链直接拒绝。
func (r Ruleset) WithoutUDPProxy() Ruleset {
	out := r
	out.V4, out.Jumps4 = nil, nil
	tmark := markArg(r.Mark)
	for _, c := range r.V4 {
		if c.Name == ChainUDPOut || c.Name == ChainUDPPre {
			continue
		}
		cc := Chain{Table: c.Table, Name: c.Name}
		for _, rule := range c.Rules {
			if c.Name == ChainGuard && strings.Contains(strings.Join(rule, " "), tmark) {
				continue
			}
			cc.Rules = append(cc.Rules, rule)
		}
		out.V4 = append(out.V4, cc)
	}
	for _, j := range r.Jumps4 {
		if !strings.HasSuffix(strings.Join(j.Spec, " "), ChainUDPOut) && !strings.HasSuffix(strings.Join(j.Spec, " "), ChainUDPPre) {
			out.Jumps4 = append(out.Jumps4, j)
		}
	}
	out.TProxy = false
	return out
}

// Empty 表示不需要任何规则（即全部清理）。
func (r Ruleset) Empty() bool { return len(r.V4) == 0 && len(r.V6) == 0 && !r.TProxy }

// OwnedV4 / OwnedV6 列出 egp 可能创建的全部链，清理时据此删除不再需要的链。
var (
	OwnedV4 = []Chain{{Table: "nat", Name: ChainTCPOut}, {Table: "mangle", Name: ChainUDPOut}, {Table: "mangle", Name: ChainUDPPre}, {Table: "filter", Name: ChainGuard}, {Table: "filter", Name: ChainGuardPX}}
	OwnedV6 = []Chain{{Table: "filter", Name: ChainGuard6}}
	// Parents 是 egp 会插入跳转的父链。
	Parents = []struct{ Table, Chain string }{{"nat", "OUTPUT"}, {"mangle", "OUTPUT"}, {"mangle", "PREROUTING"}, {"filter", "OUTPUT"}}
)

func markArg(m uint32) string { return fmt.Sprintf("0x%x/0x%x", m, m) }

func ret(args ...string) []string { return append(args, "-j", "RETURN") }

// portChunks 把端口列表拆成每组最多 15 个（multiport 的上限）。
func portChunks(ports []int) []string {
	ps := uniqInts(ports)
	var out []string
	for i := 0; i < len(ps); i += 15 {
		end := min(i+15, len(ps))
		strs := make([]string, 0, end-i)
		for _, p := range ps[i:end] {
			strs = append(strs, strconv.Itoa(p))
		}
		out = append(out, strings.Join(strs, ","))
	}
	return out
}

func uniqInts(in []int) []int {
	set := map[int]bool{}
	var out []int
	for _, v := range in {
		if v > 0 && v <= 65535 && !set[v] {
			set[v] = true
			out = append(out, v)
		}
	}
	sort.Ints(out)
	return out
}

// MergeCIDRs 合并网段：去重，并去掉被其他网段包含的网段。
func MergeCIDRs(in []netip.Prefix) []netip.Prefix {
	ps := make([]netip.Prefix, 0, len(in))
	for _, p := range in {
		if p.IsValid() && p.Addr().Is4() {
			ps = append(ps, p.Masked())
		}
	}
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].Bits() != ps[j].Bits() {
			return ps[i].Bits() < ps[j].Bits()
		}
		return ps[i].Addr().Less(ps[j].Addr())
	})
	var out []netip.Prefix
	for _, p := range ps {
		covered := false
		for _, q := range out {
			if q.Bits() <= p.Bits() && q.Contains(p.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Addr() != out[j].Addr() {
			return out[i].Addr().Less(out[j].Addr())
		}
		return out[i].Bits() < out[j].Bits()
	})
	return out
}

// BypassCIDRs 返回最终生效的绕过网段（内置 + 自动探测 + 用户配置）。
func BypassCIDRs(in Input) []netip.Prefix {
	var all []netip.Prefix
	for _, c := range BuiltinCIDRs {
		all = append(all, netip.MustParsePrefix(c))
	}
	all = append(all, in.AutoCIDRs...)
	for _, c := range in.Bypass.CIDRs {
		if p, err := model.ParseCIDR(c); err == nil {
			all = append(all, p)
		}
	}
	return MergeCIDRs(all)
}

// exemptions 是各条链共用的“直连”判定：目标网段、直连用户组。
func exemptions(in Input, cidrs []netip.Prefix) [][]string {
	var rules [][]string
	for _, c := range cidrs {
		rules = append(rules, ret("-d", c.String()))
	}
	if g := in.Bypass.DirectGroup; g != "" && in.DirectGroupExists {
		rules = append(rules, ret("-m", "owner", "--gid-owner", g))
	}
	return rules
}

func engineMarks(st model.Settings) [][]string {
	return [][]string{
		ret("-m", "mark", "--mark", markArg(st.MarkProxy)),
		ret("-m", "mark", "--mark", markArg(st.MarkDirect)),
		ret("-m", "mark", "--mark", markArg(st.MarkSelf)),
	}
}

func (in Input) mgmtPorts() []int {
	return uniqInts(append(append([]int{}, in.Bypass.MgmtPorts...), in.WebUIPort))
}

// Plan 根据输入生成规则。enabled 为 false 时返回空规则集（即清理）。
func Plan(in Input, enabled bool) Ruleset {
	st, pol := in.Settings, in.Policy
	rs := Ruleset{Mark: st.MarkTProxy, Table: st.RouteTable, Priority: st.RulePriority}
	if !enabled {
		return rs
	}
	cidrs := BypassCIDRs(in)
	ex := exemptions(in, cidrs)

	// ---- TCP：nat OUTPUT 只处理新连接的首包，入站连接（SSH/WebUI）的回包天然不受影响。
	tcp := Chain{Table: "nat", Name: ChainTCPOut}
	tcp.Rules = append(tcp.Rules, engineMarks(st)...)
	tcp.Rules = append(tcp.Rules, ret("-m", "addrtype", "--dst-type", "LOCAL"))
	tcp.Rules = append(tcp.Rules, ex...)
	for _, ch := range portChunks(in.Bypass.TCPPorts) {
		tcp.Rules = append(tcp.Rules, ret("-p", "tcp", "-m", "multiport", "--dports", ch))
	}
	// 只重定向 SYN：conntrack 表被清空后，已有连接的中途报文不会被误重定向。
	tcp.Rules = append(tcp.Rules, []string{"-p", "tcp", "--syn", "-j", "REDIRECT", "--to-ports", strconv.Itoa(st.RedirPort)})
	rs.V4 = append(rs.V4, tcp)
	rs.Jumps4 = append(rs.Jumps4, Jump{Table: "nat", Parent: "OUTPUT", Spec: []string{"-p", "tcp", "-j", ChainTCPOut}})

	// ---- UDP：mangle OUTPUT 打标记 → 策略路由送回 lo → PREROUTING TPROXY 到 gost。
	if pol.UDPMode == model.UDPProxy {
		udp := Chain{Table: "mangle", Name: ChainUDPOut}
		udp.Rules = append(udp.Rules, engineMarks(st)...)
		// 入站流（例如本机 DNS 服务）的回包方向为 REPLY，不能被导入代理。
		udp.Rules = append(udp.Rules, ret("-m", "conntrack", "--ctdir", "REPLY"))
		udp.Rules = append(udp.Rules, ret("-m", "addrtype", "--dst-type", "LOCAL"))
		udp.Rules = append(udp.Rules, ex...)
		for _, ch := range portChunks(in.Bypass.UDPPorts) {
			udp.Rules = append(udp.Rules, ret("-p", "udp", "-m", "multiport", "--dports", ch))
		}
		// conntrack 条目过期后，本机 UDP 服务的迟到回包看起来像新流，按源端口放行。
		for _, ch := range portChunks(in.LocalUDPPorts) {
			udp.Rules = append(udp.Rules, ret("-p", "udp", "-m", "multiport", "--sports", ch))
		}
		udp.Rules = append(udp.Rules, []string{"-p", "udp", "-j", "MARK", "--set-xmark", markArg(st.MarkTProxy)})
		pre := Chain{Table: "mangle", Name: ChainUDPPre, Rules: [][]string{{
			"-i", "lo", "-p", "udp", "-m", "mark", "--mark", markArg(st.MarkTProxy),
			"-j", "TPROXY", "--on-ip", "127.0.0.1", "--on-port", strconv.Itoa(st.TProxyPort),
			"--tproxy-mark", markArg(st.MarkTProxy),
		}}}
		rs.V4 = append(rs.V4, udp, pre)
		rs.Jumps4 = append(rs.Jumps4,
			Jump{Table: "mangle", Parent: "OUTPUT", Spec: []string{"-p", "udp", "-j", ChainUDPOut}},
			Jump{Table: "mangle", Parent: "PREROUTING", Spec: []string{"-i", "lo", "-p", "udp", "-j", ChainUDPPre}},
		)
		rs.TProxy = true
	}

	// ---- 防护链：kill switch 打开，或 UDP 阻断模式时需要。
	if pol.KillSwitch || pol.UDPMode == model.UDPBlock {
		guard := Chain{Table: "filter", Name: ChainGuard}
		guard.Rules = append(guard.Rules, ret("-o", "lo"))
		// 注意：同一个 OUTPUT 钩子内，mangle/nat 改变路由后 filter 的 -o 仍是原出接口，
		// 所以不能靠 -o lo 识别被拦截的流量：被 REDIRECT 的 TCP 目标已变成 127.0.0.1
		// （由 127.0.0.0/8 放行），被 TPROXY 的 UDP 按其标记放行。
		if pol.UDPMode == model.UDPProxy {
			guard.Rules = append(guard.Rules, ret("-m", "mark", "--mark", markArg(st.MarkTProxy)))
		}
		guard.Rules = append(guard.Rules, ret("-m", "conntrack", "--ctdir", "REPLY"))
		guard.Rules = append(guard.Rules, ret("-m", "mark", "--mark", markArg(st.MarkSelf)))
		if pol.KillSwitch {
			// PX 子链里的 RETURN 只回到本链，因此紧跟一条 RETURN：
			// 允许的流量从 PX 返回后在这里退出防护链，不允许的已在 PX 中被拒绝。
			guard.Rules = append(guard.Rules,
				[]string{"-m", "mark", "--mark", markArg(st.MarkProxy), "-j", ChainGuardPX},
				ret("-m", "mark", "--mark", markArg(st.MarkProxy)))
			if len(in.Bypass.Domains) > 0 {
				// 域名绕过需要 gost 直连任意地址，只能整体放行直连标记。
				guard.Rules = append(guard.Rules, ret("-m", "mark", "--mark", markArg(st.MarkDirect)))
			}
		} else {
			guard.Rules = append(guard.Rules,
				ret("-m", "mark", "--mark", markArg(st.MarkProxy)),
				ret("-m", "mark", "--mark", markArg(st.MarkDirect)))
		}
		// 管理面：conntrack 丢失时 SSH/WebUI 的回包也不能被拦。
		for _, ch := range portChunks(in.mgmtPorts()) {
			guard.Rules = append(guard.Rules, ret("-p", "tcp", "-m", "multiport", "--sports", ch))
		}
		for _, ch := range portChunks(in.LocalUDPPorts) {
			guard.Rules = append(guard.Rules, ret("-p", "udp", "-m", "multiport", "--sports", ch))
		}
		guard.Rules = append(guard.Rules, ex...)
		for _, ch := range portChunks(in.Bypass.TCPPorts) {
			guard.Rules = append(guard.Rules, ret("-p", "tcp", "-m", "multiport", "--dports", ch))
		}
		for _, ch := range portChunks(in.Bypass.UDPPorts) {
			guard.Rules = append(guard.Rules, ret("-p", "udp", "-m", "multiport", "--dports", ch))
		}
		if pol.UDPMode == model.UDPDirect {
			guard.Rules = append(guard.Rules, ret("-p", "udp"))
		}
		if pol.UDPMode == model.UDPBlock {
			// port-unreachable 让 QUIC 立即回退到 TCP。
			guard.Rules = append(guard.Rules, []string{"-p", "udp", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"})
		}
		if pol.KillSwitch {
			// 其余一律拒绝：ICMP、其他协议、绑定网卡的套接字、应用规则前已建立的直连连接。
			guard.Rules = append(guard.Rules,
				[]string{"-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"},
				[]string{"-j", "REJECT", "--reject-with", "icmp-admin-prohibited"})
			px := Chain{Table: "filter", Name: ChainGuardPX}
			seenPort := map[int]bool{}
			for _, e := range in.Proxies {
				if e.IP.IsValid() {
					px.Rules = append(px.Rules, ret("-p", "tcp", "-d", e.IP.String(), "--dport", strconv.Itoa(e.Port)))
				} else if !seenPort[e.Port] {
					// 以域名配置的代理，IP 可能变化，只能按端口放行。
					seenPort[e.Port] = true
					px.Rules = append(px.Rules, ret("-p", "tcp", "--dport", strconv.Itoa(e.Port)))
				}
			}
			// UDP 中继地址由代理在握手时动态告知，无法预先列出。
			px.Rules = append(px.Rules, ret("-p", "udp"))
			px.Rules = append(px.Rules,
				[]string{"-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"},
				[]string{"-j", "REJECT", "--reject-with", "icmp-admin-prohibited"})
			// 被引用的链必须先声明，所以 PX 链放在前面。
			rs.V4 = append(rs.V4, px)
		}
		rs.V4 = append(rs.V4, guard)
		rs.Jumps4 = append(rs.Jumps4, Jump{Table: "filter", Parent: "OUTPUT", Spec: []string{"-j", ChainGuard}})
	}

	// ---- IPv6：egp 只代理 IPv4，为防止经 IPv6 泄露真实地址，直接阻断 IPv6 出网。
	if pol.BlockIPv6 {
		g6 := Chain{Table: "filter", Name: ChainGuard6}
		g6.Rules = append(g6.Rules,
			ret("-o", "lo"),
			ret("-m", "conntrack", "--ctdir", "REPLY"),
			ret("-m", "mark", "--mark", markArg(st.MarkSelf)),
			ret("-d", "fe80::/10"),
			ret("-d", "ff00::/8"),
			ret("-d", "fc00::/7"),
		)
		for _, ch := range portChunks(in.mgmtPorts()) {
			g6.Rules = append(g6.Rules, ret("-p", "tcp", "-m", "multiport", "--sports", ch))
		}
		g6.Rules = append(g6.Rules,
			[]string{"-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"},
			[]string{"-j", "REJECT", "--reject-with", "icmp6-adm-prohibited"})
		rs.V6 = append(rs.V6, g6)
		rs.Jumps6 = append(rs.Jumps6, Jump{Table: "filter", Parent: "OUTPUT", Spec: []string{"-j", ChainGuard6}})
	}
	return rs
}

// Script 把规则集渲染成便于人工审阅的命令文本（用于 dry-run 和 WebUI 预览）。
func (r Ruleset) Script() string {
	var b strings.Builder
	write := func(cmd string, chains []Chain, jumps []Jump) {
		for _, c := range chains {
			fmt.Fprintf(&b, "%s -t %s -N %s\n", cmd, c.Table, c.Name)
			for _, rule := range c.Rules {
				fmt.Fprintf(&b, "%s -t %s -A %s %s\n", cmd, c.Table, c.Name, strings.Join(rule, " "))
			}
		}
		for _, j := range jumps {
			fmt.Fprintf(&b, "%s -t %s -I %s 1 %s\n", cmd, j.Table, j.Parent, strings.Join(j.Args(), " "))
		}
	}
	if r.Empty() {
		return "# 未启用出口代理：不下发任何规则\n"
	}
	b.WriteString("# ---- IPv4 ----\n")
	write("iptables", r.V4, r.Jumps4)
	if r.TProxy {
		fmt.Fprintf(&b, "ip -4 rule add pref %d fwmark %s lookup %d\n", r.Priority, markArg(r.Mark), r.Table)
		fmt.Fprintf(&b, "ip -4 route replace local 0.0.0.0/0 dev lo table %d\n", r.Table)
	}
	if len(r.V6) > 0 {
		b.WriteString("# ---- IPv6 ----\n")
		write("ip6tables", r.V6, r.Jumps6)
	}
	return b.String()
}
