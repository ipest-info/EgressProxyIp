// Package model 定义 egp 持久化的状态结构及其校验规则。
package model

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const SchemaVersion = 1

// 出口模式。
const (
	ModeFixed    = "fixed"    // 固定使用 Policy.ActiveProxyID 指定的代理
	ModeFailover = "failover" // 按优先级使用第一个健康的代理（主备）
)

// UDP 处理模式。
const (
	UDPProxy  = "proxy"  // UDP 经 SOCKS5 UDP ASSOCIATE 转发
	UDPDirect = "direct" // UDP 直接用 ECS 自身地址出网
	UDPBlock  = "block"  // 拒绝访问互联网的 UDP（QUIC 会回退到 TCP）
)

// 最近一次测试得出的代理 UDP 能力。
const (
	UDPUnknown     = "unknown"
	UDPSupported   = "yes"
	UDPUnsupported = "no"
)

// State 是 egp 写入磁盘的全部状态。
type State struct {
	SchemaVersion int      `json:"schemaVersion"`
	Enabled       bool     `json:"enabled"` // 是否启用出口代理（流量拦截）
	Proxies       []Proxy  `json:"proxies"` // 切片顺序即主备优先级
	Policy        Policy   `json:"policy"`
	Bypass        Bypass   `json:"bypass"`
	Settings      Settings `json:"settings"`
}

// Proxy 表示一个上游 SOCKS5 代理。
type Proxy struct {
	ID       string      `json:"id"`
	Name     string      `json:"name"`
	Host     string      `json:"host"`
	Port     int         `json:"port"`
	Username string      `json:"username,omitempty"`
	Password string      `json:"password,omitempty"`
	Enabled  bool        `json:"enabled"`
	UDP      string      `json:"udp"` // UDPUnknown / UDPSupported / UDPUnsupported 之一
	LastTest *TestResult `json:"lastTest,omitempty"`
}

// Addr 返回可直接拨号的 host:port。
func (p Proxy) Addr() string { return net.JoinHostPort(p.Host, strconv.Itoa(p.Port)) }

// TestResult 是一次手动代理测试的结果。
type TestResult struct {
	At           time.Time `json:"at"`
	OK           bool      `json:"ok"`
	Error        string    `json:"error,omitempty"`
	ConnectMs    int64     `json:"connectMs"`   // 与代理建立 TCP 连接耗时
	HandshakeMs  int64     `json:"handshakeMs"` // SOCKS5 握手 + 认证耗时
	RequestMs    int64     `json:"requestMs"`   // 经代理完成 HTTP 请求的总耗时
	ExitIP       string    `json:"exitIp,omitempty"`
	Country      string    `json:"country,omitempty"`
	Region       string    `json:"region,omitempty"`
	City         string    `json:"city,omitempty"`
	ISP          string    `json:"isp,omitempty"`
	UDP          string    `json:"udp"`
	UDPDetail    string    `json:"udpDetail,omitempty"`
	UDPMappedIP  string    `json:"udpMappedIp,omitempty"`
	RelayAddress string    `json:"relayAddress,omitempty"`
}

// Policy 控制出口流量的走向。
type Policy struct {
	Mode             string `json:"mode"`
	ActiveProxyID    string `json:"activeProxyId,omitempty"`
	KillSwitch       bool   `json:"killSwitch"`
	UDPMode          string `json:"udpMode"`
	BlockIPv6        bool   `json:"blockIpv6"`
	HealthInterval   int    `json:"healthIntervalSec"`
	FailThreshold    int    `json:"failThreshold"`
	RecoverThreshold int    `json:"recoverThreshold"`
	Failback         bool   `json:"failback"` // 高优先级代理恢复后是否自动切回
}

// Bypass 列出继续使用 ECS 自身地址出网的目标和本机身份。
type Bypass struct {
	CIDRs       []string `json:"cidrs"`
	Domains     []string `json:"domains"`     // 域名后缀，基于嗅探到的 TLS SNI / HTTP Host 匹配
	TCPPorts    []int    `json:"tcpPorts"`    // 目标端口
	UDPPorts    []int    `json:"udpPorts"`    // 目标端口
	DirectGroup string   `json:"directGroup"` // 以该用户组运行的进程不走代理
	MgmtPorts   []int    `json:"mgmtPorts"`   // 额外的本机 TCP 服务端口，其回包永远不被拦截
}

// Settings 保存底层参数。默认值刻意避开 kube-proxy、Tailscale、wg-quick、
// Cilium 和 Docker 使用的标记与路由表。
type Settings struct {
	Listen       string   `json:"listen"`
	AdminUser    string   `json:"adminUser"`
	AdminHash    string   `json:"adminHash"`
	GostBin      string   `json:"gostBin"`
	RedirPort    int      `json:"redirPort"`
	TProxyPort   int      `json:"tproxyPort"`
	APIPort      int      `json:"apiPort"`
	MetricsPort  int      `json:"metricsPort"`
	MarkProxy    uint32   `json:"markProxy"`  // gost 连接上游代理的套接字
	MarkDirect   uint32   `json:"markDirect"` // gost 直连拨号（域名绕过）
	MarkSelf     uint32   `json:"markSelf"`   // egp 自身探测流量的套接字
	MarkTProxy   uint32   `json:"markTproxy"` // 被导向 TPROXY 的 UDP 数据包
	RouteTable   int      `json:"routeTable"`
	RulePriority int      `json:"rulePriority"`
	HealthURL    string   `json:"healthUrl"`
	EchoURLs     []string `json:"echoUrls"`
	GeoURL       string   `json:"geoUrl"` // 其中 %s 会被替换为 IP
	STUNServer   string   `json:"stunServer"`
}

// Default 返回带安全默认值的全新状态。
func Default() State {
	return State{
		SchemaVersion: SchemaVersion,
		Proxies:       []Proxy{},
		Policy: Policy{
			Mode:             ModeFailover,
			KillSwitch:       true,
			UDPMode:          UDPProxy,
			BlockIPv6:        true,
			HealthInterval:   30,
			FailThreshold:    3,
			RecoverThreshold: 2,
			Failback:         true,
		},
		Bypass: Bypass{
			CIDRs:       []string{},
			Domains:     []string{},
			TCPPorts:    []int{},
			UDPPorts:    []int{123},
			DirectGroup: "egp-direct",
			MgmtPorts:   []int{22},
		},
		Settings: DefaultSettings(),
	}
}

// DefaultSettings 返回默认的底层参数。
func DefaultSettings() Settings {
	return Settings{
		Listen:       "127.0.0.1:8088",
		AdminUser:    "admin",
		GostBin:      "/usr/local/bin/gost",
		RedirPort:    7892,
		TProxyPort:   7893,
		APIPort:      17890,
		MetricsPort:  17891,
		MarkProxy:    0x2000000,
		MarkDirect:   0x1000000,
		MarkSelf:     0x8000000,
		MarkTProxy:   0x4000000,
		RouteTable:   7893,
		RulePriority: 9000,
		HealthURL:    "http://cp.cloudflare.com/generate_204",
		EchoURLs:     []string{"https://api.ipify.org", "https://checkip.amazonaws.com", "https://ifconfig.me/ip"},
		GeoURL:       "http://ip-api.com/json/%s?lang=zh-CN&fields=status,message,country,regionName,city,isp,query",
		STUNServer:   "stun.cloudflare.com:3478",
	}
}

// FillDefaults 修补旧版本或手工编辑的状态文件中留下的零值。
func (s *State) FillDefaults() {
	d := DefaultSettings()
	st := &s.Settings
	if st.Listen == "" {
		st.Listen = d.Listen
	}
	if st.AdminUser == "" {
		st.AdminUser = d.AdminUser
	}
	if st.GostBin == "" {
		st.GostBin = d.GostBin
	}
	setInt := func(v *int, def int) {
		if *v == 0 {
			*v = def
		}
	}
	setMark := func(v *uint32, def uint32) {
		if *v == 0 {
			*v = def
		}
	}
	setInt(&st.RedirPort, d.RedirPort)
	setInt(&st.TProxyPort, d.TProxyPort)
	setInt(&st.APIPort, d.APIPort)
	setInt(&st.MetricsPort, d.MetricsPort)
	setInt(&st.RouteTable, d.RouteTable)
	setInt(&st.RulePriority, d.RulePriority)
	setMark(&st.MarkProxy, d.MarkProxy)
	setMark(&st.MarkDirect, d.MarkDirect)
	setMark(&st.MarkSelf, d.MarkSelf)
	setMark(&st.MarkTProxy, d.MarkTProxy)
	if st.HealthURL == "" {
		st.HealthURL = d.HealthURL
	}
	if len(st.EchoURLs) == 0 {
		st.EchoURLs = d.EchoURLs
	}
	if st.GeoURL == "" {
		st.GeoURL = d.GeoURL
	}
	if st.STUNServer == "" {
		st.STUNServer = d.STUNServer
	}
	p := &s.Policy
	if p.Mode == "" {
		p.Mode = ModeFailover
	}
	if p.UDPMode == "" {
		p.UDPMode = UDPProxy
	}
	setInt(&p.HealthInterval, 30)
	setInt(&p.FailThreshold, 3)
	setInt(&p.RecoverThreshold, 2)
	if s.Proxies == nil {
		s.Proxies = []Proxy{}
	}
	for i := range s.Proxies {
		if s.Proxies[i].UDP == "" {
			s.Proxies[i].UDP = UDPUnknown
		}
	}
	b := &s.Bypass
	if b.CIDRs == nil {
		b.CIDRs = []string{}
	}
	if b.Domains == nil {
		b.Domains = []string{}
	}
	if b.TCPPorts == nil {
		b.TCPPorts = []int{}
	}
	if b.UDPPorts == nil {
		b.UDPPorts = []int{}
	}
	if b.MgmtPorts == nil {
		b.MgmtPorts = []int{}
	}
	if s.SchemaVersion == 0 {
		s.SchemaVersion = SchemaVersion
	}
}

// FindProxy 返回指定 ID 的代理下标，找不到时返回 -1。
func (s *State) FindProxy(id string) int {
	for i := range s.Proxies {
		if s.Proxies[i].ID == id {
			return i
		}
	}
	return -1
}

// EnabledProxies 按优先级返回已启用的代理。
func (s *State) EnabledProxies() []Proxy {
	var out []Proxy
	for _, p := range s.Proxies {
		if p.Enabled {
			out = append(out, p)
		}
	}
	return out
}

// ValidateProxy 校验单个代理的定义。
func ValidateProxy(p Proxy) error {
	if p.Host == "" {
		return errors.New("代理地址不能为空")
	}
	if strings.ContainsAny(p.Host, " /\\@?#") {
		return fmt.Errorf("代理地址 %q 含非法字符", p.Host)
	}
	if p.Port < 1 || p.Port > 65535 {
		return fmt.Errorf("端口 %d 超出范围", p.Port)
	}
	if len(p.Username) > 255 || len(p.Password) > 255 {
		return errors.New("SOCKS5 用户名/密码长度不能超过 255 字节")
	}
	if (p.Username == "") != (p.Password == "") && p.Username == "" {
		return errors.New("设置了密码但没有用户名")
	}
	if addr, err := netip.ParseAddr(p.Host); err == nil && addr.IsLoopback() {
		return errors.New("代理地址不能是回环地址")
	}
	return nil
}

// Validate 校验整个状态的一致性，不会访问系统。
func (s *State) Validate() error {
	var errs []error
	ids := map[string]bool{}
	for _, p := range s.Proxies {
		if p.ID == "" {
			errs = append(errs, errors.New("代理缺少 ID"))
		}
		if ids[p.ID] {
			errs = append(errs, fmt.Errorf("代理 ID %q 重复", p.ID))
		}
		ids[p.ID] = true
		if err := ValidateProxy(p); err != nil {
			errs = append(errs, fmt.Errorf("代理 %s: %w", p.Name, err))
		}
	}
	pol := s.Policy
	switch pol.Mode {
	case ModeFixed:
		if s.Enabled {
			i := s.FindProxy(pol.ActiveProxyID)
			if i < 0 {
				errs = append(errs, errors.New("固定模式需要选择一个出口代理"))
			} else if !s.Proxies[i].Enabled {
				errs = append(errs, errors.New("固定模式选择的代理已被禁用"))
			}
		}
	case ModeFailover:
	default:
		errs = append(errs, fmt.Errorf("未知出口模式 %q", pol.Mode))
	}
	switch pol.UDPMode {
	case UDPProxy, UDPDirect, UDPBlock:
	default:
		errs = append(errs, fmt.Errorf("未知 UDP 模式 %q", pol.UDPMode))
	}
	if pol.HealthInterval < 5 || pol.HealthInterval > 3600 {
		errs = append(errs, errors.New("健康检查间隔需在 5~3600 秒之间"))
	}
	if pol.FailThreshold < 1 || pol.FailThreshold > 100 || pol.RecoverThreshold < 1 || pol.RecoverThreshold > 100 {
		errs = append(errs, errors.New("失败/恢复阈值需在 1~100 之间"))
	}
	if s.Enabled && len(s.EnabledProxies()) == 0 {
		errs = append(errs, errors.New("启用出口代理前至少需要一个已启用的代理"))
	}
	for _, c := range s.Bypass.CIDRs {
		if _, err := ParseCIDR(c); err != nil {
			errs = append(errs, fmt.Errorf("绕过网段 %q 无效", c))
		}
	}
	for _, d := range s.Bypass.Domains {
		if err := ValidateDomain(d); err != nil {
			errs = append(errs, err)
		}
	}
	for _, ports := range [][]int{s.Bypass.TCPPorts, s.Bypass.UDPPorts, s.Bypass.MgmtPorts} {
		for _, p := range ports {
			if p < 1 || p > 65535 {
				errs = append(errs, fmt.Errorf("端口 %d 超出范围", p))
			}
		}
	}
	if g := s.Bypass.DirectGroup; g != "" && (g == "root" || g == "0") {
		errs = append(errs, errors.New("直连用户组不能是 root：绝大多数守护进程以 root 运行，这会让代理形同虚设"))
	}
	errs = append(errs, s.Settings.validate()...)
	return errors.Join(errs...)
}

func (st Settings) validate() []error {
	var errs []error
	if _, _, err := net.SplitHostPort(st.Listen); err != nil {
		errs = append(errs, fmt.Errorf("WebUI 监听地址 %q 无效", st.Listen))
	}
	ports := map[int]string{}
	for name, p := range map[string]int{"redir": st.RedirPort, "tproxy": st.TProxyPort, "api": st.APIPort, "metrics": st.MetricsPort} {
		if p < 1 || p > 65535 {
			errs = append(errs, fmt.Errorf("%s 端口 %d 无效", name, p))
		}
		if other, dup := ports[p]; dup {
			errs = append(errs, fmt.Errorf("%s 与 %s 端口冲突: %d", name, other, p))
		}
		ports[p] = name
	}
	marks := []uint32{st.MarkProxy, st.MarkDirect, st.MarkSelf, st.MarkTProxy}
	for i, m := range marks {
		if m == 0 || m&(m-1) != 0 {
			errs = append(errs, fmt.Errorf("标记 0x%x 必须是单个比特位", m))
		}
		for j := i + 1; j < len(marks); j++ {
			if m == marks[j] {
				errs = append(errs, fmt.Errorf("标记 0x%x 重复使用", m))
			}
		}
	}
	if st.RouteTable < 1 || st.RouteTable > 0x7fffffff || st.RouteTable == 253 || st.RouteTable == 254 || st.RouteTable == 255 {
		errs = append(errs, fmt.Errorf("路由表号 %d 无效或与系统表冲突", st.RouteTable))
	}
	if st.RulePriority < 1 || st.RulePriority >= 32766 {
		errs = append(errs, errors.New("策略路由优先级需在 1~32765 之间（必须先于 main 表）"))
	}
	return errs
}

// ParseCIDR 接受 "a.b.c.d" 或 "a.b.c.d/n"（仅 IPv4，IPv6 从不走代理）。
func ParseCIDR(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		s = a.String() + "/" + strconv.Itoa(a.BitLen())
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	if !p.Addr().Is4() {
		return netip.Prefix{}, errors.New("仅支持 IPv4 网段")
	}
	return p.Masked(), nil
}

// ValidateDomain 校验绕过域名后缀，如 "example.com" 或 ".example.com"。
func ValidateDomain(d string) error {
	d = strings.TrimPrefix(strings.TrimPrefix(d, "*."), ".")
	if d == "" || len(d) > 253 || !strings.Contains(d, ".") {
		return fmt.Errorf("绕过域名 %q 无效", d)
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("绕过域名 %q 无效", d)
		}
		for _, r := range label {
			if !(r == '-' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
				return fmt.Errorf("绕过域名 %q 含非法字符", d)
			}
		}
	}
	return nil
}
