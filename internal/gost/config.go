// Package gost 负责生成 gost v3 转发引擎的配置，并监管、控制其进程。
package gost

import (
	"encoding/json"
	"net"
	"strconv"
	"strings"

	"github.com/ipest-info/EgressProxyIp/internal/model"
)

// egp 在 gost 中创建的对象名称。
const (
	ServiceRedir   = "egp-redir"
	ServiceTProxy  = "egp-tproxy"
	ChainName      = "egp-chain"
	HopName        = "egp-egress"
	BypassName     = "egp-direct-domains"
	BlackholeName  = "egp-blackhole"
	BlackholeAddr  = "127.0.0.1:1"
	APIUser        = "egp"
	nodePrefix     = "px-"
	blackholeFails = 1 << 30
)

// Config 是 egp 用到的 gost v3 配置结构子集。
type Config struct {
	Services []Service `json:"services"`
	Chains   []Chain   `json:"chains"`
	Hops     []Hop     `json:"hops"`
	Bypasses []Bypass  `json:"bypasses,omitempty"`
	API      *Endpoint `json:"api,omitempty"`
	Metrics  *Endpoint `json:"metrics,omitempty"`
	Log      *Log      `json:"log,omitempty"`
}

type Service struct {
	Name     string         `json:"name"`
	Addr     string         `json:"addr"`
	Handler  Handler        `json:"handler"`
	Listener Listener       `json:"listener"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

type Handler struct {
	Type     string         `json:"type"`
	Chain    string         `json:"chain,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

type Listener struct {
	Type     string         `json:"type"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

type Chain struct {
	Name string   `json:"name"`
	Hops []HopRef `json:"hops"`
}

// HopRef 让转发链引用顶层定义的 hop，这样运行时可以通过 API 单独替换 hop，
// 无需改动转发链和服务。
type HopRef struct {
	Name string `json:"name"`
}

type Hop struct {
	Name     string    `json:"name"`
	Selector *Selector `json:"selector,omitempty"`
	Bypass   string    `json:"bypass,omitempty"`
	Nodes    []Node    `json:"nodes"`
}

type Selector struct {
	Strategy    string `json:"strategy"`
	MaxFails    int    `json:"maxFails"`
	FailTimeout string `json:"failTimeout"`
}

type Node struct {
	Name      string         `json:"name"`
	Addr      string         `json:"addr"`
	Network   string         `json:"network,omitempty"`
	Connector Connector      `json:"connector"`
	Dialer    Dialer         `json:"dialer"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

type Connector struct {
	Type     string         `json:"type"`
	Auth     *Auth          `json:"auth,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

type Dialer struct {
	Type string `json:"type"`
}

type Auth struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type Bypass struct {
	Name     string   `json:"name"`
	Matchers []string `json:"matchers"`
}

type Endpoint struct {
	Addr string `json:"addr"`
	Path string `json:"path,omitempty"`
	Auth *Auth  `json:"auth,omitempty"`
}

type Log struct {
	Level  string `json:"level"`
	Format string `json:"format"`
	Output string `json:"output"`
}

// Input 是生成配置所需的全部输入。
type Input struct {
	State model.State
	// Nodes 是放入 hop 的代理，按选择顺序排列，由控制器根据策略和健康状态得出。
	Nodes       []model.Proxy
	APIPassword string
}

// NodeName 返回代理对应的 gost 节点名。
func NodeName(id string) string { return nodePrefix + id }

func loopback(port int) string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) }

// Render 生成完整的 gost 配置。
func Render(in Input) Config {
	st := in.State.Settings
	pol := in.State.Policy
	domains := in.State.Bypass.Domains

	redir := Service{
		Name:     ServiceRedir,
		Addr:     loopback(st.RedirPort),
		Handler:  Handler{Type: "red", Chain: ChainName},
		Listener: Listener{Type: "red"},
		// 直连拨号（域名绕过）使用单独的标记，便于防护链把它与连接上游代理的流量区分开。
		Metadata: map[string]any{"so_mark": mdInt(st.MarkDirect)},
	}
	if len(domains) > 0 {
		// 只有存在域名规则时才需要嗅探 TLS SNI / HTTP Host；
		// 嗅探会让服务端先发言的协议（SSH、SMTP 等）多等待一个超时时间。
		redir.Handler.Metadata = map[string]any{
			"sniffing":          true,
			"sniffing.timeout":  "300ms",
			"sniffing.fallback": true,
		}
	}
	cfg := Config{
		Services: []Service{redir},
		Chains:   []Chain{{Name: ChainName, Hops: []HopRef{{Name: HopName}}}},
		Hops:     []Hop{RenderHop(in.State, in.Nodes)},
		API: &Endpoint{
			Addr: loopback(st.APIPort),
			Auth: &Auth{Username: APIUser, Password: in.APIPassword},
		},
		Metrics: &Endpoint{Addr: loopback(st.MetricsPort), Path: "/metrics"},
		Log:     &Log{Level: "info", Format: "text", Output: "stderr"},
	}
	if pol.UDPMode == model.UDPProxy {
		cfg.Services = append(cfg.Services, Service{
			Name:     ServiceTProxy,
			Addr:     loopback(st.TProxyPort),
			Handler:  Handler{Type: "redu", Chain: ChainName},
			Listener: Listener{Type: "redu", Metadata: map[string]any{"ttl": "60s"}},
			Metadata: map[string]any{"so_mark": mdInt(st.MarkDirect)},
		})
	}
	if len(domains) > 0 {
		cfg.Bypasses = []Bypass{{Name: BypassName, Matchers: domainMatchers(domains)}}
	}
	return cfg
}

// RenderHop 生成承载上游代理的 hop；健康状态改变节点顺序时，控制器也通过 API 下发它。
func RenderHop(st model.State, nodes []model.Proxy) Hop {
	set := st.Settings
	h := Hop{
		Name: HopName,
		// fifo = 总是使用第一个可用节点，保持出口 IP 稳定不乱跳。
		Selector: &Selector{Strategy: "fifo", MaxFails: 3, FailTimeout: "30s"},
		Nodes:    []Node{},
	}
	if len(st.Bypass.Domains) > 0 {
		// hop 级别的 bypass 命中后 gost 会跳过该 hop，即直连。
		h.Bypass = BypassName
	}
	for _, p := range nodes {
		n := Node{
			Name: NodeName(p.ID),
			Addr: p.Addr(),
			Connector: Connector{
				Type: "socks5",
				// relay=udp 表示使用标准的 UDP ASSOCIATE；不设置时 gost 会使用
				// 自有的 UDP-over-TCP 扩展，只有 gost 服务端才能识别。
				Metadata: map[string]any{"relay": "udp"},
			},
			Dialer:   Dialer{Type: "tcp"},
			Metadata: map[string]any{"so_mark": mdInt(set.MarkProxy)},
		}
		if p.Username != "" {
			n.Connector.Auth = &Auth{Username: p.Username, Password: p.Password}
		}
		if p.UDP == model.UDPUnsupported {
			n.Network = "tcp" // UDP 请求会跳过该节点
		}
		h.Nodes = append(h.Nodes, n)
	}
	if st.Policy.KillSwitch {
		// 所有真实节点都被标记失败时，gost 的 hop 选不出节点，路由会退化为直连，
		// 导致真实 IP 泄露。追加一个永远不会被过滤、也永远连不上的“黑洞”节点，
		// 把这种情况变成连接直接失败。
		h.Nodes = append(h.Nodes, Node{
			Name:      BlackholeName,
			Addr:      BlackholeAddr,
			Connector: Connector{Type: "socks5"},
			Dialer:    Dialer{Type: "tcp"},
			Metadata: map[string]any{
				"so_mark":     mdInt(set.MarkProxy),
				"maxFails":    strconv.Itoa(blackholeFails),
				"failTimeout": "1s",
			},
		})
	}
	return h
}

// mdInt 把整数写成字符串。gost 读取 metadata 中的整数时只识别 int 和 string，
// 而 JSON 配置文件里的数字会被解析成 float64 并被静默忽略（例如 so_mark 失效会导致流量回环）。
func mdInt(v uint32) string { return strconv.FormatUint(uint64(v), 10) }

func domainMatchers(domains []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, d := range domains {
		d = strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(d), "*."), "."))
		for _, m := range []string{d, "." + d} {
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	return out
}

// JSON 以确定的顺序序列化配置。
func (c Config) JSON() []byte {
	b, _ := json.MarshalIndent(c, "", "  ")
	return append(b, '\n')
}

// Redacted 返回隐藏了密码的副本，用于展示。
func (c Config) Redacted() Config {
	b, _ := json.Marshal(c)
	var cp Config
	json.Unmarshal(b, &cp)
	if cp.API != nil && cp.API.Auth != nil {
		cp.API.Auth.Password = "******"
	}
	for i := range cp.Hops {
		for j := range cp.Hops[i].Nodes {
			if a := cp.Hops[i].Nodes[j].Connector.Auth; a != nil && a.Password != "" {
				a.Password = "******"
			}
		}
	}
	return cp
}
