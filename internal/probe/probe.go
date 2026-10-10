// Package probe 测量代理质量以及本机真实的出网路径。
package probe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/ipest-info/EgressProxyIp/internal/model"
	"github.com/ipest-info/EgressProxyIp/internal/netx"
	"github.com/ipest-info/EgressProxyIp/internal/socks5"
	"github.com/ipest-info/EgressProxyIp/internal/stun"
)

// Prober 保存所有探测共用的参数。
type Prober struct {
	Mark       uint32 // egp 自身套接字使用的 SO_MARK
	HealthURL  string
	EchoURLs   []string
	GeoURL     string
	STUNServer string
	Timeout    time.Duration
}

// New 根据设置构造 Prober。
func New(st model.Settings) *Prober {
	return &Prober{
		Mark:       st.MarkSelf,
		HealthURL:  st.HealthURL,
		EchoURLs:   st.EchoURLs,
		GeoURL:     st.GeoURL,
		STUNServer: st.STUNServer,
		Timeout:    10 * time.Second,
	}
}

func (pr *Prober) client(p model.Proxy) *socks5.Client {
	d := netx.Dialer(pr.Mark, pr.Timeout)
	d.Resolver = netx.Resolver(pr.Mark)
	return &socks5.Client{Server: p.Addr(), Username: p.Username, Password: p.Password, Dial: d.DialContext}
}

// Health 经代理完成一次端到端请求，并返回耗时。
func (pr *Prober) Health(ctx context.Context, p model.Proxy) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, pr.Timeout)
	defer cancel()
	c := netx.HTTPClientVia(pr.client(p).DialContext, pr.Timeout)
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pr.HealthURL, nil)
	if err != nil {
		return 0, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return 0, fmt.Errorf("健康检查返回 HTTP %d", resp.StatusCode)
	}
	return time.Since(start), nil
}

// Test 执行完整的代理测试：各阶段耗时、出口 IP、地理位置和 UDP 支持情况。
func (pr *Prober) Test(ctx context.Context, p model.Proxy) model.TestResult {
	res := model.TestResult{At: time.Now(), UDP: model.UDPUnknown}
	ctx, cancel := context.WithTimeout(ctx, 3*pr.Timeout)
	defer cancel()

	sc := pr.client(p)
	var once sync.Once
	var timings socks5.Timings
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, t, err := sc.Connect(ctx, addr)
		once.Do(func() { timings = t })
		return conn, err
	}
	start := time.Now()
	ips, err := EchoIPs(ctx, netx.HTTPClientVia(dial, pr.Timeout), pr.EchoURLs[:min(1, len(pr.EchoURLs))])
	res.ConnectMs = timings.Connect.Milliseconds()
	res.HandshakeMs = timings.Handshake.Milliseconds()
	res.RequestMs = time.Since(start).Milliseconds()
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.OK = true
	res.ExitIP = ips[0]

	if g, err := pr.Geo(ctx, res.ExitIP); err == nil {
		res.Country, res.Region, res.City, res.ISP = g.Country, g.RegionName, g.City, g.ISP
	}
	pr.testUDP(ctx, sc, &res)
	return res
}

func (pr *Prober) testUDP(ctx context.Context, sc *socks5.Client, res *model.TestResult) {
	if pr.STUNServer == "" {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, pr.Timeout)
	defer cancel()
	host, port, err := net.SplitHostPort(pr.STUNServer)
	if err != nil {
		return
	}
	addrs, err := netx.Resolver(pr.Mark).LookupNetIP(ctx, "ip4", host)
	if err != nil || len(addrs) == 0 {
		res.UDPDetail = "无法解析 STUN 服务器: " + errString(err)
		return
	}
	dst := net.JoinHostPort(addrs[0].String(), port)

	sess, err := sc.AssociateUDP(ctx, true)
	if err != nil && sess != nil {
		// 中继地址无法原样使用，gost 会失败。为了给运维人员更多信息，
		// 再试一下替换为服务器 IP 后 UDP 是否可用。
		res.RelayAddress = sess.Reported
		res.UDP = model.UDPUnsupported
		if s2, err2 := sc.AssociateUDP(ctx, false); err2 == nil {
			defer s2.Close()
			if mapped, err3 := stunVia(ctx, s2, dst); err3 == nil {
				res.UDPMappedIP = mapped.Addr().String()
				res.UDPDetail = fmt.Sprintf("代理返回的中继地址 %s 不可直接使用（gost 会失败），替换为服务器 IP 后可用；该代理将只用于 TCP", sess.Reported)
				return
			}
		}
		res.UDPDetail = err.Error()
		return
	}
	if err != nil {
		res.UDP = model.UDPUnsupported
		res.UDPDetail = err.Error()
		return
	}
	defer sess.Close()
	res.RelayAddress = sess.Reported
	mapped, err := stunVia(ctx, sess, dst)
	if err != nil {
		res.UDP = model.UDPUnsupported
		res.UDPDetail = "UDP 中继无响应: " + err.Error()
		return
	}
	res.UDP = model.UDPSupported
	res.UDPMappedIP = mapped.Addr().String()
	if res.ExitIP != "" && res.UDPMappedIP != res.ExitIP {
		res.UDPDetail = "UDP 出口 IP 与 TCP 出口 IP 不同"
	}
}

func stunVia(ctx context.Context, s *socks5.UDPSession, dst string) (netip.AddrPort, error) {
	req, tid := stun.Request()
	resp, _, err := s.Exchange(ctx, dst, req)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return stun.Parse(resp, tid)
}

// GeoInfo 是 ip-api.com 响应的子集。
type GeoInfo struct {
	Status     string `json:"status"`
	Message    string `json:"message"`
	Country    string `json:"country"`
	RegionName string `json:"regionName"`
	City       string `json:"city"`
	ISP        string `json:"isp"`
}

// Geo 直接（带 egp 标记）查询某个 IP 的地理位置；查询只会暴露被查询的 IP，
// 不会暴露本机出口。
func (pr *Prober) Geo(ctx context.Context, ip string) (*GeoInfo, error) {
	if pr.GeoURL == "" {
		return nil, errors.New("未启用地理位置查询")
	}
	c := netx.HTTPClient(pr.Mark, pr.Timeout)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf(pr.GeoURL, ip), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var g GeoInfo
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&g); err != nil {
		return nil, err
	}
	if g.Status != "" && g.Status != "success" {
		return nil, errors.New(g.Message)
	}
	return &g, nil
}

// EchoIPs 依次向每个 URL 询问调用方的 IP，并按顺序返回结果；只有全部失败时才返回错误。
func EchoIPs(ctx context.Context, c *http.Client, urls []string) ([]string, error) {
	var out []string
	var errs []error
	for _, u := range urls {
		ip, err := echo(ctx, c, u)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", u, err))
			continue
		}
		out = append(out, ip)
	}
	if len(out) == 0 {
		if len(errs) == 0 {
			return nil, errors.New("未配置 IP 回显服务")
		}
		return nil, errors.Join(errs...)
	}
	return out, nil
}

func echo(ctx context.Context, c *http.Client, u string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "curl/8.5.0")
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	s := strings.TrimSpace(string(b))
	a, err := netip.ParseAddr(s)
	if err != nil {
		return "", fmt.Errorf("回显内容不是 IP: %.40q", s)
	}
	return a.Unmap().String(), nil
}

// EgressResult 描述互联网在某条路径上看到的来源 IP。
type EgressResult struct {
	IPs       []string `json:"ips"`
	Consensus string   `json:"consensus,omitempty"` // 至少两个服务结果一致时才设置
	Error     string   `json:"error,omitempty"`
}

// Egress 用 c 查询所有回显服务并汇总结果。
func (pr *Prober) Egress(ctx context.Context, c *http.Client) EgressResult {
	ips, err := EchoIPs(ctx, c, pr.EchoURLs)
	r := EgressResult{IPs: ips}
	if err != nil {
		r.Error = err.Error()
	}
	count := map[string]int{}
	for _, ip := range ips {
		count[ip]++
		if count[ip] >= 2 {
			r.Consensus = ip
		}
	}
	if r.Consensus == "" && len(ips) == 1 {
		r.Consensus = ips[0]
	}
	return r
}

// RealEgress 测量普通进程实际走的路径（不打标记，请求和其他程序一样经过拦截规则）。
func (pr *Prober) RealEgress(ctx context.Context) EgressResult {
	return pr.Egress(ctx, netx.HTTPClient(0, pr.Timeout))
}

// DirectEgress 测量 ECS 自身的出口地址（打标记，因此绕过 egp）。
func (pr *Prober) DirectEgress(ctx context.Context) EgressResult {
	return pr.Egress(ctx, netx.HTTPClient(pr.Mark, pr.Timeout))
}

func errString(err error) string {
	if err == nil {
		return "无结果"
	}
	return err.Error()
}
