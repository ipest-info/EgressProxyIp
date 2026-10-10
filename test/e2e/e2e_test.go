//go:build e2e

// 端到端测试：在独立的网络命名空间里搭建“ECS + 互联网”，用真实的 gost 与 iptables
// 验证出口 IP、UDP、故障切换、kill switch、待确认回滚和入站连接不受影响。
//
// 运行方式（需要 root、iproute2、gost）：
//
//	./test/e2e/run.sh
package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ipest-info/EgressProxyIp/internal/model"
	"github.com/ipest-info/EgressProxyIp/internal/netx"
	"github.com/ipest-info/EgressProxyIp/internal/passwd"
	"github.com/ipest-info/EgressProxyIp/internal/store"
	"github.com/ipest-info/EgressProxyIp/internal/stun"
)

const (
	ecsIP    = "198.51.100.1" // 模拟 ECS 自身的公网 IP
	gwIP     = "198.51.100.2"
	echoBase = "http://203.0.113.10"
	proxyA   = "203.0.113.20"
	proxyB   = "203.0.113.21"
	stunAddr = "203.0.113.30:3478"
	webAddr  = "127.0.0.1:18088"
	password = "e2e-password"
)

func freshNetns() bool {
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(b), "\n")[2:] {
		name, _, ok := strings.Cut(strings.TrimSpace(l), ":")
		if ok && name != "lo" {
			return false
		}
	}
	return true
}

func sh(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

// setupNet 创建“互联网”命名空间并用 veth 连接，返回该命名空间中常驻进程的 PID。
func setupNet(t *testing.T) int {
	holder := exec.Command("unshare", "-n", "sleep", "3600")
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { holder.Process.Kill(); holder.Wait() })
	pid := strconv.Itoa(holder.Process.Pid)
	time.Sleep(200 * time.Millisecond)
	in := func(args ...string) { sh(t, "nsenter", append([]string{"-t", pid, "-n"}, args...)...) }

	sh(t, "ip", "link", "set", "lo", "up")
	sh(t, "ip", "link", "add", "egp0", "type", "veth", "peer", "name", "inet0")
	sh(t, "ip", "link", "set", "inet0", "netns", pid)
	sh(t, "ip", "addr", "add", ecsIP+"/24", "dev", "egp0")
	sh(t, "ip", "link", "set", "egp0", "up")
	sh(t, "ip", "route", "add", "default", "via", gwIP)

	in("ip", "link", "set", "lo", "up")
	in("ip", "addr", "add", gwIP+"/24", "dev", "inet0")
	in("ip", "link", "set", "inet0", "up")
	for _, a := range []string{"203.0.113.10", proxyA, proxyB, "203.0.113.30"} {
		in("ip", "addr", "add", a+"/32", "dev", "lo")
	}
	return holder.Process.Pid
}

type client struct {
	t    *testing.T
	http *http.Client
}

func (c *client) do(method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, "http://"+webAddr+path, rd)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, b)
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

// dumpLogs 在失败时输出审计日志和 gost 日志，便于定位问题。
func (c *client) dumpLogs() {
	var logs struct {
		Audit  []map[string]any `json:"audit"`
		Engine []string         `json:"engine"`
	}
	if err := c.do("GET", "/api/logs", nil, &logs); err == nil {
		for _, e := range logs.Audit {
			c.t.Logf("审计: %v", e)
		}
		for _, l := range logs.Engine {
			c.t.Logf("gost: %s", l)
		}
	}
	c.t.Logf("iptables-save:\n%s", iptablesSave(c.t))
	rules, _ := exec.Command("ip", "rule").CombinedOutput()
	routes, _ := exec.Command("ip", "route", "show", "table", "all").CombinedOutput()
	c.t.Logf("ip rule:\n%s\nip route:\n%s", rules, routes)
}

func (c *client) must(method, path string, body any, out any) {
	c.t.Helper()
	if err := c.do(method, path, body, out); err != nil {
		c.dumpLogs()
		c.t.Fatal(err)
	}
}

// egress 用普通（不打标记）的连接访问回显服务，返回看到的来源 IP。
func egress() (string, error) {
	cl := netx.HTTPClient(0, 4*time.Second)
	resp, err := cl.Get(echoBase + "/ip")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(b)), nil
}

// udpEgress 用普通 UDP 套接字向 STUN 服务发请求，返回映射地址的 IP。
func udpEgress() (string, error) {
	conn, err := net.Dial("udp", stunAddr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	req, tid := stun.Request()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(req); err != nil {
		return "", err
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	ap, err := stun.Parse(buf[:n], tid)
	if err != nil {
		return "", err
	}
	return ap.Addr().String(), nil
}

// ctl 控制模拟互联网中的代理（带自身标记，绕过 egp）。
func ctl(t *testing.T, action, addr string) {
	t.Helper()
	cl := netx.HTTPClient(model.DefaultSettings().MarkSelf, 4*time.Second)
	resp, err := cl.Get(echoBase + "/ctl/" + action + "?addr=" + addr)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func waitFor(t *testing.T, what string, timeout time.Duration, cond func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	last := ""
	for time.Now().Before(deadline) {
		ok, s := cond()
		if ok {
			return
		}
		last = s
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("等待超时：%s（最后状态：%s）", what, last)
}

func egressIs(want string) func() (bool, string) {
	return func() (bool, string) {
		ip, err := egress()
		if err != nil {
			return false, err.Error()
		}
		return ip == want, ip
	}
}

func iptablesSave(t *testing.T) string {
	out, _ := exec.Command("iptables-save", "-c").CombinedOutput()
	return string(out)
}

func TestEndToEnd(t *testing.T) {
	if os.Geteuid() != 0 || !freshNetns() {
		t.Skip("需要 root 且在全新的网络命名空间中运行（见 run.sh）")
	}
	egpBin, fakeBin, gostBin := os.Getenv("EGP_BIN"), os.Getenv("FAKENET_BIN"), os.Getenv("EGP_GOST_BIN")
	if egpBin == "" || fakeBin == "" || gostBin == "" {
		t.Skip("需要 EGP_BIN、FAKENET_BIN、EGP_GOST_BIN")
	}
	pid := setupNet(t)

	fake := exec.Command("nsenter", "-t", strconv.Itoa(pid), "-n", fakeBin)
	fake.Stdout, fake.Stderr = os.Stderr, os.Stderr
	if err := fake.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fake.Process.Kill(); fake.Wait() })
	waitFor(t, "模拟互联网就绪", 10*time.Second, egressIs(ecsIP))

	// 入站服务：模拟 ECS 上对外提供的服务（如 SSH），用于验证回包不受影响。
	inbound, err := net.Listen("tcp", ecsIP+":18999")
	if err != nil {
		t.Fatal(err)
	}
	go http.Serve(inbound, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "inbound-ok") }))
	inboundOK := func() bool {
		out, err := exec.Command("nsenter", "-t", strconv.Itoa(pid), "-n", "curl", "-s", "-m", "3", "http://"+ecsIP+":18999/").CombinedOutput()
		return err == nil && string(out) == "inbound-ok"
	}

	// 准备状态目录。
	dir := t.TempDir()
	st := model.Default()
	st.Settings.Listen = webAddr
	st.Settings.GostBin = gostBin
	st.Settings.EchoURLs = []string{echoBase + "/ip", echoBase + "/ip2"}
	st.Settings.HealthURL = echoBase + "/204"
	st.Settings.GeoURL = echoBase + "/geo/%s"
	st.Settings.STUNServer = stunAddr
	st.Policy.HealthInterval = 5
	st.Policy.FailThreshold = 1
	st.Policy.RecoverThreshold = 1
	h, _ := passwd.Hash(password)
	st.Settings.AdminHash = h
	s, _ := store.New(dir)
	if err := s.Save(st); err != nil {
		t.Fatal(err)
	}

	egp := exec.Command(egpBin, "serve", "-dir", dir, "-confirm-timeout", "8s")
	egp.Stdout, egp.Stderr = os.Stderr, os.Stderr
	if err := egp.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		egp.Process.Signal(syscall.SIGTERM)
		egp.Wait()
		exec.Command(egpBin, "cleanup", "-dir", dir).Run()
	})

	jar, _ := cookiejar.New(nil)
	c := &client{t: t, http: &http.Client{Jar: jar, Timeout: 120 * time.Second, Transport: &http.Transport{Proxy: nil}}}
	waitFor(t, "WebUI 就绪", 15*time.Second, func() (bool, string) {
		err := c.do("POST", "/api/login", map[string]string{"username": "admin", "password": password}, nil)
		return err == nil, fmt.Sprint(err)
	})

	// 1. 导入两个代理并测试第一个。
	var imp struct {
		Added int `json:"added"`
	}
	c.must("POST", "/api/proxies/import", map[string]string{"text": fmt.Sprintf("socks5://u:p@%s:1080#主\nsocks5://u:p@%s:1080#备", proxyA, proxyB)}, &imp)
	if imp.Added != 2 {
		t.Fatalf("导入了 %d 个代理", imp.Added)
	}
	var state struct {
		Proxies []struct {
			ID string `json:"id"`
		} `json:"proxies"`
	}
	c.must("GET", "/api/state", nil, &state)
	var tr model.TestResult
	c.must("POST", "/api/proxies/"+state.Proxies[0].ID+"/test", map[string]any{}, &tr)
	if !tr.OK || tr.ExitIP != proxyA || tr.UDP != model.UDPSupported || tr.UDPMappedIP != proxyA || tr.Country != "测试国" {
		t.Fatalf("代理测试结果不符合预期: %+v", tr)
	}

	// 2. 启用并应用，确认后出口应为代理 A。
	c.must("PUT", "/api/enabled", map[string]bool{"enabled": true}, nil)
	var ar struct {
		Nonce  string `json:"nonce"`
		Verify struct {
			OK     bool   `json:"ok"`
			RealIP string `json:"realIp"`
		} `json:"verify"`
	}
	if err := c.do("POST", "/api/apply", map[string]bool{"skipVerify": false}, &ar); err != nil {
		c.dumpLogs()
		if os.Getenv("E2E_DEBUG") != "" {
			c.do("POST", "/api/apply", map[string]bool{"skipVerify": true}, &ar)
			egress()
			c.t.Logf("跳过校验后的规则计数:\n%s", iptablesSave(t))
		}
		t.Fatal(err)
	}
	if !ar.Verify.OK || ar.Verify.RealIP != proxyA {
		t.Fatalf("应用后校验不符合预期: %+v", ar)
	}
	c.must("POST", "/api/apply/confirm", map[string]string{"nonce": ar.Nonce}, nil)
	if ip, err := egress(); err != nil || ip != proxyA {
		t.Fatalf("TCP 出口应为 %s，实际 %s %v", proxyA, ip, err)
	}
	if ip, err := udpEgress(); err != nil || ip != proxyA {
		c.dumpLogs()
		t.Fatalf("UDP 出口应为 %s，实际 %s %v", proxyA, ip, err)
	}
	if !inboundOK() {
		t.Fatal("启用出口代理后，入站连接（模拟 SSH）不可用")
	}
	t.Log("✔ TCP/UDP 出口均为代理 IP，入站连接正常")

	// 3. 代理 A 故障 → 自动切换到 B；A 恢复 → 切回 A。
	ctl(t, "stop", proxyA+":1080")
	waitFor(t, "故障切换到代理 B", 30*time.Second, egressIs(proxyB))
	ctl(t, "start", proxyA+":1080")
	waitFor(t, "切回代理 A", 30*time.Second, egressIs(proxyA))
	t.Log("✔ 故障切换与自动回切正常")

	// 4. 全部代理故障且 kill switch 开启 → 断网，绝不回落到 ECS 自身 IP。
	ctl(t, "stop", proxyA+":1080")
	ctl(t, "stop", proxyB+":1080")
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if ip, err := egress(); err == nil && ip == ecsIP {
			t.Fatal("kill switch 开启时流量泄露到了 ECS 自身 IP")
		}
		time.Sleep(500 * time.Millisecond)
	}
	if _, err := egress(); err == nil {
		t.Fatal("全部代理故障时连接应失败")
	}
	if ip, err := udpEgress(); err == nil && ip == ecsIP {
		t.Fatal("kill switch 开启时 UDP 泄露到了 ECS 自身 IP")
	}
	if !inboundOK() {
		t.Fatal("kill switch 生效时入站连接不应受影响")
	}
	ctl(t, "start", proxyA+":1080")
	ctl(t, "start", proxyB+":1080")
	waitFor(t, "代理恢复后出口恢复", 30*time.Second, egressIs(proxyA))
	t.Log("✔ kill switch 生效时没有泄露")

	// 5. 应用后不确认 → 超时自动回滚（UDP 改为直连，回滚后应仍走代理）。
	var pol model.Policy
	var full struct {
		Policy model.Policy `json:"policy"`
	}
	c.must("GET", "/api/state", nil, &full)
	pol = full.Policy
	pol.UDPMode = model.UDPDirect
	c.must("PUT", "/api/policy", pol, nil)
	c.must("POST", "/api/apply", map[string]bool{"skipVerify": false}, &ar)
	if ip, _ := udpEgress(); ip != ecsIP {
		t.Fatalf("UDP 直连模式下 UDP 出口应为 ECS IP，实际 %s", ip)
	}
	time.Sleep(10 * time.Second)
	var status struct {
		Pending any    `json:"pending"`
		UDPMode string `json:"udpMode"`
	}
	c.must("GET", "/api/status", nil, &status)
	if status.Pending != nil || status.UDPMode != model.UDPProxy {
		t.Fatalf("超时后应回滚到 UDP 经代理: %+v", status)
	}
	if ip, err := udpEgress(); err != nil || ip != proxyA {
		t.Fatalf("回滚后 UDP 出口应为 %s，实际 %s %v", proxyA, ip, err)
	}
	t.Log("✔ 超时未确认自动回滚")

	// 6. 关闭 kill switch：全部代理故障时降级直连，恢复后重新走代理。
	pol.UDPMode = model.UDPProxy
	pol.KillSwitch = false
	c.must("PUT", "/api/policy", pol, nil)
	c.must("POST", "/api/apply", map[string]bool{"skipVerify": false}, &ar)
	c.must("POST", "/api/apply/confirm", map[string]string{"nonce": ar.Nonce}, nil)
	ctl(t, "stop", proxyA+":1080")
	ctl(t, "stop", proxyB+":1080")
	waitFor(t, "降级为直连", 30*time.Second, egressIs(ecsIP))
	ctl(t, "start", proxyA+":1080")
	ctl(t, "start", proxyB+":1080")
	waitFor(t, "恢复走代理", 30*time.Second, egressIs(proxyA))
	t.Log("✔ 关闭 kill switch 时降级直连并自动恢复")

	// 7. gost 被杀死后自动重启。
	var st2 struct {
		Engine struct {
			PID int `json:"pid"`
		} `json:"engine"`
	}
	c.must("GET", "/api/status", nil, &st2)
	syscall.Kill(st2.Engine.PID, syscall.SIGKILL)
	waitFor(t, "gost 自动重启", 30*time.Second, egressIs(proxyA))
	t.Log("✔ gost 异常退出后自动重启")

	// 8. 规则被人为删除后自动修复。
	exec.Command("iptables", "-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-m", "comment", "--comment", "egp", "-j", "EGP_TCP_OUT").Run()
	if ip, _ := egress(); ip != ecsIP {
		t.Fatalf("删除跳转后应暂时直连，实际 %s", ip)
	}
	waitFor(t, "规则漂移自动修复", 45*time.Second, egressIs(proxyA))
	t.Log("✔ 规则漂移自动修复")

	// 9. 停用 → 直连，规则全部清理。
	c.must("PUT", "/api/enabled", map[string]bool{"enabled": false}, nil)
	c.must("POST", "/api/apply", map[string]bool{"skipVerify": false}, nil)
	if ip, err := egress(); err != nil || ip != ecsIP {
		t.Fatalf("停用后应直连，实际 %s %v", ip, err)
	}
	if strings.Contains(iptablesSave(t), "EGP") {
		t.Fatalf("停用后仍有残留规则:\n%s", iptablesSave(t))
	}
	t.Log("✔ 停用后恢复直连且无残留规则")
}
