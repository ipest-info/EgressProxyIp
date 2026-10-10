package gost

import (
	"context"
	"encoding/json"
	"flag"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"log/slog"

	"github.com/ipest-info/EgressProxyIp/internal/model"
)

var update = flag.Bool("update", false, "重新生成 golden 文件")

func testState() model.State {
	st := model.Default()
	st.Enabled = true
	st.Proxies = []model.Proxy{
		{ID: "a1", Name: "主", Host: "203.0.113.20", Port: 1080, Username: "u1", Password: "p1", Enabled: true, UDP: model.UDPSupported},
		{ID: "b2", Name: "备", Host: "proxy.example.net", Port: 1080, Enabled: true, UDP: model.UDPUnsupported},
	}
	return st
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 golden 文件失败（可用 -update 生成）: %v", err)
	}
	if string(want) != string(got) {
		t.Errorf("%s 与 golden 不一致:\n--- 实际 ---\n%s", name, got)
	}
}

func TestRenderGolden(t *testing.T) {
	cases := map[string]func(*model.State){
		"killswitch_udp_proxy.json": func(s *model.State) {},
		"no_killswitch_domains.json": func(s *model.State) {
			s.Policy.KillSwitch = false
			s.Bypass.Domains = []string{"example.com", "*.aliyuncs.com"}
		},
		"udp_block.json": func(s *model.State) { s.Policy.UDPMode = model.UDPBlock },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			st := testState()
			mut(&st)
			cfg := Render(Input{State: st, Nodes: st.EnabledProxies(), APIPassword: "secret"})
			golden(t, name, cfg.JSON())
		})
	}
}

func TestRenderInvariants(t *testing.T) {
	st := testState()
	cfg := Render(Input{State: st, Nodes: st.EnabledProxies(), APIPassword: "x"})
	hop := cfg.Hops[0]
	if last := hop.Nodes[len(hop.Nodes)-1]; last.Name != BlackholeName {
		t.Fatalf("开启 kill switch 时黑洞节点必须排在最后，实际为 %s", last.Name)
	}
	for _, n := range hop.Nodes {
		if n.Metadata["so_mark"] != mdInt(st.Settings.MarkProxy) {
			t.Errorf("节点 %s 缺少代理标记", n.Name)
		}
		if n.Name != BlackholeName && n.Connector.Metadata["relay"] != "udp" {
			t.Errorf("节点 %s 必须设置 relay=udp", n.Name)
		}
	}
	for _, s := range cfg.Services {
		if s.Metadata["so_mark"] != mdInt(st.Settings.MarkDirect) {
			t.Errorf("服务 %s 缺少直连标记", s.Name)
		}
		if !strings.HasPrefix(s.Addr, "127.0.0.1:") {
			t.Errorf("服务 %s 必须只监听回环地址", s.Name)
		}
	}
	if !strings.HasPrefix(cfg.API.Addr, "127.0.0.1:") || cfg.API.Auth == nil {
		t.Error("API 必须只监听回环地址并启用认证")
	}
	red := cfg.Redacted()
	if b, _ := json.Marshal(red); strings.Contains(string(b), "p1") || strings.Contains(string(b), `"x"`) {
		t.Error("脱敏后的配置仍包含密码")
	}
	st.Policy.KillSwitch = false
	if h := RenderHop(st, st.EnabledProxies()); h.Nodes[len(h.Nodes)-1].Name == BlackholeName {
		t.Error("关闭 kill switch 时不应添加黑洞节点")
	}
}

func TestParseVersion(t *testing.T) {
	v, err := ParseVersion("gost 3.3.1 (go1.26.3 linux/amd64)\n")
	if err != nil || v != (Version{3, 3, 1}) {
		t.Fatalf("got %v %v", v, err)
	}
	if !(Version{3, 2, 9}).Less(MinVersion) || (Version{3, 3, 0}).Less(MinVersion) {
		t.Error("版本比较错误")
	}
}

func TestParseMetrics(t *testing.T) {
	in := `# HELP x
gost_service_transfer_input_bytes_total{client="",host="h",service="egp-redir"} 100
gost_service_transfer_output_bytes_total{client="",host="h",service="egp-redir"} 2000
gost_service_transfer_output_bytes_total{client="",host="h",service="egp-tproxy"} 3
gost_service_transfer_output_bytes_total{client="",host="h",service="other"} 999
gost_service_requests_in_flight{client="",host="h",service="egp-redir"} 4
`
	tr := ParseMetrics(strings.NewReader(in))
	if tr.InputBytes != 100 || tr.OutputBytes != 2003 || tr.InFlight != 4 {
		t.Fatalf("%+v", tr)
	}
}

// TestRealGost 用真实的 gost 加载生成的配置，并验证 API 能在运行时替换 hop。
// 设置 EGP_GOST_BIN 指向 gost 可执行文件时才运行。
func TestRealGost(t *testing.T) {
	bin := os.Getenv("EGP_GOST_BIN")
	if bin == "" {
		t.Skip("未设置 EGP_GOST_BIN")
	}
	if _, err := CheckBinary(context.Background(), bin); err != nil {
		t.Fatal(err)
	}
	st := testState()
	st.Bypass.Domains = []string{"example.com"}
	st.Settings.RedirPort = freePort(t)
	st.Settings.TProxyPort = freePort(t)
	st.Settings.APIPort = freePort(t)
	st.Settings.MetricsPort = freePort(t)
	// 非 root 环境下 redu（需要 IP_TRANSPARENT）可能无法监听，测试只验证 TCP 部分。
	if os.Geteuid() != 0 {
		st.Policy.UDPMode = model.UDPDirect
	}
	cfg := Render(Input{State: st, Nodes: st.EnabledProxies(), APIPassword: "pw"})
	dir := t.TempDir()
	path := filepath.Join(dir, "gost.json")
	os.WriteFile(path, cfg.JSON(), 0o600)

	p := NewProcess(bin, path, slog.Default())
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	api := NewAPI(st.Settings.APIPort, "pw")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var err error
	for ctx.Err() == nil {
		if err = api.Ping(ctx); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("gost API 未就绪: %v\n%s", err, strings.Join(p.Logs(), "\n"))
	}
	hop := RenderHop(st, st.EnabledProxies()[:1])
	if err := api.UpdateHop(ctx, hop); err != nil {
		t.Fatalf("更新 hop 失败: %v", err)
	}
	b, err := api.do(ctx, "GET", "/config/hops/"+HopName, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), NodeName("b2")) || !strings.Contains(string(b), NodeName("a1")) {
		t.Fatalf("hop 未被替换: %s", b)
	}
	if _, err := FetchTraffic(ctx, st.Settings.MetricsPort); err != nil {
		t.Fatalf("读取指标失败: %v", err)
	}
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
