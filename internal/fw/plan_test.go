package fw

import (
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ipest-info/EgressProxyIp/internal/model"
)

var update = flag.Bool("update", false, "重新生成 golden 文件")

func baseInput() Input {
	st := model.Default()
	return Input{
		Settings:          st.Settings,
		Policy:            st.Policy,
		Bypass:            st.Bypass,
		AutoCIDRs:         []netip.Prefix{netip.MustParsePrefix("172.31.0.0/20"), netip.MustParsePrefix("100.100.2.136/32"), netip.MustParsePrefix("8.8.8.8/32")},
		Proxies:           []Endpoint{{IP: netip.MustParseAddr("203.0.113.20"), Port: 1080}, {Port: 2080}},
		LocalUDPPorts:     []int{51820},
		WebUIPort:         8088,
		DirectGroupExists: true,
	}
}

func TestPlanGolden(t *testing.T) {
	cases := map[string]func(*Input){
		"ks_udp_proxy.txt":   func(in *Input) {},
		"ks_udp_direct.txt":  func(in *Input) { in.Policy.UDPMode = model.UDPDirect },
		"ks_udp_block.txt":   func(in *Input) { in.Policy.UDPMode = model.UDPBlock },
		"noks_udp_proxy.txt": func(in *Input) { in.Policy.KillSwitch = false; in.Policy.BlockIPv6 = false },
		"noks_udp_block.txt": func(in *Input) { in.Policy.KillSwitch = false; in.Policy.UDPMode = model.UDPBlock },
		"ks_domains_ports.txt": func(in *Input) {
			in.Bypass.Domains = []string{"example.com"}
			in.Bypass.TCPPorts = []int{25, 465}
			in.Bypass.CIDRs = []string{"198.51.100.0/24", "1.2.3.4"}
		},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			in := baseInput()
			mut(&in)
			got := Plan(in, true).Script()
			path := filepath.Join("testdata", name)
			if *update {
				os.MkdirAll("testdata", 0o755)
				os.WriteFile(path, []byte(got), 0o644)
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("读取 golden 失败（可用 -update 生成）: %v", err)
			}
			if got != string(want) {
				t.Errorf("规则与 golden 不一致:\n%s", got)
			}
		})
	}
}

// TestPlanInvariants 检查所有组合下的安全性不变式。
func TestPlanInvariants(t *testing.T) {
	for _, ks := range []bool{true, false} {
		for _, udp := range []string{model.UDPProxy, model.UDPDirect, model.UDPBlock} {
			for _, v6 := range []bool{true, false} {
				in := baseInput()
				in.Policy.KillSwitch, in.Policy.UDPMode, in.Policy.BlockIPv6 = ks, udp, v6
				rs := Plan(in, true)
				checkInvariants(t, rs, in)
			}
		}
	}
	if !Plan(baseInput(), false).Empty() {
		t.Error("未启用时规则集应为空")
	}
}

func checkInvariants(t *testing.T, rs Ruleset, in Input) {
	t.Helper()
	declared := map[string]bool{}
	for _, chains := range [][]Chain{rs.V4, rs.V6} {
		for _, c := range chains {
			declared[c.Name] = true
			action := false
			for _, r := range c.Rules {
				j := strings.Join(r, " ")
				isAction := strings.Contains(j, "-j REDIRECT") || strings.Contains(j, "-j MARK") || strings.Contains(j, "-j REJECT") || strings.Contains(j, "-j TPROXY")
				// 引擎/自身标记和本机地址的放行规则必须出现在任何动作之前，否则会形成回环。
				if strings.Contains(j, markArg(in.Settings.MarkSelf)) && strings.HasSuffix(j, "RETURN") && action {
					t.Errorf("%s: 自身标记的放行规则出现在动作之后", c.Name)
				}
				if isAction {
					action = true
				}
				// 引用的链必须已经声明。
				for i, a := range r {
					if a == "-j" && strings.HasPrefix(r[i+1], "EGP") && !declared[r[i+1]] {
						t.Errorf("%s 引用了尚未声明的链 %s", c.Name, r[i+1])
					}
				}
			}
		}
	}
	seen := map[string]bool{}
	for _, j := range append(append([]Jump{}, rs.Jumps4...), rs.Jumps6...) {
		k := j.Table + j.Parent + strings.Join(j.Spec, " ")
		if seen[k] {
			t.Errorf("重复的跳转 %s", k)
		}
		seen[k] = true
	}
	for _, c := range rs.V4 {
		if c.Name == ChainTCPOut {
			last := strings.Join(c.Rules[len(c.Rules)-1], " ")
			if !strings.Contains(last, "--syn") {
				t.Error("TCP 重定向必须只匹配 SYN")
			}
		}
	}
	if in.Policy.KillSwitch {
		if !declared[ChainGuard] || !declared[ChainGuardPX] {
			t.Error("开启 kill switch 时必须有防护链")
		}
	}
	// 子链中的 RETURN 只回到调用链，所以每个跳转到 egp 子链的规则之后，
	// 必须紧跟一条相同匹配条件的 RETURN，否则被子链放行的流量会继续落到后面的 REJECT。
	for _, c := range rs.V4 {
		for i, r := range c.Rules {
			n := len(r)
			if n >= 2 && r[n-2] == "-j" && strings.HasPrefix(r[n-1], "EGP") {
				want := strings.Join(append(append([]string{}, r[:n-2]...), "-j", "RETURN"), " ")
				if i+1 >= len(c.Rules) || strings.Join(c.Rules[i+1], " ") != want {
					t.Errorf("%s 中跳转到 %s 之后缺少对应的 RETURN", c.Name, r[n-1])
				}
			}
		}
	}
}

func TestWithoutUDPProxy(t *testing.T) {
	rs := Plan(baseInput(), true).WithoutUDPProxy()
	if rs.TProxy {
		t.Error("开机守护不应配置策略路由")
	}
	for _, c := range rs.V4 {
		if c.Name == ChainUDPOut || c.Name == ChainUDPPre {
			t.Errorf("开机守护不应包含 %s", c.Name)
		}
		for _, r := range c.Rules {
			if strings.Contains(strings.Join(r, " "), markArg(baseInput().Settings.MarkTProxy)) {
				t.Errorf("开机守护的 %s 中不应放行 TPROXY 标记", c.Name)
			}
		}
	}
	for _, j := range rs.Jumps4 {
		if j.Table == "mangle" {
			t.Errorf("开机守护不应包含 mangle 跳转 %v", j.Spec)
		}
	}
}

func TestMergeCIDRs(t *testing.T) {
	in := []netip.Prefix{
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("172.31.0.0/20"),
		netip.MustParsePrefix("10.1.2.3/32"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("8.8.8.8/32"),
		netip.MustParsePrefix("8.8.8.8/32"),
	}
	got := MergeCIDRs(in)
	want := []string{"8.8.8.8/32", "10.0.0.0/8", "172.16.0.0/12"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("got %v", got)
		}
	}
}

func TestPortChunks(t *testing.T) {
	var ports []int
	for i := 1; i <= 20; i++ {
		ports = append(ports, i)
	}
	ch := portChunks(append(ports, 3, 0, 70000))
	if len(ch) != 2 || strings.Count(ch[0], ",") != 14 {
		t.Fatalf("got %v", ch)
	}
}

func TestSplitArgsAndSameRule(t *testing.T) {
	a := splitArgs(`-p tcp -m comment --comment "egp" -j EGP_TCP_OUT`)
	j := Jump{Table: "nat", Parent: "OUTPUT", Spec: []string{"-p", "tcp", "-j", ChainTCPOut}}
	if !sameRule(a, j.Args()) {
		t.Fatalf("%q vs %q", a, j.Args())
	}
	if !isEGPJump(a) {
		t.Error("应识别为 egp 跳转")
	}
}
