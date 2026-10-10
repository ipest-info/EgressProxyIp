package model

import (
	"strings"
	"testing"
)

func validState() State {
	s := Default()
	s.Proxies = []Proxy{{ID: "a", Name: "a", Host: "1.2.3.4", Port: 1080, Enabled: true}}
	return s
}

func TestDefaultIsValid(t *testing.T) {
	s := Default()
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if !s.Policy.KillSwitch || !s.Policy.BlockIPv6 || s.Settings.Listen != "127.0.0.1:8088" {
		t.Error("默认值应偏向安全：开启 kill switch、阻断 IPv6、WebUI 只监听本机")
	}
}

func TestValidate(t *testing.T) {
	cases := map[string]func(*State){
		"启用但没有代理":   func(s *State) { s.Enabled = true; s.Proxies = nil },
		"固定模式未选择代理": func(s *State) { s.Enabled = true; s.Policy.Mode = ModeFixed },
		"重复的代理 ID":  func(s *State) { s.Proxies = append(s.Proxies, s.Proxies[0]) },
		"无效网段":      func(s *State) { s.Bypass.CIDRs = []string{"1.2.3.0/40"} },
		"IPv6 网段":   func(s *State) { s.Bypass.CIDRs = []string{"2001:db8::/32"} },
		"无效域名":      func(s *State) { s.Bypass.Domains = []string{"bad domain"} },
		"直连组为 root": func(s *State) { s.Bypass.DirectGroup = "root" },
		"标记重复":      func(s *State) { s.Settings.MarkDirect = s.Settings.MarkProxy },
		"标记不是单个比特位": func(s *State) { s.Settings.MarkSelf = 3 },
		"端口冲突":      func(s *State) { s.Settings.APIPort = s.Settings.RedirPort },
		"路由表与系统表冲突": func(s *State) { s.Settings.RouteTable = 254 },
		"代理端口越界":    func(s *State) { s.Proxies[0].Port = 70000 },
		"代理是回环地址":   func(s *State) { s.Proxies[0].Host = "127.0.0.1" },
		"健康检查间隔过短":  func(s *State) { s.Policy.HealthInterval = 1 },
		"未知 UDP 模式": func(s *State) { s.Policy.UDPMode = "x" },
	}
	for name, mut := range cases {
		s := validState()
		mut(&s)
		if err := s.Validate(); err == nil {
			t.Errorf("%s: 应校验失败", name)
		}
	}
	s := validState()
	s.Enabled = true
	if err := s.Validate(); err != nil {
		t.Errorf("合法状态校验失败: %v", err)
	}
}

func TestParseCIDR(t *testing.T) {
	p, err := ParseCIDR(" 10.1.2.3 ")
	if err != nil || p.String() != "10.1.2.3/32" {
		t.Fatalf("%v %v", p, err)
	}
	p, err = ParseCIDR("10.1.2.3/8")
	if err != nil || p.String() != "10.0.0.0/8" {
		t.Fatalf("网段应规整为网络地址: %v %v", p, err)
	}
}

func TestFillDefaults(t *testing.T) {
	var s State
	s.FillDefaults()
	if err := s.Validate(); err != nil && !strings.Contains(err.Error(), "WebUI") {
		t.Fatalf("补全默认值后应合法: %v", err)
	}
	if s.Settings.RedirPort == 0 || s.Policy.Mode == "" || s.Bypass.CIDRs == nil {
		t.Error("零值未被补全")
	}
}
