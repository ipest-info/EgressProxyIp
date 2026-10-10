package proxyuri

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	cases := []struct {
		in               string
		host             string
		port             int
		user, pass, name string
	}{
		{"socks5://u:p@1.2.3.4:1080", "1.2.3.4", 1080, "u", "p", "1.2.3.4:1080"},
		{"socks5h://u:p%40x@proxy.example.com:2080#香港-1", "proxy.example.com", 2080, "u", "p@x", "香港-1"},
		{"socks://[2001:db8::1]:1080", "2001:db8::1", 1080, "", "", "[2001:db8::1]:1080"},
		{"1.2.3.4:1080:user:pa:ss", "1.2.3.4", 1080, "user", "pa:ss", "1.2.3.4:1080"},
		{"user:pass@1.2.3.4:1080", "1.2.3.4", 1080, "user", "pass", "1.2.3.4:1080"},
		{"  1.2.3.4:1080  ", "1.2.3.4", 1080, "", "", "1.2.3.4:1080"},
	}
	for _, c := range cases {
		p, err := Parse(c.in)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if p.Host != c.host || p.Port != c.port || p.Username != c.user || p.Password != c.pass || p.Name != c.name || !p.Enabled {
			t.Errorf("%q: 得到 %+v", c.in, p)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{"", "http://1.2.3.4:80", "1.2.3.4", "1.2.3.4:99999", "1.2.3.4:1080:user", "127.0.0.1:1080", "socks5://1.2.3.4"} {
		if _, err := Parse(in); err == nil {
			t.Errorf("%q 应解析失败", in)
		}
	}
}

func TestParseBatchRedacts(t *testing.T) {
	ps, errs := ParseBatch("// 注释\n\nsocks5://a:b@1.1.1.1:1\nbad:line:secret\n1.2.3.4:x:u:topsecret\n")
	if len(ps) != 1 || len(errs) != 2 {
		t.Fatalf("ps=%v errs=%v", ps, errs)
	}
	for _, e := range errs {
		if strings.Contains(e.Text, "topsecret") {
			t.Errorf("错误回显中泄露了密码: %q", e.Text)
		}
	}
	if errs[1].Line != 5 {
		t.Errorf("行号错误: %d", errs[1].Line)
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"socks5://u:p@1.2.3.4:1080", "1.2.3.4:1080:u:p", "u:p@h:1", "[::1]:1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, err := Parse(s)
		if err == nil && (p.Port < 1 || p.Port > 65535 || p.Host == "") {
			t.Fatalf("解析出无效代理: %+v", p)
		}
	})
}
