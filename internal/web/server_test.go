package web

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ipest-info/EgressProxyIp/internal/controller"
	"github.com/ipest-info/EgressProxyIp/internal/passwd"
	"github.com/ipest-info/EgressProxyIp/internal/store"
	"github.com/ipest-info/EgressProxyIp/internal/sysinfo"
)

const testPassword = "test-password"

// newTestServer 以演示模式（不启动 gost、不改防火墙）启动完整的服务。
func newTestServer(t *testing.T, confirm time.Duration) (*httptest.Server, *controller.Controller) {
	t.Helper()
	dir := t.TempDir()
	st, _ := store.New(dir)
	s, _ := st.Load()
	s.Settings.AdminHash, _ = passwd.Hash(testPassword)
	st.Save(s)
	c, err := controller.New(controller.Options{Dir: dir, DryRun: true, ConfirmTimeout: confirm, Log: slog.Default(), Sys: sysinfo.FS{Root: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Stop(context.Background()) })
	ts := httptest.NewServer(New(c, slog.Default(), false).Handler())
	t.Cleanup(ts.Close)
	return ts, c
}

type tc struct {
	t   *testing.T
	ts  *httptest.Server
	cli *http.Client
}

func newClient(t *testing.T, ts *httptest.Server) *tc {
	jar, _ := cookiejar.New(nil)
	return &tc{t: t, ts: ts, cli: &http.Client{Jar: jar}}
}

func (c *tc) req(method, path string, body any, hdr map[string]string) (int, map[string]any) {
	c.t.Helper()
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	r, _ := http.NewRequest(method, c.ts.URL+path, bytes.NewReader(b))
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	resp, err := c.cli.Do(r)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (c *tc) login() {
	c.t.Helper()
	if code, out := c.req("POST", "/api/login", map[string]string{"username": "admin", "password": testPassword}, nil); code != 200 {
		c.t.Fatalf("登录失败: %d %v", code, out)
	}
}

func TestAuthRequired(t *testing.T) {
	ts, _ := newTestServer(t, time.Minute)
	c := newClient(t, ts)
	if code, _ := c.req("GET", "/api/status", nil, nil); code != 401 {
		t.Fatalf("未登录应返回 401，得到 %d", code)
	}
	if code, _ := c.req("GET", "/", nil, nil); code != 200 {
		t.Fatalf("首页应可访问，得到 %d", code)
	}
}

func TestLoginLockout(t *testing.T) {
	ts, _ := newTestServer(t, time.Minute)
	c := newClient(t, ts)
	for i := 0; i < maxFailures; i++ {
		if code, _ := c.req("POST", "/api/login", map[string]string{"username": "admin", "password": "wrong"}, nil); code != 401 {
			t.Fatalf("密码错误应返回 401，得到 %d", code)
		}
	}
	if code, _ := c.req("POST", "/api/login", map[string]string{"username": "admin", "password": testPassword}, nil); code != 429 {
		t.Fatalf("多次失败后应被暂时锁定，得到 %d", code)
	}
}

func TestCSRF(t *testing.T) {
	ts, _ := newTestServer(t, time.Minute)
	c := newClient(t, ts)
	c.login()
	if code, _ := c.req("PUT", "/api/enabled", map[string]bool{"enabled": true}, map[string]string{"Origin": "https://evil.example"}); code != 403 {
		t.Fatalf("跨站请求应被拒绝，得到 %d", code)
	}
	if code, _ := c.req("PUT", "/api/enabled", map[string]bool{"enabled": true}, map[string]string{"Sec-Fetch-Site": "cross-site"}); code != 403 {
		t.Fatalf("跨站请求应被拒绝，得到 %d", code)
	}
	// 表单提交（非 JSON）也必须被拒绝。
	r, _ := http.NewRequest("PUT", ts.URL+"/api/enabled", strings.NewReader("enabled=true"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, _ := c.cli.Do(r)
	if resp.StatusCode != 403 {
		t.Fatalf("非 JSON 写请求应被拒绝，得到 %d", resp.StatusCode)
	}
	if code, _ := c.req("PUT", "/api/enabled", map[string]bool{"enabled": true}, map[string]string{"Sec-Fetch-Site": "same-origin"}); code != 200 {
		t.Fatalf("同源请求应被允许，得到 %d", code)
	}
}

func TestPasswordNeverReturned(t *testing.T) {
	ts, _ := newTestServer(t, time.Minute)
	c := newClient(t, ts)
	c.login()
	c.req("POST", "/api/proxies/import", map[string]string{"text": "socks5://user:SuperSecret@203.0.113.20:1080"}, nil)
	r, _ := http.NewRequest("GET", ts.URL+"/api/state", nil)
	resp, _ := c.cli.Do(r)
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	if strings.Contains(buf.String(), "SuperSecret") || !strings.Contains(buf.String(), `"hasPassword":true`) {
		t.Fatalf("状态接口不应返回代理密码: %s", buf.String())
	}
	r, _ = http.NewRequest("GET", ts.URL+"/api/preview", nil)
	resp, _ = c.cli.Do(r)
	buf.Reset()
	buf.ReadFrom(resp.Body)
	if strings.Contains(buf.String(), "SuperSecret") {
		t.Fatal("预览接口不应返回代理密码")
	}
}

func TestApplyConfirmAndTimeout(t *testing.T) {
	ts, ctl := newTestServer(t, 300*time.Millisecond)
	c := newClient(t, ts)
	c.login()
	c.req("POST", "/api/proxies/import", map[string]string{"text": "203.0.113.20:1080"}, nil)
	c.req("PUT", "/api/enabled", map[string]bool{"enabled": true}, nil)

	// 超时未确认 → 自动回滚，已生效配置仍为“未启用”。
	code, out := c.req("POST", "/api/apply", map[string]bool{"skipVerify": false}, nil)
	if code != 200 || out["nonce"] == "" {
		t.Fatalf("应用失败: %d %v", code, out)
	}
	time.Sleep(600 * time.Millisecond)
	if s := ctl.Status(context.Background()); s.Pending != nil || s.Enabled {
		t.Fatalf("超时后应回滚: %+v", s)
	}

	// 及时确认 → 生效。
	_, out = c.req("POST", "/api/apply", map[string]bool{"skipVerify": false}, nil)
	if code, o := c.req("POST", "/api/apply/confirm", map[string]any{"nonce": out["nonce"]}, nil); code != 200 {
		t.Fatalf("确认失败: %d %v", code, o)
	}
	time.Sleep(400 * time.Millisecond)
	s := ctl.Status(context.Background())
	if !s.Enabled || s.Dirty || s.Pending != nil {
		t.Fatalf("确认后应生效且无未应用修改: %+v", s)
	}
	if code, _ := c.req("POST", "/api/apply/confirm", map[string]any{"nonce": "bogus"}, nil); code != 409 {
		t.Fatal("没有待确认应用时确认应失败")
	}
}

func TestChangePasswordInvalidatesSessions(t *testing.T) {
	ts, _ := newTestServer(t, time.Minute)
	c := newClient(t, ts)
	c.login()
	if code, _ := c.req("POST", "/api/password", map[string]string{"old": "wrong", "new": "another-password"}, nil); code != 400 {
		t.Fatal("原密码错误时应拒绝")
	}
	if code, _ := c.req("POST", "/api/password", map[string]string{"old": testPassword, "new": "short"}, nil); code != 400 {
		t.Fatal("新密码过短时应拒绝")
	}
	if code, _ := c.req("POST", "/api/password", map[string]string{"old": testPassword, "new": "another-password"}, nil); code != 200 {
		t.Fatal("修改密码失败")
	}
	if code, _ := c.req("GET", "/api/status", nil, nil); code != 401 {
		t.Fatal("修改密码后旧会话应失效")
	}
	if code, _ := c.req("POST", "/api/login", map[string]string{"username": "admin", "password": "another-password"}, nil); code != 200 {
		t.Fatal("新密码应能登录")
	}
}
