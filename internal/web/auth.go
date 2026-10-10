package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ipest-info/EgressProxyIp/internal/passwd"
)

const (
	cookieName     = "egp_session"
	sessionTTL     = 12 * time.Hour
	maxFailures    = 5
	lockoutWindow  = 5 * time.Minute
	minPasswordLen = 8
)

type session struct {
	user    string
	expires time.Time
}

// auth 管理会话与登录限速。
type auth struct {
	mu       sync.Mutex
	sessions map[string]session
	failures map[string][]time.Time
	// bcrypt 计算量很大，限制并发防止有人用登录请求耗尽 CPU。
	sem chan struct{}
}

func newAuth() *auth {
	return &auth{sessions: map[string]session{}, failures: map[string][]time.Time{}, sem: make(chan struct{}, 2)}
}

func randomToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// locked 判断该来源是否因多次失败被暂时锁定。
func (a *auth) locked(ip string, now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	var recent []time.Time
	for _, t := range a.failures[ip] {
		if now.Sub(t) < lockoutWindow {
			recent = append(recent, t)
		}
	}
	a.failures[ip] = recent
	return len(recent) >= maxFailures
}

func (a *auth) fail(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.failures[ip] = append(a.failures[ip], time.Now())
}

// check 校验用户名密码。
func (a *auth) check(user, pw, wantUser, hash string) bool {
	a.sem <- struct{}{}
	defer func() { <-a.sem }()
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(wantUser)) == 1
	pwOK := passwd.Check(hash, pw)
	return userOK && pwOK
}

func (a *auth) create(user string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	for k, s := range a.sessions {
		if now.After(s.expires) {
			delete(a.sessions, k)
		}
	}
	tok := randomToken()
	a.sessions[tok] = session{user: user, expires: now.Add(sessionTTL)}
	return tok
}

func (a *auth) lookup(tok string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[tok]
	if !ok || time.Now().After(s.expires) {
		delete(a.sessions, tok)
		return "", false
	}
	return s.user, true
}

func (a *auth) destroy(tok string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.sessions, tok)
}

// destroyAll 使所有会话失效（修改密码后）。
func (a *auth) destroyAll() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sessions = map[string]session{}
}

// sameOrigin 防 CSRF：写操作必须是 JSON 请求，且来自同源页面。
// Go 1.24 尚无 http.CrossOriginProtection，这里按同样的思路自行实现。
func sameOrigin(r *http.Request) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return false
	}
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return true
	case "":
	default:
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // 非浏览器客户端（curl 等）
	}
	o := strings.TrimPrefix(strings.TrimPrefix(origin, "https://"), "http://")
	return o == r.Host
}
