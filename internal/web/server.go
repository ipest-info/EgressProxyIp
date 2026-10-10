// Package web 提供 egp 的 WebUI 与 JSON API。
package web

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ipest-info/EgressProxyIp/internal/controller"
	"github.com/ipest-info/EgressProxyIp/internal/model"
	"github.com/ipest-info/EgressProxyIp/internal/passwd"
)

//go:embed static
var staticFS embed.FS

// Server 是 HTTP 服务。
type Server struct {
	C      *controller.Controller
	Log    *slog.Logger
	Secure bool // 是否通过 HTTPS 提供服务（决定 Cookie 的 Secure 属性）
	auth   *auth
}

// New 创建服务。
func New(c *controller.Controller, log *slog.Logger, secure bool) *Server {
	return &Server{C: c, Log: log, Secure: secure, auth: newAuth()}
}

// Handler 返回完整的路由。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(staticFS, "static")
	files := http.FileServer(http.FS(sub))
	mux.Handle("GET /", files)

	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("POST /api/logout", s.logout)
	mux.HandleFunc("GET /api/session", s.authed(s.sessionInfo))

	mux.HandleFunc("GET /api/status", s.authed(s.status))
	mux.HandleFunc("POST /api/egress-check", s.authed(s.egressCheck))
	mux.HandleFunc("GET /api/state", s.authed(s.getState))
	mux.HandleFunc("GET /api/preview", s.authed(s.preview))
	mux.HandleFunc("GET /api/logs", s.authed(s.logs))

	mux.HandleFunc("POST /api/proxies", s.authed(s.addProxy))
	mux.HandleFunc("POST /api/proxies/import", s.authed(s.importProxies))
	mux.HandleFunc("POST /api/proxies/reorder", s.authed(s.reorder))
	mux.HandleFunc("PUT /api/proxies/{id}", s.authed(s.updateProxy))
	mux.HandleFunc("DELETE /api/proxies/{id}", s.authed(s.deleteProxy))
	mux.HandleFunc("POST /api/proxies/{id}/test", s.authed(s.testProxy))

	mux.HandleFunc("PUT /api/policy", s.authed(s.setPolicy))
	mux.HandleFunc("PUT /api/bypass", s.authed(s.setBypass))
	mux.HandleFunc("PUT /api/settings", s.authed(s.setSettings))
	mux.HandleFunc("PUT /api/enabled", s.authed(s.setEnabled))
	mux.HandleFunc("POST /api/password", s.authed(s.changePassword))

	mux.HandleFunc("POST /api/apply", s.authed(s.apply))
	mux.HandleFunc("POST /api/apply/confirm", s.authed(s.confirm))
	mux.HandleFunc("POST /api/apply/revert", s.authed(s.revert))
	return securityHeaders(mux)
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		h.ServeHTTP(w, r)
	})
}

type apiError struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, apiError{Error: err.Error()})
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New("请求格式错误: " + err.Error())
	}
	return nil
}

// authed 要求已登录；写操作还要求同源 JSON 请求（防 CSRF）。
func (s *Server) authed(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil {
			fail(w, http.StatusUnauthorized, errors.New("请先登录"))
			return
		}
		if _, ok := s.auth.lookup(c.Value); !ok {
			fail(w, http.StatusUnauthorized, errors.New("会话已过期，请重新登录"))
			return
		}
		if r.Method != http.MethodGet && !sameOrigin(r) {
			fail(w, http.StatusForbidden, errors.New("拒绝跨站请求"))
			return
		}
		h(w, r)
	}
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		fail(w, http.StatusForbidden, errors.New("拒绝跨站请求"))
		return
	}
	ip := clientIP(r)
	if s.auth.locked(ip, time.Now()) {
		fail(w, http.StatusTooManyRequests, errors.New("登录失败次数过多，请 5 分钟后再试"))
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	st := s.C.State().Settings
	if !s.auth.check(req.Username, req.Password, st.AdminUser, st.AdminHash) {
		s.auth.fail(ip)
		s.C.Audit.Add("admin", "登录失败", "来源 "+ip, false)
		s.Log.Warn("登录失败", "来源", ip, "用户名", req.Username)
		fail(w, http.StatusUnauthorized, errors.New("用户名或密码错误"))
		return
	}
	tok := s.auth.create(req.Username)
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: tok, Path: "/", HttpOnly: true, Secure: s.Secure,
		SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds()),
	})
	s.C.Audit.Add("admin", "登录", "来源 "+ip, true)
	writeJSON(w, http.StatusOK, map[string]string{"user": req.Username})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		s.auth.destroy(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.Secure, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) sessionInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"user": s.C.State().Settings.AdminUser})
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.C.Status(r.Context()))
}

func (s *Server) egressCheck(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, s.C.CheckEgress(ctx))
}

// proxyView 是返回给前端的代理信息，密码只写不读。
type proxyView struct {
	model.Proxy
	Password    string `json:"password,omitempty"`
	HasPassword bool   `json:"hasPassword"`
}

type stateView struct {
	Enabled  bool         `json:"enabled"`
	Proxies  []proxyView  `json:"proxies"`
	Policy   model.Policy `json:"policy"`
	Bypass   model.Bypass `json:"bypass"`
	Settings any          `json:"settings"`
}

func (s *Server) getState(w http.ResponseWriter, r *http.Request) {
	st := s.C.State()
	v := stateView{Enabled: st.Enabled, Policy: st.Policy, Bypass: st.Bypass, Proxies: []proxyView{}}
	for _, p := range st.Proxies {
		pv := proxyView{Proxy: p, HasPassword: p.Password != ""}
		pv.Proxy.Password = ""
		v.Proxies = append(v.Proxies, pv)
	}
	set := st.Settings
	v.Settings = controller.SettingsPatch{
		Listen: set.Listen, GostBin: set.GostBin, RedirPort: set.RedirPort, TProxyPort: set.TProxyPort,
		APIPort: set.APIPort, MetricsPort: set.MetricsPort, HealthURL: set.HealthURL, EchoURLs: set.EchoURLs, STUNServer: set.STUNServer,
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) preview(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.C.Preview(r.Context()))
}

func (s *Server) logs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"audit": s.C.Audit.Recent(), "engine": s.C.EngineLogs()})
}

func (s *Server) addProxy(w http.ResponseWriter, r *http.Request) {
	var p controller.ProxyPatch
	if err := readJSON(r, &p); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	px := model.Proxy{Name: strings.TrimSpace(p.Name), Host: strings.TrimSpace(p.Host), Port: p.Port, Username: p.Username, Enabled: true}
	if p.Password != nil {
		px.Password = *p.Password
	}
	added, err := s.C.AddProxies([]model.Proxy{px})
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": added[0].ID})
}

func (s *Server) importProxies(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Text string `json:"text"`
	}
	if err := readJSON(r, &req); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	n, lineErrs, err := s.C.ImportProxies(req.Text)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"added": n, "errors": lineErrs})
}

func (s *Server) reorder(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := readJSON(r, &req); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	if err := s.C.ReorderProxies(req.IDs); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) updateProxy(w http.ResponseWriter, r *http.Request) {
	var p controller.ProxyPatch
	if err := readJSON(r, &p); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	if err := s.C.UpdateProxy(r.PathValue("id"), p); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) deleteProxy(w http.ResponseWriter, r *http.Request) {
	if err := s.C.DeleteProxy(r.PathValue("id")); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) testProxy(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	res, err := s.C.TestProxy(ctx, r.PathValue("id"))
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) setPolicy(w http.ResponseWriter, r *http.Request) {
	var p model.Policy
	if err := readJSON(r, &p); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	if err := s.C.SetPolicy(p); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) setBypass(w http.ResponseWriter, r *http.Request) {
	var b model.Bypass
	if err := readJSON(r, &b); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	if err := s.C.SetBypass(b); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) setSettings(w http.ResponseWriter, r *http.Request) {
	var p controller.SettingsPatch
	if err := readJSON(r, &p); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	if err := s.C.SetSettings(p); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) setEnabled(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := readJSON(r, &req); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	if err := s.C.SetEnabled(req.Enabled); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if err := readJSON(r, &req); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	st := s.C.State().Settings
	if !s.auth.check(st.AdminUser, req.Old, st.AdminUser, st.AdminHash) {
		fail(w, http.StatusBadRequest, errors.New("原密码错误"))
		return
	}
	if len(req.New) < minPasswordLen {
		fail(w, http.StatusBadRequest, errors.New("新密码至少 8 位"))
		return
	}
	h, err := passwd.Hash(req.New)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.C.SetPasswordHash(h); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	s.auth.destroyAll()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) apply(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SkipVerify bool `json:"skipVerify"`
	}
	if err := readJSON(r, &req); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	res, err := s.C.Apply(ctx, req.SkipVerify)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "result": res})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) confirm(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Nonce string `json:"nonce"`
	}
	if err := readJSON(r, &req); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	if err := s.C.Confirm(req.Nonce); err != nil {
		fail(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) revert(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Nonce string `json:"nonce"`
	}
	if err := readJSON(r, &req); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	if err := s.C.Revert(req.Nonce); err != nil {
		fail(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
