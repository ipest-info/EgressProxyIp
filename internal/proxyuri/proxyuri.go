// Package proxyuri 解析代理服务商常见格式的 SOCKS5 代理定义。
package proxyuri

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/ipest-info/EgressProxyIp/internal/model"
)

// Parse 接受以下任一格式：
//
//	socks5://user:pass@host:port[#名称]   （也接受 socks5h://、socks://）
//	host:port:user:pass
//	user:pass@host:port
//	host:port
//
// IPv6 地址必须使用 URL 格式并加方括号。
func Parse(line string) (model.Proxy, error) {
	s := strings.TrimSpace(line)
	if s == "" {
		return model.Proxy{}, errors.New("空行")
	}
	var name string
	if i := strings.LastIndex(s, "#"); i >= 0 {
		name = strings.TrimSpace(s[i+1:])
		if n, err := url.PathUnescape(name); err == nil {
			name = n
		}
		s = strings.TrimSpace(s[:i])
	}
	var p model.Proxy
	var err error
	if strings.Contains(s, "://") {
		p, err = parseURL(s)
	} else if strings.Contains(s, "@") {
		p, err = parseURL("socks5://" + s)
	} else {
		p, err = parseColon(s)
	}
	if err != nil {
		return model.Proxy{}, err
	}
	p.Name = name
	if p.Name == "" {
		p.Name = p.Addr()
	}
	p.Enabled = true
	p.UDP = model.UDPUnknown
	return p, model.ValidateProxy(p)
}

func parseURL(s string) (model.Proxy, error) {
	u, err := url.Parse(s)
	if err != nil {
		return model.Proxy{}, fmt.Errorf("无法解析 URL: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h", "socks":
	default:
		return model.Proxy{}, fmt.Errorf("不支持的协议 %q，仅支持 SOCKS5", u.Scheme)
	}
	host := u.Hostname()
	portStr := u.Port()
	if host == "" || portStr == "" {
		return model.Proxy{}, errors.New("缺少主机或端口")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return model.Proxy{}, fmt.Errorf("端口 %q 无效", portStr)
	}
	p := model.Proxy{Host: host, Port: port}
	if u.User != nil {
		p.Username = u.User.Username()
		p.Password, _ = u.User.Password()
	}
	return p, nil
}

func parseColon(s string) (model.Proxy, error) {
	parts := strings.Split(s, ":")
	if len(parts) > 4 {
		// host:port:user:pass 且密码本身含有 ':'
		parts = append(parts[:3], strings.Join(parts[3:], ":"))
	}
	if len(parts) != 2 && len(parts) != 4 {
		return model.Proxy{}, errors.New("格式应为 host:port 或 host:port:user:pass")
	}
	host := parts[0]
	if net.ParseIP(host) == nil && strings.ContainsAny(host, "[]") {
		return model.Proxy{}, fmt.Errorf("主机 %q 无效（IPv6 请使用 socks5://[addr]:port 格式）", host)
	}
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		return model.Proxy{}, fmt.Errorf("端口 %q 无效", parts[1])
	}
	p := model.Proxy{Host: host, Port: port}
	if len(parts) == 4 {
		p.Username, p.Password = parts[2], parts[3]
	}
	return p, nil
}

// LineError 描述无法导入的一行。
type LineError struct {
	Line  int    `json:"line"`
	Text  string `json:"text"`
	Error string `json:"error"`
}

// ParseBatch 按行解析代理，每行一个。空行以及以 "//" 或 ";" 开头的行会被跳过。
func ParseBatch(text string) ([]model.Proxy, []LineError) {
	var out []model.Proxy
	var errs []LineError
	for i, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "//") || strings.HasPrefix(t, ";") {
			continue
		}
		p, err := Parse(t)
		if err != nil {
			errs = append(errs, LineError{Line: i + 1, Text: redact(t), Error: err.Error()})
			continue
		}
		out = append(out, p)
	}
	return out, errs
}

// redact 在回显某一行之前隐藏疑似密码的内容。
func redact(s string) string {
	if i := strings.Index(s, "@"); i >= 0 {
		if j := strings.LastIndex(s[:i], ":"); j >= 0 && j > strings.Index(s, "://")+2 {
			return s[:j+1] + "****" + s[i:]
		}
	}
	parts := strings.Split(s, ":")
	if len(parts) >= 4 {
		return strings.Join(parts[:3], ":") + ":****"
	}
	return s
}
