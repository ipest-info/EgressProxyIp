package socks5_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ipest-info/EgressProxyIp/internal/socks5"
	"github.com/ipest-info/EgressProxyIp/internal/socks5/socks5test"
	"github.com/ipest-info/EgressProxyIp/internal/stun"
)

func startServer(t *testing.T, s *socks5test.Server) {
	t.Helper()
	if err := s.Start(""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
}

func echoTCP(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return l.Addr().String()
}

// stunServer 回复请求来源地址的 STUN 服务。
func stunServer(t *testing.T) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 20 {
				continue
			}
			pc.WriteTo(stun.Response([12]byte(buf[8:20]), from.(*net.UDPAddr).AddrPort()), from)
		}
	}()
	return pc.LocalAddr().String()
}

func TestConnectWithAuth(t *testing.T) {
	srv := &socks5test.Server{Username: "u", Password: "p"}
	startServer(t, srv)
	target := echoTCP(t)
	c := &socks5.Client{Server: srv.Addr(), Username: "u", Password: "p"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, tm, err := c.Connect(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte("ping"))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("经代理回显失败: %q %v", buf, err)
	}
	if tm.Connect <= 0 || tm.Handshake <= 0 || tm.Request <= 0 {
		t.Errorf("耗时统计缺失: %+v", tm)
	}
}

func TestAuthFailure(t *testing.T) {
	srv := &socks5test.Server{Username: "u", Password: "p"}
	startServer(t, srv)
	c := &socks5.Client{Server: srv.Addr(), Username: "u", Password: "wrong"}
	_, _, err := c.Connect(context.Background(), "127.0.0.1:1")
	if !errors.Is(err, socks5.ErrAuth) {
		t.Fatalf("应返回认证失败，得到 %v", err)
	}
	c2 := &socks5.Client{Server: srv.Addr()}
	if _, _, err := c2.Connect(context.Background(), "127.0.0.1:1"); err == nil || !strings.Contains(err.Error(), "认证") {
		t.Fatalf("未提供账号时应提示需要认证，得到 %v", err)
	}
}

func TestConnectRefused(t *testing.T) {
	srv := &socks5test.Server{}
	startServer(t, srv)
	c := &socks5.Client{Server: srv.Addr()}
	_, _, err := c.Connect(context.Background(), "127.0.0.1:1")
	var re *socks5.ReplyError
	if !errors.As(err, &re) || re.Code != 5 {
		t.Fatalf("应返回连接被拒绝，得到 %v", err)
	}
}

func TestUDPAssociate(t *testing.T) {
	srv := &socks5test.Server{Username: "u", Password: "p"}
	startServer(t, srv)
	stunAddr := stunServer(t)
	c := &socks5.Client{Server: srv.Addr(), Username: "u", Password: "p"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := c.AssociateUDP(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	req, tid := stun.Request()
	resp, _, err := s.Exchange(ctx, stunAddr, req)
	if err != nil {
		t.Fatal(err)
	}
	ap, err := stun.Parse(resp, tid)
	if err != nil || ap.Addr() != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("STUN 映射地址错误: %v %v", ap, err)
	}
}

func TestUDPZeroBindStrict(t *testing.T) {
	srv := &socks5test.Server{ReportZeroBind: true}
	startServer(t, srv)
	c := &socks5.Client{Server: srv.Addr()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := c.AssociateUDP(ctx, true)
	if err == nil {
		s.Close()
		t.Fatal("中继地址为 0.0.0.0 时严格模式应失败（与 gost 行为一致）")
	}
	if s == nil || !strings.HasPrefix(s.Reported, "0.0.0.0:") {
		t.Fatalf("应返回服务器报告的地址，得到 %+v", s)
	}
	s2, err := c.AssociateUDP(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if !s2.Substituted || !strings.HasPrefix(s2.Relay, "127.0.0.1:") {
		t.Fatalf("宽松模式应替换为服务器 IP，得到 %+v", s2)
	}
}

func TestUDPNotSupported(t *testing.T) {
	srv := &socks5test.Server{NoUDP: true}
	startServer(t, srv)
	c := &socks5.Client{Server: srv.Addr()}
	if _, err := c.AssociateUDP(context.Background(), true); err == nil || !strings.Contains(err.Error(), "不支持") {
		t.Fatalf("应提示不支持 UDP，得到 %v", err)
	}
}
