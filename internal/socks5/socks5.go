// Package socks5 是一个小型 SOCKS5 客户端（RFC 1928 + RFC 1929），
// 用于脱离转发引擎独立测试上游代理。
package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"
)

const (
	version       = 5
	methodNone    = 0x00
	methodUserPwd = 0x02
	methodNoAccep = 0xFF
	cmdConnect    = 0x01
	cmdUDPAssoc   = 0x03
	atypIPv4      = 0x01
	atypDomain    = 0x03
	atypIPv6      = 0x04
)

// DialFunc 建立到代理服务器的连接。
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Client 与一个 SOCKS5 服务器通信。
type Client struct {
	Server   string // host:port
	Username string
	Password string
	Dial     DialFunc // 到服务器的 TCP 与 UDP 套接字都用它创建
}

// Timings 记录建立 CONNECT 各阶段的耗时。
type Timings struct {
	Connect   time.Duration // 与代理建立 TCP 连接
	Handshake time.Duration // 方法协商 + 认证
	Request   time.Duration // 发出 CONNECT 请求到收到应答
}

var replyErrors = map[byte]string{
	1: "SOCKS 服务器一般性故障",
	2: "规则不允许该连接",
	3: "网络不可达",
	4: "主机不可达",
	5: "连接被拒绝",
	6: "TTL 超时",
	7: "不支持的命令",
	8: "不支持的地址类型",
}

// ReplyError 表示服务器返回的非成功应答码。
type ReplyError struct{ Code byte }

func (e *ReplyError) Error() string {
	if s, ok := replyErrors[e.Code]; ok {
		return "socks5: " + s
	}
	return fmt.Sprintf("socks5: 应答码 %d", e.Code)
}

// ErrAuth 表示服务器拒绝了用户名密码。
var ErrAuth = errors.New("socks5: 认证失败（用户名或密码错误）")

func (c *Client) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if c.Dial != nil {
		return c.Dial(ctx, network, addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// Connect 打开到 target（host:port）的隧道，并返回各阶段耗时。
func (c *Client) Connect(ctx context.Context, target string) (net.Conn, Timings, error) {
	var t Timings
	start := time.Now()
	conn, err := c.dial(ctx, "tcp", c.Server)
	if err != nil {
		return nil, t, fmt.Errorf("连接代理服务器失败: %w", err)
	}
	t.Connect = time.Since(start)
	stop := watch(ctx, conn)
	defer stop()

	start = time.Now()
	if err := c.handshake(conn); err != nil {
		conn.Close()
		return nil, t, err
	}
	t.Handshake = time.Since(start)

	start = time.Now()
	if _, err := c.request(conn, cmdConnect, target); err != nil {
		conn.Close()
		return nil, t, err
	}
	t.Request = time.Since(start)
	return conn, t, nil
}

// DialContext 满足 http.Transport 需要的函数签名。
func (c *Client) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, _, err := c.Connect(ctx, addr)
	return conn, err
}

// watch 在建立连接期间把 context 的截止时间应用到 conn 上。
func watch(ctx context.Context, conn net.Conn) func() {
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			conn.SetDeadline(time.Unix(1, 0))
		case <-done:
		}
	}()
	return func() {
		close(done)
		conn.SetDeadline(time.Time{})
	}
}

func (c *Client) handshake(conn net.Conn) error {
	methods := []byte{methodNone}
	if c.Username != "" {
		methods = []byte{methodUserPwd, methodNone}
	}
	if _, err := conn.Write(append([]byte{version, byte(len(methods))}, methods...)); err != nil {
		return fmt.Errorf("socks5 握手失败: %w", err)
	}
	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return fmt.Errorf("socks5 握手失败（服务器不是 SOCKS5？）: %w", err)
	}
	if resp[0] != version {
		return fmt.Errorf("socks5 握手失败: 服务器返回版本 %d", resp[0])
	}
	switch resp[1] {
	case methodNone:
		return nil
	case methodUserPwd:
		if c.Username == "" {
			return errors.New("socks5: 服务器要求用户名密码认证")
		}
		req := []byte{1, byte(len(c.Username))}
		req = append(req, c.Username...)
		req = append(req, byte(len(c.Password)))
		req = append(req, c.Password...)
		if _, err := conn.Write(req); err != nil {
			return err
		}
		if _, err := io.ReadFull(conn, resp[:]); err != nil {
			return fmt.Errorf("socks5 认证失败: %w", err)
		}
		if resp[1] != 0 {
			return ErrAuth
		}
		return nil
	case methodNoAccep:
		return errors.New("socks5: 服务器不接受任何认证方式（是否需要用户名密码？）")
	default:
		return fmt.Errorf("socks5: 服务器选择了不支持的认证方式 0x%02x", resp[1])
	}
}

// request 发送命令，并返回应答中的绑定地址。
func (c *Client) request(conn net.Conn, cmd byte, target string) (string, error) {
	addr, err := encodeAddr(target)
	if err != nil {
		return "", err
	}
	if _, err := conn.Write(append([]byte{version, cmd, 0}, addr...)); err != nil {
		return "", err
	}
	var hdr [3]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return "", fmt.Errorf("socks5 读取应答失败: %w", err)
	}
	if hdr[1] != 0 {
		return "", &ReplyError{Code: hdr[1]}
	}
	return readAddr(conn)
}

func encodeAddr(hostport string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("端口 %q 无效", portStr)
	}
	var b []byte
	if a, err := netip.ParseAddr(host); err == nil {
		if a.Is4() {
			b = append([]byte{atypIPv4}, a.AsSlice()...)
		} else {
			b = append([]byte{atypIPv6}, a.AsSlice()...)
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("主机名过长")
		}
		b = append([]byte{atypDomain, byte(len(host))}, host...)
	}
	return binary.BigEndian.AppendUint16(b, uint16(port)), nil
}

func readAddr(r io.Reader) (string, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return "", err
	}
	var host string
	switch atyp[0] {
	case atypIPv4, atypIPv6:
		n := 4
		if atyp[0] == atypIPv6 {
			n = 16
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		a, _ := netip.AddrFromSlice(b)
		host = a.String()
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = string(b)
	default:
		return "", fmt.Errorf("socks5: 未知地址类型 %d", atyp[0])
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(p[:])))), nil
}

// UDPSession 表示已建立的 UDP ASSOCIATE 关联。
type UDPSession struct {
	ctrl net.Conn
	pc   net.Conn
	// Relay 是数据报实际发往的地址。
	Relay string
	// Reported 是服务器原样返回的 BND.ADDR:BND.PORT。
	Reported string
	// Substituted 为 true 表示 Reported 不可用（未指定地址，或与服务器不同的私网地址），
	// 已改用服务器自身的 IP。
	Substituted bool
}

// AssociateUDP 执行 UDP ASSOCIATE。strict 为 true 时原样使用服务器返回的中继地址
// （与 gost 的行为一致）；否则把不可用的地址替换为代理服务器的 IP。
func (c *Client) AssociateUDP(ctx context.Context, strict bool) (*UDPSession, error) {
	conn, err := c.dial(ctx, "tcp", c.Server)
	if err != nil {
		return nil, fmt.Errorf("连接代理服务器失败: %w", err)
	}
	stop := watch(ctx, conn)
	if err := c.handshake(conn); err != nil {
		stop()
		conn.Close()
		return nil, err
	}
	reported, err := c.request(conn, cmdUDPAssoc, "0.0.0.0:0")
	stop()
	if err != nil {
		conn.Close()
		var re *ReplyError
		if errors.As(err, &re) && re.Code == 7 {
			return nil, errors.New("代理不支持 UDP ASSOCIATE")
		}
		return nil, err
	}
	s := &UDPSession{ctrl: conn, Reported: reported, Relay: reported}
	rh, rp, _ := net.SplitHostPort(reported)
	ra, perr := netip.ParseAddr(rh)
	var serverIP netip.Addr
	if ta, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		serverIP = ta.AddrPort().Addr().Unmap()
	}
	// 未指定地址一定不可用；服务器是公网地址却报告回环/私网地址，说明代理在 NAT 后面且配置有误。
	unusable := ra.IsUnspecified() ||
		(ra.IsLoopback() && serverIP.IsValid() && !serverIP.IsLoopback()) ||
		(ra.IsPrivate() && serverIP.IsValid() && !serverIP.IsPrivate() && !serverIP.IsLoopback())
	if perr == nil && unusable && serverIP.IsValid() {
		if strict {
			conn.Close()
			return s, fmt.Errorf("代理返回的 UDP 中继地址 %s 不可用", reported)
		}
		s.Relay = net.JoinHostPort(serverIP.String(), rp)
		s.Substituted = true
	}
	pc, err := c.dial(ctx, "udp", s.Relay)
	if err != nil {
		conn.Close()
		return s, fmt.Errorf("连接 UDP 中继失败: %w", err)
	}
	s.pc = pc
	return s, nil
}

// Exchange 经中继把 payload 发往 dst，并等待一个应答。
func (s *UDPSession) Exchange(ctx context.Context, dst string, payload []byte) ([]byte, string, error) {
	hdr, err := encodeAddr(dst)
	if err != nil {
		return nil, "", err
	}
	pkt := append([]byte{0, 0, 0}, hdr...)
	pkt = append(pkt, payload...)
	if dl, ok := ctx.Deadline(); ok {
		s.pc.SetDeadline(dl)
	}
	if _, err := s.pc.Write(pkt); err != nil {
		return nil, "", err
	}
	buf := make([]byte, 65535)
	n, err := s.pc.Read(buf)
	if err != nil {
		return nil, "", err
	}
	if n < 4 || buf[2] != 0 {
		return nil, "", errors.New("socks5: 收到无效或分片的 UDP 应答")
	}
	r := &sliceReader{b: buf[3:n]}
	from, err := readAddr(r)
	if err != nil {
		return nil, "", err
	}
	return r.b, from, nil
}

// Close 拆除该 UDP 关联。
func (s *UDPSession) Close() error {
	if s.pc != nil {
		s.pc.Close()
	}
	if s.ctrl != nil {
		return s.ctrl.Close()
	}
	return nil
}

type sliceReader struct{ b []byte }

func (r *sliceReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}
