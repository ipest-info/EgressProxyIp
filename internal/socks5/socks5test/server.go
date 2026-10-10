// Package socks5test 提供测试用的最小 SOCKS5 服务器，可模拟代理商常见的异常行为。
package socks5test

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
)

// Server 是监听在 127.0.0.1 上的 SOCKS5 服务器。
type Server struct {
	Username, Password string
	NoUDP              bool // 对 UDP ASSOCIATE 回复“不支持的命令”
	ReportZeroBind     bool // 把 UDP 中继地址报告为 0.0.0.0
	// Dial 用于 CONNECT 的出站连接（默认 net.Dial）。
	Dial func(network, addr string) (net.Conn, error)
	// BindIP 是 UDP 中继监听及出站使用的地址（默认 127.0.0.1）。
	BindIP string

	ln      net.Listener
	wg      sync.WaitGroup
	mu      sync.Mutex
	targets []string
}

// Start 在 addr 上监听（为空时用 "127.0.0.1:0"）并在后台提供服务。
func (s *Server) Start(addr string) error {
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.ln = ln
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return nil
}

// Addr 返回监听地址。
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Close 停止监听。
func (s *Server) Close() error {
	err := s.ln.Close()
	s.wg.Wait()
	return err
}

// Targets 返回目前为止收到的 CONNECT 目标。
func (s *Server) Targets() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.targets...)
}

func (s *Server) serve(c net.Conn) {
	defer c.Close()
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil || hdr[0] != 5 {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	want := byte(0)
	if s.Username != "" {
		want = 2
	}
	ok := false
	for _, m := range methods {
		if m == want {
			ok = true
		}
	}
	if !ok {
		c.Write([]byte{5, 0xFF})
		return
	}
	c.Write([]byte{5, want})
	if want == 2 {
		var v [2]byte
		if _, err := io.ReadFull(c, v[:]); err != nil {
			return
		}
		u := make([]byte, v[1])
		io.ReadFull(c, u)
		var pl [1]byte
		io.ReadFull(c, pl[:])
		p := make([]byte, pl[0])
		io.ReadFull(c, p)
		if string(u) != s.Username || string(p) != s.Password {
			c.Write([]byte{1, 1})
			return
		}
		c.Write([]byte{1, 0})
	}
	var req [3]byte
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return
	}
	target, err := readAddr(c)
	if err != nil {
		return
	}
	switch req[1] {
	case 1:
		s.mu.Lock()
		s.targets = append(s.targets, target)
		s.mu.Unlock()
		dial := s.Dial
		if dial == nil {
			dial = net.Dial
		}
		up, err := dial("tcp", target)
		if err != nil {
			c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		defer up.Close()
		la := up.LocalAddr().(*net.TCPAddr)
		c.Write(reply(0, la.AddrPort()))
		go func() { io.Copy(up, c); up.Close() }()
		io.Copy(c, up)
	case 3:
		if s.NoUDP {
			c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		pc, err := net.ListenPacket("udp", net.JoinHostPort(s.bindIP(), "0"))
		if err != nil {
			return
		}
		defer pc.Close()
		ap := pc.LocalAddr().(*net.UDPAddr).AddrPort()
		if s.ReportZeroBind {
			ap = netip.AddrPortFrom(netip.IPv4Unspecified(), ap.Port())
		}
		c.Write(reply(0, ap))
		go s.relayUDP(pc)
		io.Copy(io.Discard, c) // UDP 关联的生命周期与 TCP 控制连接一致
	default:
		c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
	}
}

func (s *Server) relayUDP(pc net.PacketConn) {
	buf := make([]byte, 65535)
	out, err := net.ListenPacket("udp", net.JoinHostPort(s.bindIP(), "0"))
	if err != nil {
		return
	}
	defer out.Close()
	var cmu sync.Mutex
	var client net.Addr
	go func() {
		rb := make([]byte, 65535)
		for {
			n, from, err := out.ReadFrom(rb)
			if err != nil {
				return
			}
			fa := from.(*net.UDPAddr).AddrPort()
			pkt := append([]byte{0, 0, 0}, encodeAddr(fa)...)
			pkt = append(pkt, rb[:n]...)
			cmu.Lock()
			to := client
			cmu.Unlock()
			if to != nil {
				pc.WriteTo(pkt, to)
			}
		}
	}()
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		cmu.Lock()
		client = from
		cmu.Unlock()
		if n < 4 {
			continue
		}
		r := &reader{b: buf[3:n]}
		dst, err := readAddr(r)
		if err != nil {
			continue
		}
		ua, err := net.ResolveUDPAddr("udp", dst)
		if err != nil {
			continue
		}
		out.WriteTo(r.b, ua)
	}
}

func (s *Server) bindIP() string {
	if s.BindIP != "" {
		return s.BindIP
	}
	return "127.0.0.1"
}

func reply(code byte, ap netip.AddrPort) []byte {
	return append([]byte{5, code, 0}, encodeAddr(ap)...)
}

func encodeAddr(ap netip.AddrPort) []byte {
	a := ap.Addr().Unmap()
	var b []byte
	if a.Is4() {
		b = append([]byte{1}, a.AsSlice()...)
	} else {
		b = append([]byte{4}, a.AsSlice()...)
	}
	return binary.BigEndian.AppendUint16(b, ap.Port())
}

func readAddr(r io.Reader) (string, error) {
	var t [1]byte
	if _, err := io.ReadFull(r, t[:]); err != nil {
		return "", err
	}
	var host string
	switch t[0] {
	case 1, 4:
		n := 4
		if t[0] == 4 {
			n = 16
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		a, _ := netip.AddrFromSlice(b)
		host = a.String()
	case 3:
		var l [1]byte
		io.ReadFull(r, l[:])
		b := make([]byte, l[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = string(b)
	default:
		return "", io.ErrUnexpectedEOF
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(p[:])))), nil
}

type reader struct{ b []byte }

func (r *reader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}
