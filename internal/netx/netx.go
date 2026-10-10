// Package netx 构造带防火墙标记（SO_MARK）的拨号器和 HTTP 客户端，
// 保证 egp 自身的探测流量不会被导入代理引擎。
package netx

import (
	"context"
	"net"
	"net/http"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Dialer 返回在每个套接字上设置 SO_MARK=mark 的拨号器（mark 为 0 表示不打标记）。
func Dialer(mark uint32, timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout}
	if mark != 0 {
		d.Control = func(network, address string, c syscall.RawConn) error {
			var serr error
			err := c.Control(func(fd uintptr) {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
			})
			if err != nil {
				return err
			}
			return serr
		}
	}
	return d
}

// Resolver 返回纯 Go 实现的解析器，其 DNS 套接字同样带标记。
func Resolver(mark uint32) *net.Resolver {
	d := Dialer(mark, 5*time.Second)
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return d.DialContext(ctx, network, address)
		},
	}
}

// HTTPClient 返回一个从不复用连接的客户端（保证每次测量都反映当前防火墙状态），
// 忽略代理环境变量，并给套接字打上 mark 标记。
func HTTPClient(mark uint32, timeout time.Duration) *http.Client {
	d := Dialer(mark, timeout)
	d.Resolver = Resolver(mark)
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         d.DialContext,
			DisableKeepAlives:   true,
			TLSHandshakeTimeout: timeout,
			ForceAttemptHTTP2:   false,
		},
	}
}

// HTTPClientVia 返回由 dial 建立连接的客户端，例如经指定代理的 SOCKS5 CONNECT。
func HTTPClientVia(dial func(ctx context.Context, network, addr string) (net.Conn, error), timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         dial,
			DisableKeepAlives:   true,
			TLSHandshakeTimeout: timeout,
		},
	}
}
