// fakenet 在测试用的“互联网”网络命名空间中运行：HTTP 回显服务、若干 SOCKS5 代理和 STUN 服务。
// 回显服务返回请求的来源 IP，用来判断流量究竟从哪个 IP 出网。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"

	"github.com/ipest-info/EgressProxyIp/internal/socks5/socks5test"
	"github.com/ipest-info/EgressProxyIp/internal/stun"
)

func main() {
	echo := flag.String("echo", "203.0.113.10:80", "HTTP 回显服务地址")
	socks := flag.String("socks", "203.0.113.20:1080,203.0.113.21:1080", "SOCKS5 代理地址（逗号分隔）")
	user := flag.String("user", "u", "SOCKS5 用户名")
	pass := flag.String("pass", "p", "SOCKS5 密码")
	stunAddr := flag.String("stun", "203.0.113.30:3478", "STUN 服务地址")
	flag.Parse()

	var mu sync.Mutex
	servers := map[string]*socks5test.Server{}
	start := func(addr string) error {
		ip, _, _ := net.SplitHostPort(addr)
		d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(ip)}}
		s := &socks5test.Server{Username: *user, Password: *pass, BindIP: ip, Dial: d.Dial}
		if err := s.Start(addr); err != nil {
			return err
		}
		mu.Lock()
		servers[addr] = s
		mu.Unlock()
		return nil
	}
	for _, a := range strings.Split(*socks, ",") {
		if err := start(a); err != nil {
			log.Fatalf("启动 SOCKS5 %s 失败: %v", a, err)
		}
	}

	go func() {
		pc, err := net.ListenPacket("udp", *stunAddr)
		if err != nil {
			log.Fatalf("启动 STUN 失败: %v", err)
		}
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil || n < 20 {
				continue
			}
			tid := [12]byte(buf[8:20])
			ap := from.(*net.UDPAddr).AddrPort()
			pc.WriteTo(stun.Response(tid, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())), from)
		}
	}()

	mux := http.NewServeMux()
	src := func(r *http.Request) string { h, _, _ := net.SplitHostPort(r.RemoteAddr); return h }
	mux.HandleFunc("/ip", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, src(r)) })
	mux.HandleFunc("/ip2", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, src(r)) })
	mux.HandleFunc("/204", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("/geo/", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "success", "country": "测试国", "regionName": "测试省", "city": "测试市", "isp": "测试网络"})
	})
	// /ctl/stop?addr=203.0.113.20:1080 关闭某个代理，模拟代理故障；/ctl/start 重新启动。
	mux.HandleFunc("/ctl/stop", func(w http.ResponseWriter, r *http.Request) {
		addr := r.URL.Query().Get("addr")
		mu.Lock()
		s := servers[addr]
		delete(servers, addr)
		mu.Unlock()
		if s != nil {
			s.Close()
		}
		fmt.Fprintln(w, "stopped")
	})
	mux.HandleFunc("/ctl/start", func(w http.ResponseWriter, r *http.Request) {
		if err := start(r.URL.Query().Get("addr")); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		fmt.Fprintln(w, "started")
	})
	log.Printf("fakenet 已就绪: echo=%s socks=%s stun=%s", *echo, *socks, *stunAddr)
	log.Fatal(http.ListenAndServe(*echo, mux))
}
