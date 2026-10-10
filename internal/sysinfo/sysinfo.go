// Package sysinfo 从 /proc 和 /etc 读取主机信息。根目录可注入，便于测试使用样例文件。
package sysinfo

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// FS 以 Root 为根读取文件（生产环境为 "/"）。
type FS struct{ Root string }

// Host 表示真实系统。
var Host = FS{Root: "/"}

func (f FS) path(p string) string { return filepath.Join(f.Root, p) }

func (f FS) read(p string) string {
	b, err := os.ReadFile(f.path(p))
	if err != nil {
		return ""
	}
	return string(b)
}

// ResolverIPs 返回主机配置的 IPv4 DNS 服务器。使用 systemd-resolved 时，
// 除 127.0.0.53 存根外还会返回其真实上游（回环地址本就总是绕过）。
func (f FS) ResolverIPs() []netip.Addr {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, p := range []string{"etc/resolv.conf", "run/systemd/resolve/resolv.conf"} {
		for _, line := range strings.Split(f.read(p), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 || fields[0] != "nameserver" {
				continue
			}
			a, err := netip.ParseAddr(fields[1])
			if err != nil || !a.Is4() || seen[a] {
				continue
			}
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

// ConnectedSubnets 从 /proc/net/route 返回直连的 IPv4 网段（无网关的路由），
// 不含回环与默认路由。
func (f FS) ConnectedSubnets() []netip.Prefix {
	var out []netip.Prefix
	sc := bufio.NewScanner(strings.NewReader(f.read("proc/net/route")))
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		fl := strings.Fields(sc.Text())
		if len(fl) < 8 || fl[0] == "lo" {
			continue
		}
		dst, ok1 := hexIPv4(fl[1])
		gw, ok2 := hexIPv4(fl[2])
		mask, ok3 := hexIPv4(fl[7])
		if !ok1 || !ok2 || !ok3 || !gw.IsUnspecified() || dst.IsUnspecified() {
			continue
		}
		bits := 0
		for _, b := range mask.As4() {
			for i := 7; i >= 0; i-- {
				if b&(1<<i) != 0 {
					bits++
				}
			}
		}
		if p, err := dst.Prefix(bits); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// hexIPv4 解码 /proc/net/route 中小端序的十六进制地址。
func hexIPv4(s string) (netip.Addr, bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 4 {
		return netip.Addr{}, false
	}
	v := binary.LittleEndian.Uint32(b)
	var a [4]byte
	binary.BigEndian.PutUint32(a[:], v)
	return netip.AddrFrom4(a), true
}

// Socket 表示本机处于监听状态（TCP）或已绑定（UDP）的套接字。
type Socket struct {
	Addr netip.Addr
	Port int
}

// Listening 返回 IPv4/IPv6 下处于 LISTEN 状态的 TCP 套接字，或已绑定未连接的 UDP 套接字。
func (f FS) Listening(proto string) []Socket {
	state := "0A" // TCP_LISTEN
	if proto == "udp" {
		state = "07" // 未连接的 UDP 套接字在 /proc 中显示为 TCP_CLOSE
	}
	var out []Socket
	for _, file := range []string{"proc/net/" + proto, "proc/net/" + proto + "6"} {
		sc := bufio.NewScanner(strings.NewReader(f.read(file)))
		for sc.Scan() {
			fl := strings.Fields(sc.Text())
			if len(fl) < 4 || fl[3] != state {
				continue
			}
			local := fl[1]
			i := strings.LastIndex(local, ":")
			if i < 0 {
				continue
			}
			port, err := strconv.ParseUint(local[i+1:], 16, 16)
			if err != nil {
				continue
			}
			// 已绑定但未连接的 UDP 套接字，其远端地址全为 0。
			if proto == "udp" && strings.Trim(strings.ReplaceAll(fl[2], ":", ""), "0") != "" {
				continue
			}
			out = append(out, Socket{Addr: procAddr(local[:i]), Port: int(port)})
		}
	}
	return out
}

func procAddr(h string) netip.Addr {
	b, err := hex.DecodeString(h)
	if err != nil {
		return netip.Addr{}
	}
	// /proc 中每个 32 位字以主机字节序（小端）存储。
	for i := 0; i+4 <= len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	a, _ := netip.AddrFromSlice(b)
	return a.Unmap()
}

// PortInUse 判断指定协议的本地套接字是否占用了 port。
func (f FS) PortInUse(proto string, port int) bool {
	for _, s := range f.Listening(proto) {
		if s.Port == port {
			return true
		}
	}
	return false
}

// LocalPortRangeStart 返回临时端口范围的起点（默认 32768）。
func (f FS) LocalPortRangeStart() int {
	fl := strings.Fields(f.read("proc/sys/net/ipv4/ip_local_port_range"))
	if len(fl) >= 1 {
		if v, err := strconv.Atoi(fl[0]); err == nil && v > 0 {
			return v
		}
	}
	return 32768
}

// LocalUDPServicePorts 返回绑定在临时端口范围以下的 UDP 端口。它们是本机对外提供的
// 服务（DNS、WireGuard、游戏服务器等），conntrack 条目过期后其回包也不能被导入代理。
func (f FS) LocalUDPServicePorts(exclude ...int) []int {
	limit := f.LocalPortRangeStart()
	skip := map[int]bool{}
	for _, p := range exclude {
		skip[p] = true
	}
	set := map[int]bool{}
	for _, s := range f.Listening("udp") {
		if s.Port > 0 && s.Port < limit && !skip[s.Port] && !s.Addr.IsLoopback() {
			set[s.Port] = true
		}
	}
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// Conntrack 返回当前与最大的连接跟踪条目数。
func (f FS) Conntrack() (count, max int) {
	count, _ = strconv.Atoi(strings.TrimSpace(f.read("proc/sys/net/netfilter/nf_conntrack_count")))
	max, _ = strconv.Atoi(strings.TrimSpace(f.read("proc/sys/net/netfilter/nf_conntrack_max")))
	return
}

// HasGlobalIPv6 判断是否有网卡配置了全局 IPv6 地址。
func (f FS) HasGlobalIPv6() bool {
	for _, line := range strings.Split(f.read("proc/net/if_inet6"), "\n") {
		fl := strings.Fields(line)
		if len(fl) >= 6 && fl[3] == "00" && fl[5] != "lo" {
			return true
		}
	}
	return false
}

// GroupExists 判断 /etc/group 中是否定义了该用户组。
func (f FS) GroupExists(name string) bool {
	for _, line := range strings.Split(f.read("etc/group"), "\n") {
		if strings.HasPrefix(line, name+":") {
			return true
		}
	}
	return false
}
