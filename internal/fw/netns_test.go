package fw

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// requireNetns 只允许在全新的网络命名空间（只有 lo 网卡）中执行会修改防火墙的测试，
// 绝不触碰宿主机的规则。用法：sudo unshare -n go test ./internal/fw -run Netns
func requireNetns(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("需要 root")
	}
	if !freshNetns() {
		t.Skip("不在全新的网络命名空间中（请用 unshare -n 运行），跳过以免修改宿主机防火墙")
	}
}

// freshNetns 判断当前网络命名空间是否只有回环网卡。
func freshNetns() bool {
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(b), "\n")[2:] {
		name, _, ok := strings.Cut(strings.TrimSpace(l), ":")
		if ok && name != "lo" {
			return false
		}
	}
	return true
}

func save(t *testing.T, b Backend) string {
	t.Helper()
	cmd := strings.TrimSuffix(b.IPTRest, "-restore") + "-save"
	out, err := exec.Command(cmd).Output()
	if err != nil {
		t.Fatalf("%s: %v", cmd, err)
	}
	var keep []string
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(l, "#") || strings.HasPrefix(l, ":") || l == "" {
			continue // 去掉时间戳和计数器
		}
		// nft 后端会留下空表，与语义无关，去掉没有规则的表。
		if l == "COMMIT" && len(keep) > 0 && strings.HasPrefix(keep[len(keep)-1], "*") {
			keep = keep[:len(keep)-1]
			continue
		}
		keep = append(keep, l)
	}
	return strings.Join(keep, "\n")
}

func TestNetnsApplyIdempotentAndCleanup(t *testing.T) {
	requireNetns(t)
	for _, name := range []string{"nft", "legacy"} {
		t.Run(name, func(t *testing.T) {
			b := backendFor(name)
			if lookPath("iptables-"+name) == "" {
				t.Skipf("没有 iptables-%s", name)
			}
			ctx := context.Background()
			f := &Firewall{R: Exec{}, B: b, Log: slog.Default(), HasIPv6: b.IP6T != ""}
			// 模拟已存在的第三方规则（Docker/ufw），egp 不能破坏它们。
			exec.Command(b.IPT, "-t", "nat", "-N", "DOCKER").Run()
			exec.Command(b.IPT, "-t", "nat", "-A", "OUTPUT", "-m", "addrtype", "--dst-type", "LOCAL", "-j", "DOCKER").Run()
			exec.Command(b.IPT, "-A", "OUTPUT", "-p", "tcp", "--dport", "9999", "-j", "ACCEPT").Run()
			before := save(t, b)

			in := baseInput()
			in.LocalUDPPorts = nil
			in.Bypass.DirectGroup = "65534" // 测试环境中必定存在的 gid
			rs := Plan(in, true)
			rs.TProxy = false // 测试环境可能没有 ip 命令，策略路由单独验证
			if err := f.Apply(ctx, rs); err != nil {
				t.Fatal(err)
			}
			first := save(t, b)
			if err := f.Apply(ctx, rs); err != nil {
				t.Fatal(err)
			}
			if second := save(t, b); second != first {
				t.Fatalf("重复应用结果不一致:\n%s\n----\n%s", first, second)
			}
			if p := f.Check(ctx, rs); len(p) != 0 {
				t.Fatalf("检查发现问题: %v", p)
			}
			// 切换到更少的规则（关闭 kill switch），多余的链应被删除。
			in.Policy.KillSwitch = false
			rs2 := Plan(in, true)
			rs2.TProxy = false
			if err := f.Apply(ctx, rs2); err != nil {
				t.Fatal(err)
			}
			if out := save(t, b); strings.Contains(out, ChainGuardPX) {
				t.Fatalf("关闭 kill switch 后防护链仍存在:\n%s", out)
			}
			// 模拟漂移：有人删掉了跳转。
			exec.Command(b.IPT, "-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-m", "comment", "--comment", "egp", "-j", ChainTCPOut).Run()
			if p := f.Check(ctx, rs2); len(p) == 0 {
				t.Fatal("应检测到跳转缺失")
			}
			if err := f.Cleanup(ctx, rs2); err != nil {
				t.Fatal(err)
			}
			if err := f.Cleanup(ctx, rs2); err != nil {
				t.Fatal(err)
			}
			if after := save(t, b); after != before {
				t.Fatalf("清理后未恢复原状:\n--- 之前 ---\n%s\n--- 之后 ---\n%s", before, after)
			}
		})
	}
}
