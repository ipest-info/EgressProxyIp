// Package install 实现 egp 在 Ubuntu（systemd）上的一键安装、卸载与服务管理。
package install

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ipest-info/EgressProxyIp/internal/gost"
	"github.com/ipest-info/EgressProxyIp/internal/model"
	"github.com/ipest-info/EgressProxyIp/internal/passwd"
	"github.com/ipest-info/EgressProxyIp/internal/store"
)

//go:embed files
var files embed.FS

// 安装路径。
const (
	BinPath     = "/usr/local/bin/egp"
	GostPath    = "/usr/local/bin/gost"
	ConfigDir   = "/etc/egp"
	UnitDir     = "/etc/systemd/system"
	ModulesConf = "/etc/modules-load.d/egp.conf"
	Service     = "egp.service"
	GuardUnit   = "egp-guard.service"
	DirectGroup = "egp-direct"
)

// Options 是安装参数。
type Options struct {
	GostBin string // 指定 gost 可执行文件；为空时依次查找 egp 同目录、/usr/local/bin/gost
	Listen  string // WebUI 监听地址，为空保持默认 127.0.0.1:8088
	NoStart bool   // 只安装不启动
	Out     io.Writer
}

func (o Options) printf(format string, a ...any) { fmt.Fprintf(o.Out, format, a...) }

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s 失败: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func have(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func copyFile(src, dst string, perm os.FileMode) error {
	if same(src, dst) {
		return os.Chmod(dst, perm)
	}
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	// 先写临时文件再改名，避免覆盖正在运行的可执行文件时报 “text file busy”。
	return store.WriteFile(dst, b, perm)
}

func same(a, b string) bool {
	ra, err1 := filepath.EvalSymlinks(a)
	rb, err2 := filepath.EvalSymlinks(b)
	return err1 == nil && err2 == nil && ra == rb
}

// checkSystem 检查运行环境，缺少依赖时尝试用 apt 安装。
func checkSystem(o Options) error {
	if os.Geteuid() != 0 {
		return errors.New("请使用 root 运行（sudo egp install）")
	}
	if !have("systemctl") {
		return errors.New("未找到 systemctl：egp 需要 systemd")
	}
	if b, err := os.ReadFile("/etc/os-release"); err == nil && !strings.Contains(string(b), "ID=ubuntu") {
		o.printf("⚠ 当前系统不是 Ubuntu，将按 systemd 通用方式继续安装\n")
	}
	var missing []string
	for _, c := range []struct{ bin, pkg string }{{"iptables", "iptables"}, {"ip", "iproute2"}} {
		if !have(c.bin) {
			missing = append(missing, c.pkg)
		}
	}
	if len(missing) > 0 {
		if !have("apt-get") {
			return fmt.Errorf("缺少依赖 %s，请先手动安装", strings.Join(missing, "、"))
		}
		o.printf("· 安装依赖: %s\n", strings.Join(missing, " "))
		if err := run("apt-get", append([]string{"install", "-y"}, missing...)...); err != nil {
			return err
		}
	}
	return nil
}

// findGost 找到要安装的 gost。
func findGost(o Options) (string, error) {
	var candidates []string
	if o.GostBin != "" {
		candidates = append(candidates, o.GostBin)
	} else {
		if exe, err := os.Executable(); err == nil {
			candidates = append(candidates, filepath.Join(filepath.Dir(exe), "gost"))
		}
		candidates = append(candidates, GostPath)
	}
	var errs []string
	for _, c := range candidates {
		if _, err := os.Stat(c); err != nil {
			continue
		}
		v, err := gost.CheckBinary(context.Background(), c)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		o.printf("· 找到 gost %s: %s\n", v, c)
		return c, nil
	}
	if len(errs) > 0 {
		return "", errors.New(strings.Join(errs, "；"))
	}
	return "", errors.New("没有找到 gost 可执行文件：请把 gost 放在 egp 同一目录，或使用 --gost 指定路径（install.sh 会自动下载）")
}

// Install 执行一键安装。
func Install(o Options) error {
	if o.Out == nil {
		o.Out = os.Stdout
	}
	if err := checkSystem(o); err != nil {
		return err
	}
	gostSrc, err := findGost(o)
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	o.printf("· 安装 egp → %s\n", BinPath)
	if err := copyFile(exe, BinPath, 0o755); err != nil {
		return fmt.Errorf("安装 egp 失败: %w", err)
	}
	o.printf("· 安装 gost → %s\n", GostPath)
	if err := copyFile(gostSrc, GostPath, 0o755); err != nil {
		return fmt.Errorf("安装 gost 失败: %w", err)
	}
	if err := os.MkdirAll(ConfigDir, 0o700); err != nil {
		return err
	}
	if err := exec.Command("getent", "group", DirectGroup).Run(); err != nil {
		o.printf("· 创建直连用户组 %s\n", DirectGroup)
		if err := run("groupadd", "--system", DirectGroup); err != nil {
			o.printf("⚠ %v\n", err)
		}
	}
	mods, _ := files.ReadFile("files/modules.conf")
	if err := store.WriteFile(ModulesConf, mods, 0o644); err != nil {
		return err
	}
	for _, line := range strings.Split(string(mods), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			exec.Command("modprobe", line).Run() // 尽力而为：部分模块可能已编入内核
		}
	}
	for _, u := range []string{Service, GuardUnit} {
		b, _ := files.ReadFile("files/" + u)
		if err := store.WriteFile(filepath.Join(UnitDir, u), b, 0o644); err != nil {
			return err
		}
	}
	pw, err := initState(o)
	if err != nil {
		return err
	}
	// 容器等没有以 systemd 启动的环境中无法注册服务，只完成文件安装。
	systemdUp := true
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		systemdUp = false
		o.printf("⚠ 当前系统未以 systemd 运行（例如容器内），已跳过服务注册；可手动运行：%s serve -dir %s\n", BinPath, ConfigDir)
	} else {
		if err := run("systemctl", "daemon-reload"); err != nil {
			return err
		}
		if err := run("systemctl", "enable", Service, GuardUnit); err != nil {
			return err
		}
	}
	if !o.NoStart && systemdUp {
		o.printf("· 启动服务\n")
		if err := run("systemctl", "restart", Service); err != nil {
			return err
		}
		time.Sleep(time.Second)
		if err := exec.Command("systemctl", "is-active", "--quiet", Service).Run(); err != nil {
			return errors.New("服务启动失败，请执行 journalctl -u egp -n 50 查看原因")
		}
	}
	st, _ := loadState()
	o.printf("\n✔ 安装完成\n\n")
	o.printf("  WebUI 地址: %s\n", webURL(st.Settings.Listen))
	if pw != "" {
		o.printf("  用户名: %s\n  初始密码: %s（同时保存在 %s/initial-password，登录后请修改）\n", st.Settings.AdminUser, pw, ConfigDir)
	}
	if host := hostOf(st.Settings.Listen); host == "127.0.0.1" || host == "localhost" {
		o.printf("\n  WebUI 只监听本机，请在自己电脑上建立 SSH 隧道后访问：\n")
		o.printf("    ssh -L 8088:%s root@<ECS 公网 IP>\n    然后打开 http://127.0.0.1:8088\n", st.Settings.Listen)
	} else {
		o.printf("\n  ⚠ WebUI 监听在 %s，请在阿里云安全组中只放行你自己的 IP。\n", st.Settings.Listen)
	}
	o.printf("\n  常用命令: egp start | egp stop | egp restart | egp status | egp logs\n")
	o.printf("  出口代理默认未启用：登录 WebUI 添加代理并点击“启用出口代理”后才会生效。\n")
	return nil
}

func hostOf(listen string) string {
	h := listen
	if i := strings.LastIndex(listen, ":"); i >= 0 {
		h = listen[:i]
	}
	return strings.Trim(h, "[]")
}

func webURL(listen string) string {
	host := hostOf(listen)
	scheme := "https"
	if host == "127.0.0.1" || host == "localhost" || host == "::1" {
		scheme = "http"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "<ECS 公网 IP>"
	}
	port := listen[strings.LastIndex(listen, ":")+1:]
	return fmt.Sprintf("%s://%s:%s", scheme, host, port)
}

func loadState() (model.State, error) {
	s, err := store.New(ConfigDir)
	if err != nil {
		return model.Default(), err
	}
	return s.Load()
}

// initState 初始化状态文件：设置 gost 路径、监听地址，没有密码时生成初始密码。
func initState(o Options) (string, error) {
	s, err := store.New(ConfigDir)
	if err != nil {
		return "", err
	}
	st, err := s.Load()
	if err != nil {
		return "", err
	}
	st.Settings.GostBin = GostPath
	if o.Listen != "" {
		st.Settings.Listen = o.Listen
	}
	pw := ""
	if st.Settings.AdminHash == "" {
		pw, err = SetInitialPassword(&st, ConfigDir)
		if err != nil {
			return "", err
		}
	}
	return pw, s.Save(st)
}

// SetInitialPassword 生成随机密码，写入 st 并保存到 dir/initial-password（0600）。
func SetInitialPassword(st *model.State, dir string) (string, error) {
	pw := passwd.Random()
	h, err := passwd.Hash(pw)
	if err != nil {
		return "", err
	}
	st.Settings.AdminHash = h
	content := fmt.Sprintf("用户名: %s\n密码: %s\n（首次登录后请在 WebUI “设置”中修改密码，然后可删除本文件）\n", st.Settings.AdminUser, pw)
	if err := store.WriteFile(filepath.Join(dir, "initial-password"), []byte(content), 0o600); err != nil {
		return "", err
	}
	return pw, nil
}

// Uninstall 停止并删除服务。purge 为 true 时同时删除 /etc/egp 下的配置。
func Uninstall(out io.Writer, purge bool) error {
	if os.Geteuid() != 0 {
		return errors.New("请使用 root 运行（sudo egp uninstall）")
	}
	fmt.Fprintln(out, "· 停止并禁用服务")
	exec.Command("systemctl", "disable", "--now", Service, GuardUnit).Run()
	fmt.Fprintln(out, "· 清理防火墙规则")
	if b, err := exec.Command(BinPath, "cleanup", "-dir", ConfigDir).CombinedOutput(); err != nil {
		fmt.Fprintf(out, "⚠ 清理规则失败: %v %s\n", err, b)
	}
	for _, p := range []string{filepath.Join(UnitDir, Service), filepath.Join(UnitDir, GuardUnit), ModulesConf} {
		os.Remove(p)
	}
	exec.Command("systemctl", "daemon-reload").Run()
	os.Remove(GostPath)
	if purge {
		fmt.Fprintf(out, "· 删除配置目录 %s\n", ConfigDir)
		os.RemoveAll(ConfigDir)
		exec.Command("groupdel", DirectGroup).Run()
	} else {
		fmt.Fprintf(out, "· 保留配置目录 %s（使用 --purge 一并删除）\n", ConfigDir)
	}
	os.Remove(BinPath)
	fmt.Fprintln(out, "✔ 已卸载，流量已恢复直连")
	return nil
}

// Systemctl 透传 systemctl 命令并把输出直接打印到终端。
func Systemctl(args ...string) error {
	cmd := exec.Command("systemctl", args...)
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
	return cmd.Run()
}

// Journal 显示服务日志。
func Journal(follow bool, lines int) error {
	args := []string{"-u", "egp", "-u", "egp-guard", "-n", fmt.Sprint(lines), "--no-pager", "-o", "short-iso"}
	if follow {
		args = append(args, "-f")
	}
	cmd := exec.Command("journalctl", args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

// Active 判断服务是否在运行。
func Active() bool {
	return exec.Command("systemctl", "is-active", "--quiet", Service).Run() == nil
}
