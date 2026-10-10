// egp：ECS 出口代理。通过 WebUI 配置 SOCKS5 代理 IP，使本机所有出站流量以代理 IP 访问互联网。
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ipest-info/EgressProxyIp/internal/controller"
	"github.com/ipest-info/EgressProxyIp/internal/install"
	"github.com/ipest-info/EgressProxyIp/internal/passwd"
	"github.com/ipest-info/EgressProxyIp/internal/store"
	"github.com/ipest-info/EgressProxyIp/internal/web"
)

// version 在构建时通过 -ldflags "-X main.version=..." 注入。
var version = "dev"

const usage = `egp —— ECS 出口代理（使用代理 IP 作为本机访问互联网的出口）

服务管理：
  egp install [--gost 路径] [--listen 地址]   一键安装为 systemd 服务并启动
  egp uninstall [--purge]                      卸载（--purge 同时删除配置）
  egp start                                    启动服务
  egp stop                                     停止服务并恢复直连
  egp restart                                  重启服务
  egp status                                   查看服务状态
  egp logs [-f] [-n 行数]                      查看服务日志

其他：
  egp serve [-dir /etc/egp] [-listen 地址] [-dry-run]   前台运行（systemd 调用）
  egp plan [-dir /etc/egp]                     预览将要下发的规则与 gost 配置
  egp cleanup [-dir /etc/egp]                  立即删除全部防火墙规则，恢复直连
  egp reset-password [-dir /etc/egp]           重置管理员密码
  egp version                                  显示版本
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = cmdServe(args)
	case "install":
		err = cmdInstall(args)
	case "uninstall":
		fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
		purge := fs.Bool("purge", false, "同时删除 /etc/egp 下的配置与数据")
		fs.Parse(args)
		err = install.Uninstall(os.Stdout, *purge)
	case "start":
		err = cmdStart()
	case "stop":
		err = cmdStop()
	case "restart":
		err = install.Systemctl("restart", install.Service)
		if err == nil {
			fmt.Println("✔ 已重启")
		}
	case "status":
		err = install.Systemctl("status", install.Service, "--no-pager", "-l")
	case "logs":
		fs := flag.NewFlagSet("logs", flag.ExitOnError)
		follow := fs.Bool("f", false, "持续输出")
		n := fs.Int("n", 200, "显示的行数")
		fs.Parse(args)
		err = install.Journal(*follow, *n)
	case "plan":
		err = cmdPlan(args)
	case "cleanup":
		err = cmdCleanup(args)
	case "boot-guard":
		err = cmdBootGuard(args)
	case "reset-password":
		err = cmdResetPassword(args)
	case "version", "-v", "--version":
		fmt.Println("egp", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "未知命令 %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		os.Exit(1)
	}
}

func newLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

func requireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("需要 root 权限，请使用 sudo")
	}
	return nil
}

func cmdInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	gostBin := fs.String("gost", "", "gost 可执行文件路径（默认查找 egp 同目录下的 gost）")
	listen := fs.String("listen", "", "WebUI 监听地址（默认 127.0.0.1:8088）")
	noStart := fs.Bool("no-start", false, "只安装，不启动服务")
	fs.Parse(args)
	return install.Install(install.Options{GostBin: *gostBin, Listen: *listen, NoStart: *noStart, Out: os.Stdout})
}

func cmdStart() error {
	if err := requireRoot(); err != nil {
		return err
	}
	if err := install.Systemctl("enable", "--now", install.Service, install.GuardUnit); err != nil {
		return err
	}
	fmt.Println("✔ 服务已启动（出口代理是否生效取决于 WebUI 中的“启用出口代理”）")
	return nil
}

func cmdStop() error {
	if err := requireRoot(); err != nil {
		return err
	}
	if err := install.Systemctl("stop", install.Service); err != nil {
		return err
	}
	// 主动停止表示用户希望恢复直连：即使开启了 kill switch 也清理规则。
	if _, err := controller.Cleanup(context.Background(), install.ConfigDir, newLogger(), false); err != nil {
		return fmt.Errorf("清理规则失败: %w", err)
	}
	fmt.Println("✔ 服务已停止，流量已恢复使用 ECS 自身 IP 直连（开机仍会自动启动，如需禁用请执行 systemctl disable egp）")
	return nil
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dir := fs.String("dir", install.ConfigDir, "配置与数据目录")
	listenFlag := fs.String("listen", "", "覆盖 WebUI 监听地址")
	dryRun := fs.Bool("dry-run", false, "演示模式：不启动 gost、不修改防火墙")
	insecure := fs.Bool("insecure-http", false, "监听非回环地址时也使用 HTTP（不推荐）")
	confirmTimeout := fs.Duration("confirm-timeout", 60*time.Second, "应用后等待确认的时间，超时自动回滚")
	fs.Parse(args)
	log := newLogger()
	if !*dryRun {
		if err := requireRoot(); err != nil {
			return err
		}
	}

	// 首次启动且没有密码时生成初始密码。
	st, err := store.New(*dir)
	if err != nil {
		return err
	}
	state, err := st.Load()
	if err != nil {
		return err
	}
	if state.Settings.AdminHash == "" {
		if _, err := install.SetInitialPassword(&state, *dir); err != nil {
			return err
		}
		if err := st.Save(state); err != nil {
			return err
		}
		log.Warn("已生成初始管理员密码", "文件", *dir+"/initial-password")
	}
	listen := state.Settings.Listen
	if *listenFlag != "" {
		listen = *listenFlag
	}
	host, portStr, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("监听地址 %q 无效: %w", listen, err)
	}
	var port int
	fmt.Sscan(portStr, &port)

	runDir := "/run/egp"
	if *dryRun || os.Getenv("RUNTIME_DIRECTORY") != "" {
		if d := os.Getenv("RUNTIME_DIRECTORY"); d != "" {
			runDir = d
		} else {
			runDir = *dir + "/run"
		}
	}
	c, err := controller.New(controller.Options{Dir: *dir, RunDir: runDir, DryRun: *dryRun, WebUIPort: port, Log: log, ConfirmTimeout: *confirmTimeout})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := c.Start(ctx); err != nil {
		return err
	}

	loopback := host == "127.0.0.1" || host == "localhost" || host == "::1"
	secure := !loopback && !*insecure
	srv := &http.Server{
		Addr:              listen,
		Handler:           web.New(c, log, secure).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	errc := make(chan error, 1)
	go func() {
		var err error
		if secure {
			var cert tls.Certificate
			cert, err = web.LoadOrCreateCert(*dir, []string{host})
			if err == nil {
				srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
				log.Info("WebUI 已启动（HTTPS，自签证书）", "地址", "https://"+listen)
				err = srv.ListenAndServeTLS("", "")
			}
		} else {
			if !loopback {
				log.Warn("WebUI 以明文 HTTP 监听在非回环地址，密码可能被窃听")
			}
			log.Info("WebUI 已启动", "地址", "http://"+listen)
			err = srv.ListenAndServe()
		}
		if !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Info("收到退出信号，正在停止")
	case err := <-errc:
		log.Error("WebUI 启动失败", "错误", err.Error())
		c.Stop(context.Background())
		return err
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(sctx)
	c.Stop(sctx)
	log.Info("已停止")
	return nil
}

func cmdPlan(args []string) error {
	fs := flag.NewFlagSet("plan", flag.ExitOnError)
	dir := fs.String("dir", install.ConfigDir, "配置与数据目录")
	fs.Parse(args)
	c, err := controller.New(controller.Options{Dir: *dir, RunDir: os.TempDir(), DryRun: true, Log: newLogger()})
	if err != nil {
		return err
	}
	p := c.Preview(context.Background())
	fmt.Println("# ===== 防火墙规则 =====")
	fmt.Print(p.Rules)
	fmt.Println("\n# ===== 绕过网段 =====")
	fmt.Println(strings.Join(p.Bypass, " "))
	fmt.Println("\n# ===== gost 配置（已隐藏密码）=====")
	fmt.Println(string(p.GostConfig))
	return nil
}

func cmdCleanup(args []string) error {
	fs := flag.NewFlagSet("cleanup", flag.ExitOnError)
	dir := fs.String("dir", install.ConfigDir, "配置与数据目录")
	respect := fs.Bool("respect-killswitch", false, "kill switch 开启时保留规则（供 systemd 使用）")
	fs.Parse(args)
	if err := requireRoot(); err != nil {
		return err
	}
	skipped, err := controller.Cleanup(context.Background(), *dir, newLogger(), *respect)
	if err != nil {
		return err
	}
	if skipped {
		fmt.Println("kill switch 已开启：保留防火墙规则（本机将无法访问互联网）。如需恢复直连请执行 egp cleanup")
		return nil
	}
	fmt.Println("✔ 已删除 egp 的全部防火墙规则，流量恢复直连")
	return nil
}

func cmdBootGuard(args []string) error {
	fs := flag.NewFlagSet("boot-guard", flag.ExitOnError)
	dir := fs.String("dir", install.ConfigDir, "配置与数据目录")
	fs.Parse(args)
	applied, err := controller.BootGuard(context.Background(), controller.Options{Dir: *dir, RunDir: os.TempDir(), Log: newLogger()})
	if err != nil {
		return err
	}
	if applied {
		fmt.Println("kill switch 已开启：开机阶段已下发阻断规则，等待 egp 服务启动")
	}
	return nil
}

func cmdResetPassword(args []string) error {
	fs := flag.NewFlagSet("reset-password", flag.ExitOnError)
	dir := fs.String("dir", install.ConfigDir, "配置与数据目录")
	fs.Parse(args)
	if err := requireRoot(); err != nil {
		return err
	}
	st, err := store.New(*dir)
	if err != nil {
		return err
	}
	state, err := st.Load()
	if err != nil {
		return err
	}
	pw := passwd.Random()
	h, err := passwd.Hash(pw)
	if err != nil {
		return err
	}
	state.Settings.AdminHash = h
	if err := st.Save(state); err != nil {
		return err
	}
	if a, err := st.LoadApplied(); err == nil && a != nil {
		a.State.Settings.AdminHash = h
		st.SaveApplied(a)
	}
	fmt.Printf("✔ 新密码: %s（用户名 %s）\n", pw, state.Settings.AdminUser)
	if install.Active() {
		// 运行中的服务在内存里持有旧密码，需要重启才能生效。
		if err := install.Systemctl("restart", install.Service); err == nil {
			fmt.Println("已重启服务使新密码生效")
		}
	}
	return nil
}
