package gost

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Process 监管一个 gost 子进程，并收集它的日志。
type Process struct {
	Bin        string
	ConfigPath string
	Log        *slog.Logger
	// OnExit 在进程意外退出时被调用（主动 Stop 不会触发）。
	OnExit func(err error)

	mu       sync.Mutex
	cmd      *exec.Cmd
	done     chan struct{}
	stopping bool
	started  time.Time
	lastErr  error
	ring     *ring
}

// NewProcess 创建一个进程监管器。
func NewProcess(bin, configPath string, log *slog.Logger) *Process {
	return &Process{Bin: bin, ConfigPath: configPath, Log: log, ring: newRing(500)}
}

// Start 启动 gost。调用前进程必须处于停止状态。
func (p *Process) Start() error {
	p.mu.Lock()
	if p.cmd != nil {
		p.mu.Unlock()
		return errors.New("gost 已在运行")
	}
	p.mu.Unlock()

	type result struct {
		cmd *exec.Cmd
		err error
	}
	ch := make(chan result, 1)
	registered := make(chan struct{})
	done := make(chan struct{})
	// Pdeathsig 绑定的是创建子进程的那个系统线程，而不是整个进程。因此在一个
	// 锁定且直到子进程退出才释放的线程上启动 gost，egp 异常退出时 gost 会随之被杀掉。
	go func() {
		runtime.LockOSThread()
		cmd := exec.Command(p.Bin, "-C", p.ConfigPath)
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Setpgid: true}
		stdout, _ := cmd.StdoutPipe()
		stderr, _ := cmd.StderrPipe()
		if err := cmd.Start(); err != nil {
			ch <- result{err: err}
			close(done)
			return
		}
		ch <- result{cmd: cmd}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); p.collect(stdout) }()
		go func() { defer wg.Done(); p.collect(stderr) }()
		wg.Wait()
		err := cmd.Wait()
		<-registered
		p.mu.Lock()
		p.cmd = nil
		p.lastErr = err
		stopping := p.stopping
		p.stopping = false
		p.mu.Unlock()
		close(done)
		if !stopping {
			p.Log.Error("gost 意外退出", "错误", fmt.Sprint(err))
			if p.OnExit != nil {
				p.OnExit(err)
			}
		}
	}()
	r := <-ch
	if r.err != nil {
		return fmt.Errorf("启动 gost 失败: %w", r.err)
	}
	p.mu.Lock()
	p.cmd, p.done, p.started, p.lastErr = r.cmd, done, time.Now(), nil
	pid := p.pidLocked()
	p.mu.Unlock()
	close(registered)
	p.Log.Info("gost 已启动", "pid", pid, "配置", p.ConfigPath)
	return nil
}

func (p *Process) pidLocked() int {
	if p.cmd != nil && p.cmd.Process != nil {
		return p.cmd.Process.Pid
	}
	return 0
}

// Stop 先发送 SIGTERM，5 秒内未退出则 SIGKILL。
func (p *Process) Stop() error {
	p.mu.Lock()
	cmd, done := p.cmd, p.done
	if cmd == nil {
		p.mu.Unlock()
		return nil
	}
	p.stopping = true
	p.mu.Unlock()
	syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
	}
	p.Log.Info("gost 已停止")
	return nil
}

// Running 报告 gost 是否在运行。
func (p *Process) Running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cmd != nil
}

// Info 返回运行信息。
func (p *Process) Info() (running bool, pid int, since time.Time, lastErr string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.lastErr != nil {
		lastErr = p.lastErr.Error()
	}
	return p.cmd != nil, p.pidLocked(), p.started, lastErr
}

// Logs 返回最近的 gost 输出。
func (p *Process) Logs() []string { return p.ring.lines() }

func (p *Process) collect(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		p.ring.add(sc.Text())
	}
}

type ring struct {
	mu   sync.Mutex
	buf  []string
	next int
	full bool
}

func newRing(n int) *ring { return &ring{buf: make([]string, n)} }

func (r *ring) add(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf[r.next] = time.Now().Format("01-02 15:04:05 ") + s
	r.next = (r.next + 1) % len(r.buf)
	if r.next == 0 {
		r.full = true
	}
}

func (r *ring) lines() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.full {
		return append([]string(nil), r.buf[:r.next]...)
	}
	return append(append([]string(nil), r.buf[r.next:]...), r.buf[:r.next]...)
}

// Version 是 gost 的版本号。
type Version struct{ Major, Minor, Patch int }

func (v Version) String() string { return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch) }

// Less 判断 v 是否早于 o。
func (v Version) Less(o Version) bool {
	if v.Major != o.Major {
		return v.Major < o.Major
	}
	if v.Minor != o.Minor {
		return v.Minor < o.Minor
	}
	return v.Patch < o.Patch
}

// MinVersion 是经过验证的最低 gost 版本。
var MinVersion = Version{3, 3, 0}

var versionRE = regexp.MustCompile(`gost v?(\d+)\.(\d+)\.(\d+)`)

// ParseVersion 解析 `gost -V` 的输出，例如 "gost 3.3.1 (go1.26.3 linux/amd64)"。
func ParseVersion(out string) (Version, error) {
	m := versionRE.FindStringSubmatch(out)
	if m == nil {
		return Version{}, fmt.Errorf("无法识别 gost 版本: %.80q", strings.TrimSpace(out))
	}
	a, _ := strconv.Atoi(m[1])
	b, _ := strconv.Atoi(m[2])
	c, _ := strconv.Atoi(m[3])
	return Version{a, b, c}, nil
}

// CheckBinary 确认 gost 可执行并且版本满足要求。
func CheckBinary(ctx context.Context, bin string) (Version, error) {
	if _, err := os.Stat(bin); err != nil {
		return Version{}, fmt.Errorf("找不到 gost 可执行文件 %s: %w", bin, err)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "-V").CombinedOutput()
	if err != nil {
		return Version{}, fmt.Errorf("执行 %s -V 失败: %w", bin, err)
	}
	v, err := ParseVersion(string(out))
	if err != nil {
		return v, err
	}
	if v.Major != 3 {
		return v, fmt.Errorf("需要 gost v3，当前为 %s", v)
	}
	if v.Less(MinVersion) {
		return v, fmt.Errorf("gost %s 过旧，至少需要 %s", v, MinVersion)
	}
	return v, nil
}
