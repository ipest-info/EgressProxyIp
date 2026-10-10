package fw

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Runner 执行外部命令。生产环境使用 Exec，测试和 dry-run 使用替身。
type Runner interface {
	Run(ctx context.Context, stdin string, name string, args ...string) (string, error)
}

// Exec 直接执行命令。
type Exec struct{}

func (Exec) Run(ctx context.Context, stdin, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = strings.TrimSpace(out.String())
		}
		return out.String(), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, msg)
	}
	return out.String(), nil
}

// DryRun 只记录命令不执行；查询类命令一律返回“不存在”。
type DryRun struct {
	mu   sync.Mutex
	Cmds []string
}

func (d *DryRun) Run(_ context.Context, stdin, name string, args ...string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	line := name + " " + strings.Join(args, " ")
	if stdin != "" {
		line += " <<EOF\n" + stdin + "EOF"
	}
	d.Cmds = append(d.Cmds, line)
	for _, a := range args {
		if a == "-S" || a == "-C" || a == "show" {
			return "", errors.New("dry-run")
		}
	}
	return "", nil
}

// Backend 是一套 iptables 命令（legacy 或 nft 变体）。
type Backend struct {
	Name     string // "nft" 或 "legacy"
	IPT      string
	IPTRest  string
	IP6T     string
	IP6TRest string
}

// Firewall 下发和清理 egp 的规则。
type Firewall struct {
	R       Runner
	B       Backend
	Log     *slog.Logger
	HasIPv6 bool // ip6tables 是否可用
	// RequireIPv6 表示本机有全局 IPv6 地址，IPv6 规则下发失败必须视为错误。
	RequireIPv6 bool
}

func lookPath(names ...string) string {
	for _, n := range names {
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	return ""
}

// backendFor 返回指定变体的命令；变体专用的命令不存在时退回通用命令。
func backendFor(name string) Backend {
	b := Backend{Name: name}
	b.IPT = lookPath("iptables-"+name, "iptables")
	b.IPTRest = lookPath("iptables-"+name+"-restore", "iptables-restore")
	b.IP6T = lookPath("ip6tables-"+name, "ip6tables")
	b.IP6TRest = lookPath("ip6tables-"+name+"-restore", "ip6tables-restore")
	return b
}

func countRules(ctx context.Context, r Runner, save string) int {
	if save == "" {
		return -1
	}
	out, err := r.Run(ctx, "", save)
	if err != nil {
		return -1
	}
	n := 0
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "-A ") {
			n++
		}
	}
	return n
}

// DetectBackend 选择与系统中已有规则一致的 iptables 变体（参考 Kubernetes
// iptables-wrapper 的做法）：两套都有规则时选规则多的那套，都没有时跟随默认的 iptables。
func DetectBackend(ctx context.Context, r Runner) (Backend, error) {
	nftSave := lookPath("iptables-nft-save")
	legacySave := lookPath("iptables-legacy-save")
	if nftSave == "" && legacySave == "" {
		b := backendFor("nft")
		if b.IPT == "" || b.IPTRest == "" {
			return b, errors.New("找不到 iptables / iptables-restore，请先安装 iptables 软件包")
		}
		out, _ := r.Run(ctx, "", b.IPT, "-V")
		if !strings.Contains(out, "nf_tables") {
			b.Name = "legacy"
		}
		return b, nil
	}
	nft, legacy := countRules(ctx, r, nftSave), countRules(ctx, r, legacySave)
	name := "nft"
	switch {
	case legacy > nft:
		name = "legacy"
	case legacy == nft:
		if out, _ := r.Run(ctx, "", lookPath("iptables"), "-V"); out != "" && !strings.Contains(out, "nf_tables") {
			name = "legacy"
		}
	}
	b := backendFor(name)
	if b.IPT == "" || b.IPTRest == "" {
		return b, fmt.Errorf("找不到 iptables-%s 命令", name)
	}
	return b, nil
}

func (f *Firewall) ipt(v6 bool) (string, string) {
	if v6 {
		return f.B.IP6T, f.B.IP6TRest
	}
	return f.B.IPT, f.B.IPTRest
}

func (f *Firewall) run(ctx context.Context, name string, args ...string) (string, error) {
	return f.R.Run(ctx, "", name, args...)
}

func (f *Firewall) chainExists(ctx context.Context, v6 bool, table, chain string) bool {
	ipt, _ := f.ipt(v6)
	_, err := f.run(ctx, ipt, "-w", "5", "-t", table, "-S", chain)
	return err == nil
}

// Apply 让系统规则与 rs 一致：创建/刷新需要的链，删除不再需要的链，
// 并保证每条跳转在父链中只有一条且位于第 1 位。可重复执行。
func (f *Firewall) Apply(ctx context.Context, rs Ruleset) error {
	if err := f.applyFamily(ctx, false, rs.V4, rs.Jumps4, OwnedV4); err != nil {
		return err
	}
	if f.HasIPv6 {
		if err := f.applyFamily(ctx, true, rs.V6, rs.Jumps6, OwnedV6); err != nil {
			// 主机没有全局 IPv6 地址时不存在经 IPv6 泄露的风险，只告警不中断。
			if f.RequireIPv6 {
				return err
			}
			f.Log.Warn("IPv6 规则下发失败（本机没有全局 IPv6 地址，忽略）", "错误", err.Error())
		}
	} else if len(rs.V6) > 0 {
		if f.RequireIPv6 {
			return errors.New("本机有全局 IPv6 地址，但找不到 ip6tables，无法阻断 IPv6 出网")
		}
		f.Log.Warn("未找到 ip6tables，跳过 IPv6 阻断规则")
	}
	return f.applyPolicyRoute(ctx, rs)
}

func (f *Firewall) applyFamily(ctx context.Context, v6 bool, chains []Chain, jumps []Jump, owned []Chain) error {
	ipt, rest := f.ipt(v6)
	if ipt == "" || rest == "" {
		return errors.New("找不到 iptables 命令")
	}
	want := map[string]bool{}
	for _, c := range chains {
		want[c.Table+"/"+c.Name] = true
	}
	// 1. 先删除指向“不再需要的链”的跳转，以及所有重复或位置不对的 egp 跳转。
	if err := f.fixJumps(ctx, v6, jumps, want); err != nil {
		return err
	}
	// 2. 一次性下发需要的链（每张表一个事务）。
	if len(chains) > 0 {
		byTable := map[string][]Chain{}
		var tables []string
		for _, c := range chains {
			if _, ok := byTable[c.Table]; !ok {
				tables = append(tables, c.Table)
			}
			byTable[c.Table] = append(byTable[c.Table], c)
		}
		var b strings.Builder
		for _, t := range tables {
			fmt.Fprintf(&b, "*%s\n", t)
			for _, c := range byTable[t] {
				if f.chainExists(ctx, v6, t, c.Name) {
					fmt.Fprintf(&b, "-F %s\n", c.Name)
				} else {
					fmt.Fprintf(&b, "-N %s\n", c.Name)
				}
			}
			for _, c := range byTable[t] {
				for _, r := range c.Rules {
					fmt.Fprintf(&b, "-A %s %s\n", c.Name, strings.Join(r, " "))
				}
			}
			b.WriteString("COMMIT\n")
		}
		if _, err := f.R.Run(ctx, b.String(), rest, "-w", "5", "--noflush"); err != nil {
			return fmt.Errorf("下发 iptables 规则失败: %w", err)
		}
	}
	// 3. 插入跳转（链已存在之后才能插入）。
	for _, j := range jumps {
		if f.jumpOK(ctx, v6, j) {
			continue
		}
		f.deleteJump(ctx, v6, j)
		args := append([]string{"-w", "5", "-t", j.Table, "-I", j.Parent, "1"}, j.Args()...)
		if _, err := f.run(ctx, ipt, args...); err != nil {
			return fmt.Errorf("插入跳转规则失败: %w", err)
		}
	}
	// 4. 删除不再需要的链（先清空再删除，以解除链之间的引用）。
	var stale []Chain
	for _, c := range owned {
		if !want[c.Table+"/"+c.Name] && f.chainExists(ctx, v6, c.Table, c.Name) {
			stale = append(stale, c)
		}
	}
	for _, c := range stale {
		f.run(ctx, ipt, "-w", "5", "-t", c.Table, "-F", c.Name)
	}
	for _, c := range stale {
		if _, err := f.run(ctx, ipt, "-w", "5", "-t", c.Table, "-X", c.Name); err != nil {
			return fmt.Errorf("删除链 %s 失败: %w", c.Name, err)
		}
	}
	return nil
}

// parentRules 返回父链中的规则（`-S` 输出中 "-A" 开头的行，已拆分为参数）。
func (f *Firewall) parentRules(ctx context.Context, v6 bool, table, parent string) [][]string {
	ipt, _ := f.ipt(v6)
	out, err := f.run(ctx, ipt, "-w", "5", "-t", table, "-S", parent)
	if err != nil {
		return nil
	}
	var rules [][]string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "-A "+parent+" ") {
			rules = append(rules, splitArgs(strings.TrimPrefix(l, "-A "+parent+" ")))
		}
	}
	return rules
}

func isEGPJump(rule []string) bool {
	for i, a := range rule {
		if (a == "-j" || a == "-g") && i+1 < len(rule) && strings.HasPrefix(rule[i+1], "EGP") {
			return true
		}
	}
	return false
}

// sameRule 比较两条规则。`iptables -S` 会调整参数顺序（例如把 -m comment 放到 -j 之前），
// 所以按排序后的参数比较。
func sameRule(a, b []string) bool {
	norm := func(r []string) string {
		c := make([]string, len(r))
		for i, t := range r {
			c[i] = strings.Trim(t, `"`)
		}
		sort.Strings(c)
		return strings.Join(c, " ")
	}
	return norm(a) == norm(b)
}

// jumpOK 判断跳转是否已经是父链的第 1 条且只出现一次。
func (f *Firewall) jumpOK(ctx context.Context, v6 bool, j Jump) bool {
	rules := f.parentRules(ctx, v6, j.Table, j.Parent)
	if len(rules) == 0 || !sameRule(rules[0], j.Args()) {
		return false
	}
	for _, r := range rules[1:] {
		if sameRule(r, j.Args()) {
			return false
		}
	}
	return true
}

func (f *Firewall) deleteJump(ctx context.Context, v6 bool, j Jump) {
	ipt, _ := f.ipt(v6)
	for _, r := range f.parentRules(ctx, v6, j.Table, j.Parent) {
		if sameRule(r, j.Args()) {
			f.run(ctx, ipt, append([]string{"-w", "5", "-t", j.Table, "-D", j.Parent}, r...)...)
		}
	}
}

// fixJumps 删除不属于期望集合的 egp 跳转（指向已废弃的链，或规格已变化的旧跳转）。
func (f *Firewall) fixJumps(ctx context.Context, v6 bool, jumps []Jump, want map[string]bool) error {
	ipt, _ := f.ipt(v6)
	for _, p := range Parents {
		for _, r := range f.parentRules(ctx, v6, p.Table, p.Chain) {
			if !isEGPJump(r) {
				continue
			}
			keep := false
			for _, j := range jumps {
				if j.Table == p.Table && j.Parent == p.Chain && sameRule(r, j.Args()) {
					keep = true
				}
			}
			if !keep {
				if _, err := f.run(ctx, ipt, append([]string{"-w", "5", "-t", p.Table, "-D", p.Chain}, r...)...); err != nil {
					return fmt.Errorf("删除旧跳转失败: %w", err)
				}
			}
		}
	}
	return nil
}

func (f *Firewall) applyPolicyRoute(ctx context.Context, rs Ruleset) error {
	ipCmd := lookPath("ip")
	if ipCmd == "" {
		if rs.TProxy {
			return errors.New("找不到 ip 命令（iproute2），无法配置 UDP 透明代理的策略路由")
		}
		return nil
	}
	pref := strconv.Itoa(rs.Priority)
	table := strconv.Itoa(rs.Table)
	// 先删掉该优先级上的所有规则（最多 10 条，防止死循环），再按需添加。
	for i := 0; i < 10; i++ {
		if _, err := f.run(ctx, ipCmd, "-4", "rule", "del", "pref", pref); err != nil {
			break
		}
	}
	if !rs.TProxy {
		f.run(ctx, ipCmd, "-4", "route", "flush", "table", table)
		return nil
	}
	if _, err := f.run(ctx, ipCmd, "-4", "rule", "add", "pref", pref, "fwmark", markArg(rs.Mark), "lookup", table); err != nil {
		return fmt.Errorf("添加策略路由失败: %w", err)
	}
	if _, err := f.run(ctx, ipCmd, "-4", "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", table); err != nil {
		return fmt.Errorf("添加本地路由失败: %w", err)
	}
	return nil
}

// Cleanup 删除 egp 的全部规则和策略路由。
func (f *Firewall) Cleanup(ctx context.Context, settings Ruleset) error {
	return f.Apply(ctx, Ruleset{Mark: settings.Mark, Table: settings.Table, Priority: settings.Priority})
}

// CleanupAll 在 legacy 和 nft 两套 iptables 中凡是含有 egp 规则的都执行清理，用于卸载和手动恢复。
// 不含 egp 规则的那套不去触碰，避免在纯 nft 系统上初始化 legacy 表（会导致 iptables-save 告警）。
func CleanupAll(ctx context.Context, r Runner, log *slog.Logger, base Ruleset) error {
	var errs []error
	cleaned := false
	for _, name := range []string{"nft", "legacy"} {
		if lookPath("iptables-"+name) == "" {
			continue
		}
		has := false
		for _, save := range []string{"iptables-" + name + "-save", "ip6tables-" + name + "-save"} {
			if p := lookPath(save); p != "" {
				if out, err := r.Run(ctx, "", p); err == nil && strings.Contains(out, "EGP") {
					has = true
				}
			}
		}
		if !has {
			continue
		}
		b := backendFor(name)
		f := &Firewall{R: r, B: b, Log: log, HasIPv6: b.IP6T != "" && b.IP6TRest != ""}
		if err := f.Cleanup(ctx, base); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", b.Name, err))
		}
		cleaned = true
	}
	if !cleaned {
		// 没有 egp 的 iptables 规则时仍要清理可能残留的策略路由。
		f := &Firewall{R: r, Log: log}
		if err := f.applyPolicyRoute(ctx, Ruleset{Mark: base.Mark, Table: base.Table, Priority: base.Priority}); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Check 检查当前规则是否与 rs 一致（跳转在首位、链的规则数一致），用于发现漂移。
func (f *Firewall) Check(ctx context.Context, rs Ruleset) []string {
	var problems []string
	check := func(v6 bool, chains []Chain, jumps []Jump) {
		ipt, _ := f.ipt(v6)
		for _, j := range jumps {
			if !f.jumpOK(ctx, v6, j) {
				problems = append(problems, fmt.Sprintf("%s/%s 中的跳转 %s 缺失或不在首位", j.Table, j.Parent, strings.Join(j.Spec, " ")))
			}
		}
		for _, c := range chains {
			out, err := f.run(ctx, ipt, "-w", "5", "-t", c.Table, "-S", c.Name)
			if err != nil {
				problems = append(problems, fmt.Sprintf("链 %s 不存在", c.Name))
				continue
			}
			n := strings.Count(out, "-A "+c.Name+" ")
			if n != len(c.Rules) {
				problems = append(problems, fmt.Sprintf("链 %s 有 %d 条规则，期望 %d 条", c.Name, n, len(c.Rules)))
			}
		}
	}
	check(false, rs.V4, rs.Jumps4)
	// 没有全局 IPv6 地址时 IPv6 规则只是尽力而为，不检查漂移。
	if f.HasIPv6 && f.RequireIPv6 {
		check(true, rs.V6, rs.Jumps6)
	}
	return problems
}

// splitArgs 按空白拆分 `iptables -S` 的输出，支持双引号包裹的参数。
func splitArgs(s string) []string {
	var out []string
	var cur strings.Builder
	inQ, has := false, false
	for _, r := range s {
		switch {
		case r == '"':
			inQ = !inQ
			has = true
		case (r == ' ' || r == '\t') && !inQ:
			if has {
				out = append(out, cur.String())
				cur.Reset()
				has = false
			}
		default:
			cur.WriteRune(r)
			has = true
		}
	}
	if has {
		out = append(out, cur.String())
	}
	return out
}
