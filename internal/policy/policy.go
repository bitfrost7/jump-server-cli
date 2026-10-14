package policy

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed rules.default.yaml
var defaultRulesYAML []byte

const prodEnv = "prod"

// Mode 策略模式。
type Mode string

const (
	// ModeAudit 只判定、只记录，不拦截。用于灰度观察误报。
	ModeAudit Mode = "audit"
	// ModeEnforce 判定即拦截。
	ModeEnforce Mode = "enforce"
)

// Decision 判定结果。
type Decision string

const (
	Allow Decision = "allow"
	Warn  Decision = "warn"
	Deny  Decision = "deny"
)

// Verdict 一次判定的完整结论。
type Verdict struct {
	Decision Decision `json:"decision"`
	RuleID   string   `json:"rule_id,omitempty"`
	Severity string   `json:"severity,omitempty"`
	Reason   string   `json:"reason,omitempty"`
	Advice   string   `json:"advice,omitempty"`
	Detail   string   `json:"detail,omitempty"`
}

// Blocked 是否应当拒绝执行。
func (v Verdict) Blocked() bool { return v.Decision == Deny }

// Limits 命令整形阈值。
type Limits struct {
	MaxCommandLength  int `yaml:"max_command_length"`
	WarnCommandLength int `yaml:"warn_command_length"`
	WarnChainSegments int `yaml:"warn_chain_segments"`
	DenyChainSegments int `yaml:"deny_chain_segments"`
	InlineBase64Min   int `yaml:"inline_base64_min"`
}

// Rule 一条黑名单/提示规则。
type Rule struct {
	ID       string `yaml:"id"`
	Severity string `yaml:"severity"`
	Reason   string `yaml:"reason"`
	Advice   string `yaml:"advice"`
	Pattern  string `yaml:"pattern"`
}

// File 规则文件结构（内嵌默认 + 用户覆盖）。
type File struct {
	Version      int    `yaml:"version"`
	Limits       Limits `yaml:"limits"`
	ProdReadOnly *bool  `yaml:"prod_readonly"`
	Deny         []Rule `yaml:"deny"`
	Warn         []Rule `yaml:"warn"`
	ProdDeny     []Rule `yaml:"prod_deny"`
}

type compiledRule struct {
	Rule
	re *regexp.Regexp
}

// Engine 策略引擎。
type Engine struct {
	mode     Mode
	limits   Limits
	prodOnly bool
	deny     []compiledRule
	warn     []compiledRule
	// prodDeny 为用户自定义的生产环境补充规则（主判定在代码里）
	prodDeny []compiledRule
}

// New 构建引擎。userRulesPath 为空或文件不存在时只用内嵌默认规则。
func New(mode Mode, userRulesPath string) (*Engine, error) {
	if mode != ModeEnforce {
		mode = ModeAudit
	}
	f, err := loadFile(userRulesPath)
	if err != nil {
		return nil, err
	}
	e := &Engine{
		mode:     mode,
		limits:   f.Limits,
		prodOnly: f.ProdReadOnly == nil || *f.ProdReadOnly,
	}
	if e.deny, err = compile(f.Deny); err != nil {
		return nil, err
	}
	if e.warn, err = compile(f.Warn); err != nil {
		return nil, err
	}
	if e.prodDeny, err = compile(f.ProdDeny); err != nil {
		return nil, err
	}
	return e, nil
}

// Mode 返回当前模式。
func (e *Engine) Mode() Mode { return e.mode }

// Enforcing 当前是否真的拦截。
func (e *Engine) Enforcing() bool { return e.mode == ModeEnforce }

// Limits 返回整形阈值。
func (e *Engine) Limits() Limits { return e.limits }

// RuleCount 返回各类规则条数（用于 policy list）。
func (e *Engine) RuleCount() (deny, warn, prod int) {
	return len(e.deny), len(e.warn), len(e.prodDeny)
}

// ProdReadOnly 生产环境是否已开启只读。
func (e *Engine) ProdReadOnly() bool { return e.prodOnly }

// Describe 返回人类可读的规则清单（供 policy list 使用）。
func (e *Engine) Describe() string {
	var sb strings.Builder
	write := func(kind string, rules []compiledRule) {
		for _, r := range rules {
			fmt.Fprintf(&sb, "  [%-4s] %-9s %-24s %s\n", kind, r.Severity, r.ID, r.Reason)
		}
	}
	write("deny", e.deny)
	write("warn", e.warn)
	write("prod", e.prodDeny)
	return sb.String()
}

// Check 对一条命令给出判定。env 为空时按 test 处理。
func (e *Engine) Check(env, cmd string) Verdict {
	if strings.TrimSpace(cmd) == "" {
		return Verdict{Decision: Allow}
	}
	norm := Normalize(cmd)
	compact := Compact(norm)
	segments := ChainSegments(cmd)

	// ── 硬性整形上限（先于规则，避免超长串绕过正则）──
	if e.limits.MaxCommandLength > 0 && len(cmd) > e.limits.MaxCommandLength {
		return Verdict{
			Decision: Deny, RuleID: "LIMIT-001-length", Severity: "high",
			Reason: fmt.Sprintf("命令长度 %d 字符，超过上限 %d", len(cmd), e.limits.MaxCommandLength),
			Advice: "请拆分成多条简短命令；大文件请用 jump_upload，不要塞进命令行",
		}
	}
	if e.limits.DenyChainSegments > 0 && segments >= e.limits.DenyChainSegments {
		return Verdict{
			Decision: Deny, RuleID: "LIMIT-002-chain", Severity: "medium",
			Reason: fmt.Sprintf("命令串联了 %d 段，超过上限 %d", segments, e.limits.DenyChainSegments),
			Advice: "请拆成多条命令；需要连续执行请用 commands 参数（一次登录多条命令）",
		}
	}

	// ── 生产环境只读 ──
	if env == prodEnv && e.prodOnly {
		if v := e.checkProd(cmd, norm); v != nil {
			return *v
		}
	}

	// ── 黑名单（先展开解释器内联代码，再全文匹配）──
	if v := e.checkInlineCode(norm, 0); v != nil {
		return *v
	}
	if v := e.matchDeny(norm, compact); v != nil {
		return *v
	}

	// ── 自定义 prod 补充规则 ──
	if env == prodEnv {
		for _, r := range e.prodDeny {
			if hit := r.re.FindString(norm); hit != "" {
				return Verdict{
					Decision: Deny, RuleID: r.ID, Severity: r.Severity,
					Reason: r.Reason, Advice: r.Advice, Detail: "命中片段: " + hit,
				}
			}
		}
	}

	// ── 提示级 ──
	for _, r := range e.warn {
		if hit := r.re.FindString(norm); hit != "" {
			return Verdict{
				Decision: Warn, RuleID: r.ID, Severity: r.Severity,
				Reason: r.Reason, Advice: r.Advice, Detail: "命中片段: " + hit,
			}
		}
	}
	if e.limits.WarnChainSegments > 0 && segments >= e.limits.WarnChainSegments {
		return Verdict{
			Decision: Warn, RuleID: "LIMIT-003-chain", Severity: "low",
			Reason: fmt.Sprintf("命令串联了 %d 段", segments),
			Advice: "同质参数可以合并（ls -la a b c），不同目的建议拆开或改用 commands 参数",
		}
	}
	if e.limits.WarnCommandLength > 0 && len(cmd) > e.limits.WarnCommandLength {
		return Verdict{
			Decision: Warn, RuleID: "LIMIT-004-length", Severity: "low",
			Reason: fmt.Sprintf("命令长度 %d 字符，超过建议值 %d", len(cmd), e.limits.WarnCommandLength),
			Advice: "人类手敲命令很少超过 300 字符；请确认是否需要改用 jump_upload",
		}
	}

	return Verdict{Decision: Allow}
}

// ── 黑名单匹配 ──────────────────────────────────────────────────

// matchDeny 对给定文本跑全部黑名单规则。
//
// norm 先匹配；未命中时再用 compact（去掉全部空白）试一次，
// 用于捕获 `/dev/${IFS}tcp` 这类用空白变量拆分关键字的写法。
func (e *Engine) matchDeny(norm, compact string) *Verdict {
	for _, r := range e.deny {
		if hit := r.re.FindString(norm); hit != "" {
			return &Verdict{
				Decision: Deny, RuleID: r.ID, Severity: r.Severity,
				Reason: r.Reason, Advice: r.Advice, Detail: "命中片段: " + hit,
			}
		}
	}
	if compact != norm {
		for _, r := range e.deny {
			if hit := r.re.FindString(compact); hit != "" {
				return &Verdict{
					Decision: Deny, RuleID: r.ID, Severity: r.Severity,
					Reason: r.Reason, Advice: r.Advice,
					Detail: "命中片段: " + hit + "（检测到用空白拆分关键字）",
				}
			}
		}
	}
	return nil
}

// inlineCodeRE 匹配解释器的内联代码参数（bash -c '…'、python3 -c "…"）。
var inlineCodeRE = regexp.MustCompile(`(?i)(^|[|;&]{1,2}\s*)(bash|sh|zsh|ksh|dash|python3?|perl|ruby|node|php|awk)\b[^|;&]*\s-[a-z]*c\s+(.+)`)

// checkInlineCode 展开解释器内联代码后再判定。
//
// 不做这一步的话 `bash -c 'rm -rf /'` 就是一条万能绕过路径：
// 黑名单只在命令位置匹配，而危险命令藏在引号里。
// 只展开一层；嵌套解释器会因外层命中而被拦。
func (e *Engine) checkInlineCode(norm string, depth int) *Verdict {
	if depth > 0 {
		return nil
	}
	m := inlineCodeRE.FindStringSubmatch(norm)
	if m == nil {
		return nil
	}
	inner := strings.TrimSpace(m[3])
	if inner == "" {
		return nil
	}
	// 内联代码本身是一段新命令，从命令位置开始重新匹配
	if v := e.matchDeny(inner, Compact(inner)); v != nil {
		v.Detail = fmt.Sprintf("内联代码 %q 中：%s", preview(inner), v.Detail)
		return v
	}
	return nil
}

func preview(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 80 {
		return s[:80] + "…"
	}
	return s
}

// ── 生产环境只读（精确判定，避免 grep tar 这类参数误伤）─────────────

var prodFileWriteHeads = map[string]bool{
	"rm": true, "mv": true, "cp": true, "dd": true, "truncate": true,
	"shred": true, "install": true, "ln": true, "touch": true, "mkdir": true,
	"rmdir": true, "chmod": true, "chown": true, "chgrp": true, "chattr": true,
	"tee": true, "zip": true, "tar": true, "gzip": true, "unzip": true,
	"vi": true, "vim": true, "nano": true, "emacs": true,
}

var prodScriptHeads = map[string]bool{
	"bash": true, "sh": true, "zsh": true, "ksh": true, "csh": true,
	"python": true, "python3": true, "perl": true, "ruby": true,
	"node": true, "php": true, "expect": true,
}

var prodOtherHeads = map[string]bool{
	"sudo": true, "su": true, "doas": true, "pkexec": true,
	"kill": true, "pkill": true, "killall": true,
	"iptables": true, "ip6tables": true, "nft": true,
	"mount": true, "umount": true, "swapoff": true,
	"useradd": true, "usermod": true, "userdel": true, "groupadd": true, "gpasswd": true,
	"crontab": true, "at": true, "systemd-run": true,
	"reboot": true, "shutdown": true, "halt": true, "poweroff": true,
	"setenforce": true, "sysctl": true, "modprobe": true, "insmod": true, "rmmod": true,
	"lvcreate": true, "lvremove": true, "fdisk": true, "parted": true,
}

// prodHeadPairs 需要看第二个 token 的命令。
var prodHeadPairs = map[string]map[string]bool{
	"docker":    set("restart", "stop", "start", "kill", "rm", "rmi", "create", "run", "exec", "cp", "commit", "update", "build", "push", "tag", "load", "import"),
	"systemctl": set("restart", "stop", "start", "enable", "disable", "mask", "unmask", "daemon-reload"),
	"service":   set("restart", "stop", "start", "reload"),
	"yum":       set("install", "remove", "erase", "update", "upgrade", "reinstall"),
	"dnf":       set("install", "remove", "erase", "update", "upgrade"),
	"apt":       set("install", "remove", "purge", "update", "upgrade"),
	"apt-get":   set("install", "remove", "purge", "update", "upgrade"),
	"rpm":       set("-i", "-U", "-e", "--install", "--upgrade", "--erase"),
	"pip":       set("install", "uninstall"),
	"pip3":      set("install", "uninstall"),
	"npm":       set("install", "uninstall", "i", "rm", "update"),
	"gem":       set("install", "uninstall", "update"),
	"sed":       set("-i", "--in-place"),
}

func set(ss ...string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

var (
	sqlWriteRE   = regexp.MustCompile(`(?i)\b(insert\s+into|update\s+\S+\s+set|delete\s+from|drop\s+(table|database|index|view)|alter\s+table|truncate\s+table|create\s+(table|database|index|user)|grant\s+\S+\s+to|revoke\s+\S+\s+from|replace\s+into|rename\s+table)\b`)
	redisWriteRE = regexp.MustCompile(`\b(SET|SETEX|SETNX|DEL|UNLINK|FLUSHALL|FLUSHDB|RENAME|EXPIRE|PEXPIRE|LPUSH|RPUSH|LPOP|RPOP|SADD|SREM|HSET|HDEL|ZADD|ZREM|INCR|DECR|CONFIG\s+SET|SLAVEOF|REPLICAOF|SHUTDOWN|EVAL)\b`)
	// showOnlyRE 匹配只读的 SHOW 语句，匹配后从待检查文本里剔除。
	showOnlyRE = regexp.MustCompile(`(?i)\bshow\s+(create|index|indexes|keys|table\s+status|databases|tables|columns|full\s+columns|grants|variables|status|processlist|engine)\b`)
)

// checkProd 生产环境只读判定。返回 nil 表示放行。
func (e *Engine) checkProd(cmd, norm string) *Verdict {
	deny := func(id, reason, advice, detail string) *Verdict {
		return &Verdict{Decision: Deny, RuleID: id, Severity: "critical",
			Reason: reason, Advice: advice, Detail: detail}
	}

	for _, seg := range splitSegments(cmd) {
		tokens := strings.Fields(seg)
		if len(tokens) == 0 {
			continue
		}
		head := filepath.Base(tokens[0])

		if prodFileWriteHeads[head] {
			return deny("PROD-001-file-write",
				"生产环境禁止写文件（"+head+"）",
				"生产变更走发布流程；如需查看文件请用 cat/ls/grep 等只读命令",
				"命令: "+tokens[0])
		}
		if prodScriptHeads[head] {
			return deny("PROD-002-script-exec",
				"生产环境禁止执行脚本/内联代码（"+head+"），无法审计其内部行为",
				"如需执行，请走发布流程；只读查询请用具体命令",
				"命令: "+tokens[0])
		}
		if prodOtherHeads[head] {
			return deny("PROD-003-privileged",
				"生产环境禁止该操作（"+head+"）",
				"请走变更流程",
				"命令: "+tokens[0])
		}
		if sub, ok := prodHeadPairs[head]; ok && len(tokens) > 1 && sub[tokens[1]] {
			return deny("PROD-004-service-change",
				"生产环境禁止变更服务/容器/软件包（"+head+" "+tokens[1]+"）",
				"生产变更走发布流程；只读查看请用 docker ps / docker logs / systemctl status",
				"命令: "+head+" "+tokens[1])
		}
	}

	// 重定向写文件（/dev/null 无害）
	for _, t := range redirectTargets(cmd) {
		if t == "/dev/null" || t == "/dev/stderr" || t == "/dev/stdout" || strings.HasPrefix(t, "&") {
			continue
		}
		return deny("PROD-005-redirect-write",
			"生产环境禁止重定向写文件",
			"生产变更走发布流程",
			"目标: "+t)
	}

	// SQL 写入（仅限 SQL 上下文，避免 grep 到 SQL 关键字误伤）
	if isSQLContext(norm) {
		// 先剥掉只读的 SHOW 语句：`SHOW CREATE TABLE x` 里的 create 不是 DDL
		scan := showOnlyRE.ReplaceAllString(norm, " ")
		if hit := sqlWriteRE.FindString(scan); hit != "" {
			return deny("PROD-006-sql-write",
				"生产数据库写操作",
				"生产库只读；变更请走 DBA 流程",
				"命中 SQL: "+hit)
		}
	}
	// Redis 写入
	if strings.Contains(norm, "redis-cli") {
		if hit := redisWriteRE.FindString(norm); hit != "" {
			return deny("PROD-007-redis-write",
				"生产 Redis 写操作",
				"生产缓存只读",
				"命中命令: "+hit)
		}
	}

	// 内嵌大块 base64（绕过审计通道的自动化上传特征）
	if e.limits.InlineBase64Min > 0 && hasInlineBase64(norm, e.limits.InlineBase64Min) {
		return deny("PROD-008-inline-base64",
			"生产环境禁止命令行内嵌大块 base64",
			"请使用 jump_upload / jump_download 传输文件",
			"")
	}
	return nil
}

func isSQLContext(norm string) bool {
	return strings.Contains(norm, "easysql") ||
		strings.Contains(norm, "mysql") ||
		strings.Contains(norm, "psql") ||
		strings.Contains(norm, "sqlplus") ||
		strings.Contains(norm, "mariadb")
}

// hasInlineBase64 检测命令行内嵌的长 base64 串。
func hasInlineBase64(norm string, min int) bool {
	for _, f := range strings.Fields(norm) {
		if len(f) < min {
			continue
		}
		ok := true
		for _, c := range f {
			if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' ||
				c >= '0' && c <= '9' || c == '+' || c == '/' || c == '=') {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// splitSegments 按 ; && || | 切分命令，引号内不切。
func splitSegments(cmd string) []string {
	var out []string
	var quote byte
	start := 0
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		if c == '\\' {
			i++
			continue
		}
		if c == ';' || c == '&' || c == '|' {
			out = append(out, strings.TrimSpace(cmd[start:i]))
			if i+1 < len(cmd) && cmd[i+1] == c {
				i++
			}
			start = i + 1
		}
	}
	out = append(out, strings.TrimSpace(cmd[start:]))
	return out
}

// ── 规则加载 ────────────────────────────────────────────────────

func loadFile(userPath string) (File, error) {
	var f File
	if err := yaml.Unmarshal(defaultRulesYAML, &f); err != nil {
		return f, fmt.Errorf("解析内嵌默认规则失败: %w", err)
	}
	if userPath == "" {
		return f, nil
	}
	b, err := os.ReadFile(userPath)
	if err != nil {
		if os.IsNotExist(err) {
			return f, nil // 未提供覆盖文件，用默认
		}
		return f, fmt.Errorf("读取规则文件 %s 失败: %w", userPath, err)
	}
	var u File
	if err := yaml.Unmarshal(b, &u); err != nil {
		return f, fmt.Errorf("解析规则文件 %s 失败: %w", userPath, err)
	}
	mergeFile(&f, u)
	return f, nil
}

// mergeFile 用户文件覆盖默认：limits 非零覆盖，prod_readonly 显式覆盖，规则按 id 覆盖。
func mergeFile(base *File, user File) {
	l := &base.Limits
	if user.Limits.MaxCommandLength > 0 {
		l.MaxCommandLength = user.Limits.MaxCommandLength
	}
	if user.Limits.WarnCommandLength > 0 {
		l.WarnCommandLength = user.Limits.WarnCommandLength
	}
	if user.Limits.WarnChainSegments > 0 {
		l.WarnChainSegments = user.Limits.WarnChainSegments
	}
	if user.Limits.DenyChainSegments > 0 {
		l.DenyChainSegments = user.Limits.DenyChainSegments
	}
	if user.Limits.InlineBase64Min > 0 {
		l.InlineBase64Min = user.Limits.InlineBase64Min
	}
	if user.ProdReadOnly != nil {
		base.ProdReadOnly = user.ProdReadOnly
	}
	base.Deny = mergeRules(base.Deny, user.Deny)
	base.Warn = mergeRules(base.Warn, user.Warn)
	base.ProdDeny = mergeRules(base.ProdDeny, user.ProdDeny)
}

func mergeRules(base, over []Rule) []Rule {
	for _, r := range over {
		replaced := false
		for i := range base {
			if base[i].ID == r.ID {
				base[i] = r
				replaced = true
				break
			}
		}
		if !replaced {
			base = append(base, r)
		}
	}
	return base
}

func compile(rules []Rule) ([]compiledRule, error) {
	out := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		if r.Pattern == "" {
			return nil, fmt.Errorf("规则 %s 缺少 pattern", r.ID)
		}
		re, err := regexp.Compile("(?i)" + r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("规则 %s 正则无效: %w", r.ID, err)
		}
		out = append(out, compiledRule{Rule: r, re: re})
	}
	return out, nil
}
