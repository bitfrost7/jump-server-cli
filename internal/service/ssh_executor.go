package service

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/bitfrost7/jump-server-cli/config"
)

var (
	ansiRE   = regexp.MustCompile(`\x1b\[[0-9;?]*[a-zA-Z]`)
	oscRE    = regexp.MustCompile(`\x1b\][^\x07]*\x07`)
	promptRE = regexp.MustCompile(`^\[?[a-zA-Z0-9_.-]+(@[a-zA-Z0-9_.-]+)?[^\$#]*[\$#]\s*`)
)

// isNoiseLine 判断清理后的行是否为 PTY/受限 shell 噪音（横幅、指纹警告、提示等）。
func isNoiseLine(t string) bool {
	if t == "logout" || t == "exit" {
		return true
	}
	for _, p := range []string{
		"Last login:",
		"Shared connection",
		"Warning: Permanently added",
		"Authenticated to",
		"You are in a limited shell.",
		"Type '?' or 'help'",
	} {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	if strings.HasPrefix(t, "Connection to ") && strings.HasSuffix(t, " closed.") {
		return true
	}
	return false
}

type SSHExecutor struct {
	cfg config.SSHConfig
}

func NewSSHExecutor(cfg config.SSHConfig) *SSHExecutor {
	return &SSHExecutor{cfg: cfg}
}

func (s *SSHExecutor) ResolveBastionHostname(env string) string {
	return resolveHostname(s.cfg.BastionForEnv(env).Host)
}

// SocketPath 返回指定环境跳板机的 ControlMaster socket 路径（~ 自动展开）。
func (s *SSHExecutor) SocketPath(env string) (string, error) {
	sp := s.cfg.SocketPattern
	if sp == "" {
		return "", fmt.Errorf("socket_pattern 未配置")
	}
	be := s.cfg.BastionForEnv(env)
	realHost := resolveHostname(be.Host)
	p := strings.ReplaceAll(strings.ReplaceAll(sp, "{user}", be.User), "{host}", realHost)
	if strings.HasPrefix(p, "~/") {
		home, _ := os.UserHomeDir()
		p = filepath.Join(home, p[2:])
	}
	return p, nil
}

// CheckSocket 检查免密长连接（ControlMaster socket）是否已建立。
// 跳板机服务端仅支持密码认证，日常免密依赖该 socket；未建立时返回带指引的错误。
func (s *SSHExecutor) CheckSocket(env string) error {
	sp := s.cfg.SocketPattern
	if sp == "" || s.cfg.SkipSocketCheck {
		return nil
	}
	socketPath, err := s.SocketPath(env)
	if err != nil {
		return err
	}
	be := s.cfg.BastionForEnv(env)
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		return fmt.Errorf("未建立免密长连接（ControlMaster socket 不存在: %s）\n请先执行 `jump-server connect`（或 `ssh %s`）输入一次密码建立连接，4 小时内免密", socketPath, be.Host)
	}
	return nil
}

func (s *SSHExecutor) Execute(ctx context.Context, user, host, cmd, env string) (string, error) {
	be := s.cfg.BastionForEnv(env)
	if user == "" {
		user = be.TargetUser
		if user == "" {
			user = s.cfg.DefaultUser
		}
	}
	if be.Mode == "proxyjump" {
		return s.execProxyJump(ctx, user, host, cmd, be)
	}
	return s.execPipe(ctx, user, host, cmd, be)
}

func (s *SSHExecutor) ExecuteDirect(ctx context.Context, user, host, cmd string) (string, error) {
	return s.execDirectMany(ctx, user, host, []string{cmd}, 0, 0)
}

// ExecuteBatch 按顺序执行多条命令。
//
// host 为空表示在跳板机本身执行（user 为跳板机登录用户），
// host 非空表示经跳板机到目标主机执行（user 为空时自动解析）。
//
// gapMin/gapMax 为命令之间的随机间隔：
//   - 在跳板机上执行时逐行下发，间隔生效（上游 PTY 会话）；
//   - 到目标主机执行时用一次 heredoc 连续下发，
//     多条命令落在同一个 shell 会话里，审计上是连续的 N 行——
//     这正是人类登录后逐条敲命令的形态。
//
// 目的：把「一次调用一条命令、短间隔反复调用」改为「一次调用完成一组查询」，
// 既降低调用频次，也让跳板机侧的命令历史更像人在操作。
func (s *SSHExecutor) ExecuteBatch(ctx context.Context, env, host, user string, cmds []string, gapMin, gapMax time.Duration) (string, error) {
	cmds = trimEmpty(cmds)
	if len(cmds) == 0 {
		return "", nil
	}
	be := s.cfg.BastionForEnv(env)

	// 目标：跳板机本身
	if host == "" {
		if user == "" {
			user = be.User
		}
		if len(cmds) == 1 {
			gapMin, gapMax = 0, 0 // 单条命令无需批内间隔
		}
		return s.execDirectMany(ctx, user, be.Host, cmds, gapMin, gapMax)
	}

	// 目标：跳板机之后的主机（一次登录，多条命令连续下发）
	return s.Execute(ctx, user, host, strings.Join(cmds, "\n"), env)
}

func trimEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimRight(s, "\n")
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

// execDirectMany 在跳板机上执行 1..N 条命令，命令之间按 [gapMin,gapMax] 随机等待。
func (s *SSHExecutor) execDirectMany(ctx context.Context, user, host string, cmds []string, gapMin, gapMax time.Duration) (string, error) {
	if user == "" {
		user = s.cfg.DefaultUser
	}
	to := s.timeout()
	c, cancel := context.WithTimeout(ctx, to)
	defer cancel()

	sshCmd := exec.CommandContext(c, "ssh",
		"-tt",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "BatchMode=yes", // 禁止交互式密码输入：无长连接时快速失败，而不是卡住/弹密码
		"-o", fmt.Sprintf("ConnectTimeout=%d", s.cfg.ConnectTimeout),
		fmt.Sprintf("%s@%s", user, host),
	)
	// 用标记行区分 PTY 输出，stripPTY 截取标记后的内容
	marker := "===JUMPEXEC==="
	var buf syncWriter
	sshCmd.Stdout = &buf
	sshCmd.Stderr = &buf

	stdin, err := sshCmd.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("建立 stdin 管道失败: %w", err)
	}
	if err := sshCmd.Start(); err != nil {
		return "", fmt.Errorf("启动 ssh 失败: %w", err)
	}

	// 标记行与命令分开下发：标记只用于本地区分 PTY 回显，不污染命令本身。
	fmt.Fprintf(stdin, "echo '%s'\n", marker)
	for i, cmd := range cmds {
		fmt.Fprintf(stdin, "%s\n", cmd)
		if i < len(cmds)-1 {
			sleepRand(c, gapMin, gapMax)
		}
	}
	fmt.Fprintln(stdin, "exit")
	stdin.Close()

	waitErr := sshCmd.Wait()
	out := buf.String()
	cleaned := stripPTY(out, marker, strings.Join(cmds, "\n"))
	if !strings.Contains(out, marker) {
		// 标记行未出现在输出中：命令根本没被执行（无长连接、或登录被拒）
		return cleaned, fmt.Errorf("命令未在 %s 上执行（未建立免密长连接或登录被拒）\n请先执行 `jump-server connect` 建立免密长连接", host)
	}
	_ = waitErr // PTY + sudosh 可能返回非零退出码，但输出有效
	return cleaned, nil
}

// syncWriter 串行化 stdout/stderr 的写入，避免 os/exec 的两个拷贝 goroutine 竞争。
type syncWriter struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func (w *syncWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}

// sleepRand 等待 [min,max) 内的随机时长；ctx 取消时立即返回。
func sleepRand(ctx context.Context, min, max time.Duration) {
	if max <= 0 {
		return
	}
	d := min
	if max > min {
		d = min + time.Duration(rand.Int63n(int64(max-min)))
	}
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

func (s *SSHExecutor) execPipe(ctx context.Context, user, host, cmd string, be config.BastionEntry) (string, error) {
	if user == "" {
		user = be.TargetUser
		if user == "" {
			user = s.cfg.DefaultUser
		}
	}
	to := s.timeout()
	timeoutStr := fmt.Sprintf("%d", s.cfg.ConnectTimeout)
	marker := "===JUMPEXEC==="
	// 使用 -tt + heredoc 绕过目标主机 sudosh 限制
	inner := fmt.Sprintf("echo '%s'\nssh -tt -o StrictHostKeyChecking=no -o ConnectTimeout=%s %s@%s <<'JUMPINNER'\n%s\nexit\nJUMPINNER\nexit",
		marker, timeoutStr, user, host, cmd)

	c, cancel := context.WithTimeout(ctx, to)
	defer cancel()

	sshCmd := exec.CommandContext(c, "ssh",
		"-tt",
		"-o", "StrictHostKeyChecking=no",
		"-o", "BatchMode=yes", // 同上：依赖免密长连接，未建立时快速失败
		"-o", fmt.Sprintf("ConnectTimeout=%s", timeoutStr),
		be.Host,
	)
	sshCmd.Stdin = strings.NewReader(inner + "\n")

	out, err := sshCmd.CombinedOutput()
	cleaned := stripPTY(string(out), marker, cmd)
	if err != nil {
		return cleaned, nil
	}
	return cleaned, nil
}

func (s *SSHExecutor) execProxyJump(ctx context.Context, user, host, cmd string, be config.BastionEntry) (string, error) {
	if user == "" {
		user = be.TargetUser
		if user == "" {
			user = s.cfg.DefaultUser
		}
	}
	to := s.timeout()
	c, cancel := context.WithTimeout(ctx, to)
	defer cancel()

	out, err := exec.CommandContext(c, "ssh",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "BatchMode=yes",
		"-o", fmt.Sprintf("ConnectTimeout=%d", s.cfg.ConnectTimeout),
		"-o", fmt.Sprintf("ProxyJump=%s@%s", be.User, be.Host),
		fmt.Sprintf("%s@%s", user, host), cmd,
	).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("proxyjump ssh: %w", err)
	}
	return string(out), nil
}

func (s *SSHExecutor) timeout() time.Duration {
	return time.Duration(s.cfg.ExecTimeout) * time.Second
}

func resolveHostname(alias string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ssh", "-G", alias).Output()
	if err != nil {
		return alias
	}
	s := bufio.NewScanner(strings.NewReader(string(out)))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if strings.HasPrefix(line, "hostname ") {
			if hn := strings.TrimSpace(strings.TrimPrefix(line, "hostname ")); hn != "" {
				return hn
			}
		}
	}
	return alias
}

func stripPTY(output, marker, cmd string) string {
	// 去除 ANSI 转义序列（含 ? 前缀的 CSI，如 [?1034h）
	s := ansiRE.ReplaceAllString(output, "")
	s = oscRE.ReplaceAllString(s, "")

	cleanLine := func(line string, skipCmdEcho bool) (string, bool) {
		cleaned := promptRE.ReplaceAllString(line, "")
		ct := strings.TrimSpace(cleaned)
		// 剥掉 heredoc 续行提示符（> > >）
		for strings.HasPrefix(ct, "> ") {
			ct = strings.TrimSpace(ct[2:])
		}
		if ct == "" || isNoiseLine(ct) {
			return "", false
		}
		if skipCmdEcho && cmd != "" && ct == strings.TrimSpace(cmd) {
			return "", false // PTY 回显的命令本身
		}
		return ct, true
	}

	// 按标记行截取：取最后一个 marker（PTY 会回显 echo 命令本身，首个 marker 可能在回显中）
	idx := strings.LastIndex(s, marker)
	if idx < 0 {
		// 找不到标记，回退到通用清理（不跳过命令回显，保守处理）
		lines := strings.Split(s, "\n")
		var clean []string
		for _, line := range lines {
			if ct, ok := cleanLine(line, false); ok {
				clean = append(clean, ct)
			}
		}
		return strings.TrimSpace(strings.Join(clean, "\n"))
	}

	// 取标记行后的内容
	after := s[idx+len(marker):]
	lines := strings.Split(after, "\n")
	var clean []string
	for _, line := range lines {
		if ct, ok := cleanLine(line, true); ok {
			clean = append(clean, ct)
		}
	}
	return strings.TrimSpace(strings.Join(clean, "\n"))
}
