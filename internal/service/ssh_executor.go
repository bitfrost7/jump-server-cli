package service

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
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

func (s *SSHExecutor) CheckSocket(env string) error {
	sp := s.cfg.SocketPattern
	if sp == "" {
		return nil
	}
	be := s.cfg.BastionForEnv(env)
	realHost := resolveHostname(be.Host)
	socketPath := strings.ReplaceAll(strings.ReplaceAll(sp, "{user}", be.User), "{host}", realHost)
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		return fmt.Errorf("SSH ControlMaster socket 不存在: %s\n请先执行 `ssh %s` 建立连接", socketPath, be.Host)
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
		"-o", fmt.Sprintf("ConnectTimeout=%d", s.cfg.ConnectTimeout),
		fmt.Sprintf("%s@%s", user, host),
	)
	// 用标记行区分 PTY 输出，stripPTY 截取标记后的内容
	marker := "===JUMPEXEC==="
	stdin, _ := sshCmd.StdinPipe()
	stdin.Write([]byte(fmt.Sprintf("echo '%s' && %s; exit\n", marker, cmd)))
	stdin.Close()

	out, err := sshCmd.CombinedOutput()
	cleaned := stripPTY(string(out), marker, cmd)
	if err != nil {
		return cleaned, nil // PTY+sudosh 可能返回非零退出码，但输出有效
	}
	return cleaned, nil
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
