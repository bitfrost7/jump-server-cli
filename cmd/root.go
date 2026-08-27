package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bitfrost7/jump-server-cli/config"
	"github.com/bitfrost7/jump-server-cli/internal/service"
	"github.com/bitfrost7/jump-server-cli/pkg/audit"
	"github.com/bitfrost7/jump-server-cli/pkg/store"

	"github.com/spf13/cobra"
)

var (
	cfgFile      string
	envFlag      string
	hostFlag     string
	cmdFlag      string
	uploadFlag   string
	downloadFlag string
)

var defaultConfigPath = func() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "config.yaml"
	}
	return filepath.Join(home, ".local", "jump-server", "config.yaml")
}()

var rootCmd = &cobra.Command{
	Use:   "jump-server",
	Short: "SSH/SCP 远程执行工具",
	Long: `通过中转服务器执行 SSH 命令或传输文件。

支持多环境（test/prod）、远程主机中转，无需白名单。`,
	Example: `  jump-server doctor
  jump-server -e prod -c "systemctl status nginx"
  jump-server -h 10.0.0.5 -c 'docker ps'
  jump-server --upload ./local.txt:/remote/path/file.txt
  jump-server --download /remote/path/file.txt:./local.txt
  jump-server -e prod -h db01 --upload ./dump.sql:/tmp/dump.sql`,

	Args: cobra.NoArgs,
	RunE: runJump,

	SilenceUsage: true,
}

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	rootCmd.Flags().BoolP("help", "", false, "显示帮助")

	rootCmd.Flags().StringVarP(&envFlag, "env", "e", "test",
		"环境 (test/prod)")
	rootCmd.Flags().StringVarP(&hostFlag, "host", "h", "",
		"中转之后的目标主机，不指定则在中转服务器上操作")
	rootCmd.Flags().StringVarP(&cmdFlag, "cmd", "c", "",
		"要执行的命令")
	rootCmd.Flags().StringVar(&uploadFlag, "upload", "",
		"上传文件，格式 local_path:remote_path")
	rootCmd.Flags().StringVar(&downloadFlag, "download", "",
		"下载文件，格式 remote_path:local_path")
	rootCmd.Flags().StringVar(&cfgFile, "config", defaultConfigPath,
		"配置文件路径")

	rootCmd.MarkFlagsOneRequired("cmd", "upload", "download")
	rootCmd.MarkFlagsMutuallyExclusive("upload", "download")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runJump(cmd *cobra.Command, args []string) error {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("加载配置失败: %w", err)
	}
	slog.Debug("配置已加载", "path", cfgFile)

	dbPath := expandPath(cfg.Store.Path)
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return fmt.Errorf("创建存储目录失败: %w", err)
	}
	st, err := store.New(dbPath)
	if err != nil {
		return fmt.Errorf("初始化状态存储失败: %w", err)
	}
	defer st.Close()
	slog.Debug("状态存储已打开", "path", dbPath)

	sshExec := service.NewSSHExecutor(cfg.SSH)
	bastion := cfg.SSH.BastionForEnv(envFlag)
	ctx := context.Background()

	if cmdFlag != "" {
		return runCmd(ctx, cfg, sshExec, bastion, st)
	}

	if uploadFlag != "" {
		return runTransfer(ctx, cfg, bastion, st, "upload")
	}
	if downloadFlag != "" {
		return runTransfer(ctx, cfg, bastion, st, "download")
	}

	return nil
}

func runCmd(ctx context.Context, cfg config.Config, sshExec *service.SSHExecutor, bastion config.BastionEntry, st *store.Store) error {
	if err := enforceRateLimit(st, cfg.Ratelimit, envFlag, hostFlag, cmdFlag); err != nil {
		audit.Log(cfg.Audit.Dir, audit.Entry{
			Tool: "jump_exec", User: targetUserOf(cfg, bastion, hostFlag),
			Host: hostFlag, Command: cmdFlag, Env: envFlag,
			Allowed: false, Error: err.Error(),
		})
		return err
	}
	// 跳板机仅支持密码认证，日常免密依赖 ControlMaster 长连接；未建立时直接给出指引
	if err := sshExec.CheckSocket(envFlag); err != nil {
		return err
	}
	start := time.Now()

	var output string
	var execErr error
	if hostFlag != "" {
		slog.Info("通过中转执行命令到目标主机", "host", hostFlag, "env", envFlag)
		output, execErr = sshExec.Execute(ctx, "", hostFlag, cmdFlag, envFlag)
	} else {
		slog.Info("执行命令", "host", bastion.Host)
		output, execErr = sshExec.ExecuteDirect(ctx, bastion.User, bastion.Host, cmdFlag)
	}
	dur := time.Since(start)

	success := execErr == nil
	audit.Log(cfg.Audit.Dir, audit.Entry{
		Tool: "jump_exec", User: targetUserOf(cfg, bastion, hostFlag),
		Host: hostFlag, Command: cmdFlag, Env: envFlag,
		Allowed: true, Success: &success,
		Output: truncateOutput(output, 2048), Error: errString(execErr),
		Duration: dur.String(),
	})

	if execErr != nil {
		slog.Warn("命令执行有错误信息", "error", execErr, "duration", dur)
	}
	fmt.Println(output)
	return nil
}

func runTransfer(ctx context.Context, cfg config.Config, bastion config.BastionEntry, st *store.Store, mode string) error {
	var localPath, remotePath string
	if mode == "upload" {
		parts := strings.SplitN(uploadFlag, ":", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return fmt.Errorf("--upload 格式错误，应为 local_path:remote_path")
		}
		localPath, remotePath = parts[0], parts[1]
	} else {
		parts := strings.SplitN(downloadFlag, ":", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return fmt.Errorf("--download 格式错误，应为 remote_path:local_path")
		}
		remotePath, localPath = parts[0], parts[1]
	}

	start := time.Now()
	scpExec := service.NewSCPExecutor(bastion.Host, cfg.SCP.DefaultUser,
		time.Duration(cfg.SCP.ConnectTimeout)*time.Second)
	sshExec := service.NewSSHExecutor(cfg.SSH)

	transferDesc := fmt.Sprintf("%s %s -> %s", mode, localPath, remotePath)
	if hostFlag != "" {
		transferDesc = fmt.Sprintf("%s via %s %s -> %s (target=%s)", mode, bastion.Host, localPath, remotePath, hostFlag)
	}

	if err := enforceRateLimit(st, cfg.Ratelimit, envFlag, hostFlag, transferDesc); err != nil {
		audit.Log(cfg.Audit.Dir, audit.Entry{
			Tool: "jump_transfer", User: targetUserOf(cfg, bastion, hostFlag),
			Host: hostFlag, Command: transferDesc, Env: envFlag,
			Allowed: false, Error: err.Error(),
		})
		return err
	}

	var logErr string
	var success bool

	if mode == "upload" {
		if hostFlag != "" {
			logErr = doUploadViaJump(ctx, cfg, bastion, localPath, remotePath, hostFlag, scpExec, sshExec)
		} else {
			_, err := scpExec.CopyToBastion(ctx, localPath, remotePath)
			if err != nil {
				logErr = err.Error()
			}
		}
	} else {
		if hostFlag != "" {
			logErr = doDownloadViaJump(ctx, cfg, bastion, remotePath, localPath, hostFlag, scpExec, sshExec)
		} else {
			_, err := scpExec.CopyFromBastion(ctx, remotePath, localPath)
			if err != nil {
				logErr = err.Error()
			}
		}
	}

	success = logErr == ""
	dur := time.Since(start)
	audit.Log(cfg.Audit.Dir, audit.Entry{
		Tool: "jump_transfer", User: targetUserOf(cfg, bastion, hostFlag),
		Host: hostFlag, Command: transferDesc, Env: envFlag,
		Allowed: true, Success: &success,
		Error: logErr, Duration: dur.String(),
	})

	if logErr != "" {
		return fmt.Errorf("传输失败: %s", logErr)
	}
	slog.Info("传输成功", "duration", dur)
	return nil
}

func doUploadViaJump(ctx context.Context, cfg config.Config, bastion config.BastionEntry, localPath, remotePath, targetHost string, scpExec *service.SCPExecutor, sshExec *service.SSHExecutor) string {
	targetUser := bastion.TargetUser
	if targetUser == "" {
		targetUser = cfg.SSH.DefaultUser
	}
	data, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Sprintf("读取本地文件失败: %v", err)
	}
	b64 := base64.StdEncoding.EncodeToString(data)
	cmd := fmt.Sprintf("echo '%s' | base64 -d > '%s'", b64, remotePath)
	_, err = sshExec.Execute(ctx, targetUser, targetHost, cmd, envFlag)
	if err != nil {
		return fmt.Sprintf("通过 PTY 写入目标主机失败: %v", err)
	}
	return ""
}

func doDownloadViaJump(ctx context.Context, cfg config.Config, bastion config.BastionEntry, remotePath, localPath, targetHost string, scpExec *service.SCPExecutor, sshExec *service.SSHExecutor) string {
	targetUser := bastion.TargetUser
	if targetUser == "" {
		targetUser = cfg.SSH.DefaultUser
	}
	cmd := fmt.Sprintf("base64 '%s'", remotePath)
	output, err := sshExec.Execute(ctx, targetUser, targetHost, cmd, envFlag)
	if err != nil {
		return fmt.Sprintf("读取目标主机文件失败: %v", err)
	}
	b64Data := extractBase64(output)
	if b64Data == "" {
		return fmt.Sprintf("未找到 base64 数据，原始输出: %s", output[:min(len(output), 300)])
	}
	decoded, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return fmt.Sprintf("base64 解码失败: %v，提取的数据: %s", err, b64Data[:min(len(b64Data), 100)])
	}
	if err := os.WriteFile(localPath, decoded, 0644); err != nil {
		return fmt.Sprintf("写入本地文件失败: %v", err)
	}
	return ""
}

func extractBase64(s string) string {
	lines := strings.Split(s, "\n")
	var b64Lines []string
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if t == "" || len(t) < 10 {
			continue
		}
		isB64 := true
		for _, c := range t {
			if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
				isB64 = false
				break
			}
		}
		if isB64 {
			b64Lines = append(b64Lines, t)
		}
	}
	return strings.Join(b64Lines, "")
}

func cleanupJumpFile(ctx context.Context, sshExec *service.SSHExecutor, bastion config.BastionEntry, path string) {
	if _, err := sshExec.ExecuteDirect(ctx, bastion.User, bastion.Host, fmt.Sprintf("rm -f %s", path)); err != nil {
		slog.Warn("清理中转临时文件失败", "path", path, "error", err)
	}
}

func expandPath(p string) string {
	if strings.HasPrefix(p, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, p[2:])
	}
	return p
}

func truncateOutput(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + fmt.Sprintf("\n... (截断 %d 字节)", len(s)-max)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// targetUserOf 返回目标主机登录用户（host 为空时返回跳板机用户）。
func targetUserOf(cfg config.Config, bastion config.BastionEntry, host string) string {
	if host == "" {
		return bastion.User
	}
	if bastion.TargetUser != "" {
		return bastion.TargetUser
	}
	return cfg.SSH.DefaultUser
}

// enforceRateLimit 全局令牌桶 + 同命令冷却（跨进程持久化在 SQLite）。
func enforceRateLimit(st *store.Store, rl config.RatelimitConfig, env, host, cmd string) error {
	if !rl.Enabled {
		return nil
	}
	now := time.Now().Unix()
	hash := rateLimitHash(env, host, cmd)

	// 命令冷却：未过冷却直接拒绝（不消耗令牌）
	if rl.CmdCooldown > 0 {
		if last, err := st.CmdCooldown(hash); err == nil && last > 0 {
			if left := int64(rl.CmdCooldown) - (now - last); left > 0 {
				return fmt.Errorf("命令冷却中：相同命令 %d 秒内禁止重复执行（剩余 %d 秒）", rl.CmdCooldown, left)
			}
		}
	}

	// 全局令牌桶（rate 单位：个/分钟 → 个/秒）
	ratePerSec := rl.GlobalRate / 60.0
	if ratePerSec <= 0 {
		ratePerSec = 1
	}
	burst := rl.GlobalBurst
	if burst <= 0 {
		burst = 1
	}
	tokens, nowUnix, err := st.TokenBucket("default", ratePerSec, burst)
	if err != nil {
		return fmt.Errorf("限流检查失败: %w", err)
	}
	if tokens < 1 {
		return fmt.Errorf("触发全局限流：请求过于频繁，请稍后再试（令牌桶剩余 %.2f）", tokens)
	}
	if err := st.DeductToken("default", tokens-1, nowUnix); err != nil {
		return fmt.Errorf("限流扣减失败: %w", err)
	}

	// 冷却登记（扣减成功后）
	if rl.CmdCooldown > 0 {
		_ = st.SetCmdCooldown(hash, now)
	}
	return nil
}

func rateLimitHash(env, host, cmd string) string {
	h := sha256.Sum256([]byte(env + "|" + host + "|" + cmd))
	return hex.EncodeToString(h[:])
}