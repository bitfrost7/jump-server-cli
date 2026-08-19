package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/bitfrost7/jump-server-cli/config"
	"github.com/bitfrost7/jump-server-cli/internal/service"
	"github.com/bitfrost7/jump-server-cli/pkg/audit"
	"github.com/bitfrost7/jump-server-cli/pkg/store"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
)

var mcpCmd = &cobra.Command{
	Use:    "mcp",
	Short:  "启动 MCP stdio 服务器",
	Hidden: true,
	RunE:   runMCPServer,
}

func init() {
	rootCmd.AddCommand(mcpCmd)
}

func runMCPServer(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(defaultConfigPath)
	if err != nil {
		return fmt.Errorf("加载配置失败: %w", err)
	}
	st, err := store.New(expandPath(cfg.Store.Path))
	if err != nil {
		return fmt.Errorf("初始化状态存储失败: %w", err)
	}
	defer st.Close()

	s := server.NewMCPServer(
		"jump-server",
		"1.0.0",
	)

	// ── jump_exec ──
	execTool := mcp.NewTool("jump_exec",
		mcp.WithDescription("通过跳板机在目标主机执行 SSH 命令。无白名单限制，任意命令均可执行。"),
		mcp.WithString("host", mcp.Description("目标主机 IP（留空则在跳板机执行）")),
		mcp.WithString("command", mcp.Required(), mcp.Description("shell 命令")),
		mcp.WithString("env", mcp.Description("环境: test/prod"), mcp.DefaultString("test")),
		mcp.WithNumber("timeout", mcp.Description("超时秒数"), mcp.DefaultNumber(60)),
	)
	s.AddTool(execTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleExec(ctx, req, cfg, st)
	})

	// ── jump_upload ──
	uploadTool := mcp.NewTool("jump_upload",
		mcp.WithDescription("上传本地文件到跳板机或远程主机。host 留空则传到跳板机。"),
		mcp.WithString("local_path", mcp.Required(), mcp.Description("本地文件路径")),
		mcp.WithString("remote_path", mcp.Required(), mcp.Description("远程目标路径")),
		mcp.WithString("host", mcp.Description("目标主机 IP（留空则传到跳板机）")),
		mcp.WithString("env", mcp.Description("环境: test/prod"), mcp.DefaultString("test")),
		mcp.WithNumber("timeout", mcp.Description("超时秒数"), mcp.DefaultNumber(120)),
	)
	s.AddTool(uploadTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleUpload(ctx, req, cfg, st)
	})

	// ── jump_download ──
	downloadTool := mcp.NewTool("jump_download",
		mcp.WithDescription("从跳板机或远程主机下载文件到本地。host 留空则从跳板机下载。"),
		mcp.WithString("remote_path", mcp.Required(), mcp.Description("远程文件路径")),
		mcp.WithString("local_path", mcp.Required(), mcp.Description("本地目标路径")),
		mcp.WithString("host", mcp.Description("目标主机 IP（留空则从跳板机下载）")),
		mcp.WithString("env", mcp.Description("环境: test/prod"), mcp.DefaultString("test")),
		mcp.WithNumber("timeout", mcp.Description("超时秒数"), mcp.DefaultNumber(120)),
	)
	s.AddTool(downloadTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleDownload(ctx, req, cfg, st)
	})

	// ── jump_doctor ──
	doctorTool := mcp.NewTool("jump_doctor",
		mcp.WithDescription("检测所有环境（test + prod）的跳板机连通性。"),
		mcp.WithNumber("timeout", mcp.Description("超时秒数"), mcp.DefaultNumber(120)),
	)
	s.AddTool(doctorTool, handleDoctor)

	return server.ServeStdio(s)
}

// ── tool handler ──

func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{Type: "text", Text: text},
		},
	}
}

func errResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{
			mcp.TextContent{Type: "text", Text: text},
		},
	}
}

// logAudit 写一条 jsonl 审计记录（失败静默，不影响主流程）。
func logAudit(cfg config.Config, e audit.Entry) {
	if err := audit.Log(cfg.Audit.Dir, e); err != nil {
		slog.Error("审计写入失败", "error", err)
	}
}

func handleExec(ctx context.Context, req mcp.CallToolRequest, cfg config.Config, st *store.Store) (*mcp.CallToolResult, error) {
	args := getArgs(req)
	host := strArg(args, "host")
	command := strArg(args, "command")
	env := strArg(args, "env", "test")
	timeout := intArg(args, "timeout", 60)

	if command == "" {
		return errResult("command 不能为空"), nil
	}

	bastion := cfg.SSH.BastionForEnv(env)
	if err := enforceRateLimit(st, cfg.Ratelimit, env, host, command); err != nil {
		logAudit(cfg, audit.Entry{
			Tool: "jump_exec", User: targetUserOf(cfg, bastion, host),
			Host: host, Command: command, Env: env,
			Allowed: false, Error: err.Error(),
		})
		return errResult(err.Error()), nil
	}

	start := time.Now()
	sshExec := service.NewSSHExecutor(cfg.SSH)
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	var output string
	var execErr error
	if host != "" {
		output, execErr = sshExec.Execute(ctx, "", host, command, env)
	} else {
		output, execErr = sshExec.ExecuteDirect(ctx, bastion.User, bastion.Host, command)
	}
	dur := time.Since(start)

	// PTY 模式下退出码不可靠，输出即结果；错误记入审计
	success := execErr == nil
	logAudit(cfg, audit.Entry{
		Tool: "jump_exec", User: targetUserOf(cfg, bastion, host),
		Host: host, Command: command, Env: env,
		Allowed: true, Success: &success,
		Output: truncateOutput(output, 2048), Error: errString(execErr),
		Duration: dur.String(),
	})
	return textResult(output), nil
}

func handleUpload(ctx context.Context, req mcp.CallToolRequest, cfg config.Config, st *store.Store) (*mcp.CallToolResult, error) {
	args := getArgs(req)
	localPath := strArg(args, "local_path")
	remotePath := strArg(args, "remote_path")
	host := strArg(args, "host")
	env := strArg(args, "env", "test")
	timeout := intArg(args, "timeout", 120)

	if localPath == "" || remotePath == "" {
		return errResult("local_path 和 remote_path 不能为空"), nil
	}

	bastion := cfg.SSH.BastionForEnv(env)
	desc := fmt.Sprintf("upload %s -> %s", localPath, remotePath)
	if host != "" {
		desc = fmt.Sprintf("upload via %s %s -> %s (target=%s)", bastion.Host, localPath, remotePath, host)
	}
	if err := enforceRateLimit(st, cfg.Ratelimit, env, host, desc); err != nil {
		logAudit(cfg, audit.Entry{
			Tool: "jump_upload", User: targetUserOf(cfg, bastion, host),
			Host: host, Command: desc, Env: env,
			Allowed: false, Error: err.Error(),
		})
		return errResult(err.Error()), nil
	}

	start := time.Now()
	sshExec := service.NewSSHExecutor(cfg.SSH)
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	var logErr string
	if host != "" {
		targetUser := bastion.TargetUser
		if targetUser == "" {
			targetUser = cfg.SSH.DefaultUser
		}
		data, err := os.ReadFile(localPath)
		if err != nil {
			logErr = "读取本地文件失败: " + err.Error()
		} else {
			b64 := base64.StdEncoding.EncodeToString(data)
			cmd := fmt.Sprintf("echo '%s' | base64 -d > '%s'", b64, remotePath)
			if _, err = sshExec.Execute(ctx, targetUser, host, cmd, env); err != nil {
				logErr = "上传失败: " + err.Error()
			}
		}
	} else {
		scpExec := service.NewSCPExecutor(bastion.Host, cfg.SCP.DefaultUser,
			time.Duration(cfg.SCP.ConnectTimeout)*time.Second)
		if _, err := scpExec.CopyToBastion(ctx, localPath, remotePath); err != nil {
			logErr = "上传到跳板机失败: " + err.Error()
		}
	}
	dur := time.Since(start)

	success := logErr == ""
	logAudit(cfg, audit.Entry{
		Tool: "jump_upload", User: targetUserOf(cfg, bastion, host),
		Host: host, Command: desc, Env: env,
		Allowed: true, Success: &success,
		Error: logErr, Duration: dur.String(),
	})
	if logErr != "" {
		return errResult(logErr), nil
	}
	return textResult("上传成功"), nil
}

func handleDownload(ctx context.Context, req mcp.CallToolRequest, cfg config.Config, st *store.Store) (*mcp.CallToolResult, error) {
	args := getArgs(req)
	remotePath := strArg(args, "remote_path")
	localPath := strArg(args, "local_path")
	host := strArg(args, "host")
	env := strArg(args, "env", "test")
	timeout := intArg(args, "timeout", 120)

	if remotePath == "" || localPath == "" {
		return errResult("remote_path 和 local_path 不能为空"), nil
	}

	bastion := cfg.SSH.BastionForEnv(env)
	desc := fmt.Sprintf("download %s -> %s", remotePath, localPath)
	if host != "" {
		desc = fmt.Sprintf("download via %s %s -> %s (target=%s)", bastion.Host, remotePath, localPath, host)
	}
	if err := enforceRateLimit(st, cfg.Ratelimit, env, host, desc); err != nil {
		logAudit(cfg, audit.Entry{
			Tool: "jump_download", User: targetUserOf(cfg, bastion, host),
			Host: host, Command: desc, Env: env,
			Allowed: false, Error: err.Error(),
		})
		return errResult(err.Error()), nil
	}

	start := time.Now()
	sshExec := service.NewSSHExecutor(cfg.SSH)
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	var logErr string
	if host != "" {
		targetUser := bastion.TargetUser
		if targetUser == "" {
			targetUser = cfg.SSH.DefaultUser
		}
		cmd := fmt.Sprintf("base64 '%s'", remotePath)
		output, err := sshExec.Execute(ctx, targetUser, host, cmd, env)
		if err != nil {
			logErr = "读取远程文件失败: " + err.Error()
		} else {
			b64Data := extractBase64(output)
			if b64Data == "" {
				logErr = "未找到 base64 数据"
			} else if decoded, err := base64.StdEncoding.DecodeString(b64Data); err != nil {
				logErr = "base64 解码失败: " + err.Error()
			} else if err := os.WriteFile(localPath, decoded, 0644); err != nil {
				logErr = "写入本地文件失败: " + err.Error()
			}
		}
	} else {
		scpExec := service.NewSCPExecutor(bastion.Host, cfg.SCP.DefaultUser,
			time.Duration(cfg.SCP.ConnectTimeout)*time.Second)
		if _, err := scpExec.CopyFromBastion(ctx, remotePath, localPath); err != nil {
			logErr = "从跳板机下载失败: " + err.Error()
		}
	}
	dur := time.Since(start)

	success := logErr == ""
	logAudit(cfg, audit.Entry{
		Tool: "jump_download", User: targetUserOf(cfg, bastion, host),
		Host: host, Command: desc, Env: env,
		Allowed: true, Success: &success,
		Error: logErr, Duration: dur.String(),
	})
	if logErr != "" {
		return errResult(logErr), nil
	}
	return textResult("下载成功"), nil
}

func handleDoctor(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	cfg, err := config.Load(defaultConfigPath)
	if err != nil {
		return errResult("加载配置失败: " + err.Error()), nil
	}

	var sb resultBuilder
	allOK := true

	for _, env := range []string{"test", "prod"} {
		bastion := cfg.SSH.BastionForEnv(env)
		sshExec := service.NewSSHExecutor(cfg.SSH)

		sb.linef("=== %s ===", env)

		_, err := sshExec.ExecuteDirect(ctx, bastion.User, bastion.Host, "echo ok")
		if err != nil {
			sb.linef("  跳板机 %s: ❌ %v", bastion.Host, err)
			allOK = false
		} else {
			sb.linef("  跳板机 %s: ✅", bastion.Host)
		}
	}

	if allOK {
		sb.line("✅ 全部正常")
	} else {
		sb.line("⚠️  存在异常")
	}

	return textResult(sb.string()), nil
}

// ── helpers ──

func getArgs(req mcp.CallToolRequest) map[string]interface{} {
	if args, ok := req.Params.Arguments.(map[string]interface{}); ok {
		return args
	}
	return nil
}

func strArg(args map[string]interface{}, key string, defaults ...string) string {
	if v, ok := args[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	if len(defaults) > 0 {
		return defaults[0]
	}
	return ""
}

func intArg(args map[string]interface{}, key string, defaults ...float64) int {
	if v, ok := args[key]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case int64:
			return int(n)
		}
	}
	if len(defaults) > 0 {
		return int(defaults[0])
	}
	return 0
}

type resultBuilder struct {
	s string
}

func (b *resultBuilder) line(s string) {
	b.s += s + "\n"
}

func (b *resultBuilder) linef(format string, args ...interface{}) {
	b.s += fmt.Sprintf(format, args...) + "\n"
}

func (b *resultBuilder) string() string {
	return b.s
}
