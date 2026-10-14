package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bitfrost7/jump-server-cli/config"
	"github.com/bitfrost7/jump-server-cli/internal/policy"
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

	eng, err := buildEngine(cfg)
	if err != nil {
		return fmt.Errorf("初始化安全策略失败: %w", err)
	}

	s := server.NewMCPServer(
		"jump-server",
		"2.0.0",
		server.WithInstructions(jumpServerInstructions(eng)),
	)

	// ── jump_exec ──
	execTool := mcp.NewTool("jump_exec",
		mcp.WithDescription(`通过跳板机执行远程命令（查看状态、读日志、查配置、只读查询）。

执行前每条命令都会经过安全策略校验：裸 socket / 扫描 / 破坏性 / 提权 / 逃逸类命令会被拒绝。

粒度要求：一条命令只做一件事，不要用 ";"、"&&" 串联不同目的的动作；
同质参数可以合并（ls -la /a /b ✅）；需要连续执行多条时用 commands 参数。

文件传输请用 jump_upload / jump_download，不要把文件内容塞进命令行。`),
		mcp.WithDestructiveHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithString("command", mcp.Description("单条 shell 命令（建议不超过 500 字符）。一条命令只做一件事，不要用 ; 或 && 串联多个不同目的的动作；多条命令请用 commands")),
		mcp.WithArray("commands",
			mcp.Description("需要连续执行的多条命令（一次登录、按顺序执行）。需要连续做几件事时优先用这个，而不是把命令拼成长串"),
			mcp.WithStringItems(),
		),
		mcp.WithString("host", mcp.Description("目标主机 IP（留空则在跳板机执行）")),
		mcp.WithString("env", mcp.Description("环境: test/prod。prod 为生产环境，禁止一切写操作"), mcp.DefaultString("test")),
		mcp.WithNumber("timeout", mcp.Description("超时秒数"), mcp.DefaultNumber(60)),
	)
	s.AddTool(execTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleExec(ctx, req, cfg, st, eng)
	})

	// ── jump_upload ──
	uploadTool := mcp.NewTool("jump_upload",
		mcp.WithDescription(`上传本地文件到跳板机或远程主机。host 留空则传到跳板机。

这是传文件的唯一正确通道：不要用 echo '<base64>' | base64 -d 之类的方式在命令行里写文件。`),
		mcp.WithReadOnlyHintAnnotation(false),
		mcp.WithDestructiveHintAnnotation(true),
		mcp.WithString("local_path", mcp.Required(), mcp.Description("本地文件路径")),
		mcp.WithString("remote_path", mcp.Required(), mcp.Description("远程目标路径（建议先落 /tmp）")),
		mcp.WithString("host", mcp.Description("目标主机 IP（留空则传到跳板机）")),
		mcp.WithString("env", mcp.Description("环境: test/prod。prod 为生产环境，写操作受限"), mcp.DefaultString("test")),
		mcp.WithNumber("timeout", mcp.Description("超时秒数"), mcp.DefaultNumber(120)),
	)
	s.AddTool(uploadTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleUpload(ctx, req, cfg, st)
	})

	// ── jump_download ──
	downloadTool := mcp.NewTool("jump_download",
		mcp.WithDescription("从跳板机或远程主机下载文件到本地（只读，不修改远端）。host 留空则从跳板机下载。"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithDestructiveHintAnnotation(false),
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
		mcp.WithDescription("检测所有环境（test + prod）的跳板机连通性。只读探测，不修改任何状态。"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithDestructiveHintAnnotation(false),
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

// jumpServerInstructions 作为 MCP initialize 的 instructions 下发，会常驻客户端 system prompt。
// 这是安全规范的主要传递渠道：工具描述只在被调用时可见，instructions 则一直存在。
func jumpServerInstructions(eng *policy.Engine) string {
	mode := "audit —— 只记录、不拦截（灰度观察期）"
	if eng.Enforcing() {
		mode = "enforce —— 命中即拒绝"
	}
	return fmt.Sprintf(`jump-server：通过跳板机执行远程命令、传输文件。每次执行前都会做安全策略校验，命中红线的命令会被拒绝并留痕。

【当前策略模式】%s

一、安全红线（会被拒绝，不要尝试换写法绕过）
  1. 裸 socket / 反弹 shell：/dev/tcp、/dev/udp、nc -e、ncat -l、socat exec:、bash -i 重定向
  2. 扫描：nmap / masscan / zmap / hping3；for 循环批量探测多主机或多端口
  3. 破坏性：rm -rf /、mkfs、dd of=/dev/*、fork bomb、iptables -F、shutdown / reboot
  4. 下载即执行：curl | sh、wget | bash、eval $(curl …)
  5. 凭据读取：.ssh/id_*、/etc/shadow、.docker/config.json、.aws/credentials
  6. 提权与持久化：sudo su、useradd、crontab、写 authorized_keys / .bashrc
  7. 逃逸：chroot、mount、nsenter、docker run --privileged、/var/run/docker.sock

二、判断连通性
  用 nc -z -w2 <host> <port>，或 curl -sS -m2 -o /dev/null -w '%%{http_code}' <url>。
  更好的做法是直接执行真实命令（curl / docker pull / mysql），报错信息比探测结果更有价值。
  不要用 /dev/tcp 做可达性测试：它与反弹 shell 无法区分，必然触发安全告警。

三、命令粒度（重要）
  一条命令只做一件事。不要用 ";"、"&&" 串联多个不同目的的动作。
  需要连续执行多条时，用 commands 参数一次传多行（一次登录、逐条执行），
  而不是拼成一条长串命令。
  同质参数可以合并：ls -la /a /b ✅ ；ls /a; ls /b ❌

四、文件传输
  一律用 jump_upload / jump_download。不要用 echo '<base64>' | base64 -d 写文件，
  也不要把大文件内容塞进命令行。

五、生产环境
  env=prod 为生产环境，禁止一切写操作（写文件、重启服务、变更容器、SQL 写入），
  只允许只读查询。确需变更请走发布流程。

六、节奏
  先合并查询再调用；拿到结果后读完再决定下一步。避免固定间隔的高频连续调用。`, mode)
}

// ── 拟人节奏：批间冷却（同一 MCP 进程内生效）──

var (
	lastExecMu sync.Mutex
	lastExecAt time.Time
)

// waitBatchCooldown 两次执行之间至少间隔 cooldown，模拟"人在看结果"。
// 用等待而非拒绝：拒绝会让调用方立即重试，反而造成更密集的调用。
func waitBatchCooldown(ctx context.Context, cooldown time.Duration) {
	if cooldown <= 0 {
		return
	}
	lastExecMu.Lock()
	wait := time.Until(lastExecAt.Add(cooldown))
	lastExecMu.Unlock()
	if wait <= 0 {
		return
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

func markExecDone() {
	lastExecMu.Lock()
	lastExecAt = time.Now()
	lastExecMu.Unlock()
}

// collectCommands 取出待执行命令：command（单条）与 commands（多条）二选一。
func collectCommands(args map[string]interface{}) ([]string, error) {
	single := strings.TrimSpace(strArg(args, "command"))
	multi := strArgList(args, "commands")
	switch {
	case single != "" && len(multi) > 0:
		return nil, fmt.Errorf("command 与 commands 只能给一个：单条用 command，多条用 commands")
	case single != "":
		return []string{single}, nil
	default:
		return multi, nil
	}
}

func strArgList(args map[string]interface{}, key string) []string {
	v, ok := args[key]
	if !ok {
		return nil
	}
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, it := range arr {
		if s, ok := it.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

func handleExec(ctx context.Context, req mcp.CallToolRequest, cfg config.Config, st *store.Store, eng *policy.Engine) (*mcp.CallToolResult, error) {
	args := getArgs(req)
	host := strArg(args, "host")
	env := strArg(args, "env", "test")
	timeout := intArg(args, "timeout", 60)

	cmds, err := collectCommands(args)
	if err != nil {
		return errResult(err.Error()), nil
	}
	if len(cmds) == 0 {
		return errResult("command 或 commands 不能为空"), nil
	}
	maxBatch := cfg.Policy.Pacing.MaxCommandsPerBatch
	if maxBatch <= 0 {
		maxBatch = 10
	}
	if len(cmds) > maxBatch {
		return errResult(fmt.Sprintf("单次最多 %d 条命令（收到 %d 条）。请分批调用；同质查询请合并，例如 ls -la /a /b",
			maxBatch, len(cmds))), nil
	}

	bastion := cfg.SSH.BastionForEnv(env)
	user := targetUserOf(cfg, bastion, host)
	batchID := fmt.Sprintf("%d", time.Now().UnixNano())

	// ── 安全策略：任一条被拒则整批不执行（避免部分执行留下中间状态）──
	for i, c := range cmds {
		v := eng.Check(env, c)
		if v.Blocked() && eng.Enforcing() {
			e := audit.Entry{
				Tool: "jump_exec", User: user, Host: host, Command: c, Env: env,
				Allowed: false, Error: policyError(v).Error(),
				Normalized: policy.Normalize(c),
				BatchID:    batchID, BatchIndex: i + 1,
			}
			auditFromVerdict(&e, v, true)
			logAudit(cfg, e)
			return errResult(fmt.Sprintf("整批未执行：第 %d/%d 条未通过安全策略\n\n%s",
				i+1, len(cmds), policyError(v))), nil
		}
		if v.Decision != policy.Allow {
			// audit 模式下的 deny、以及 warn：只记录，不拦
			e := audit.Entry{
				Tool: "jump_exec", User: user, Host: host, Command: c, Env: env,
				Allowed: true, Normalized: policy.Normalize(c),
				BatchID: batchID, BatchIndex: i + 1,
			}
			auditFromVerdict(&e, v, false)
			logAudit(cfg, e)
		}
	}

	// ── 限流（按整批计一次）──
	rateKey := strings.Join(cmds, "\n")
	if err := enforceRateLimit(st, cfg.Ratelimit, env, host, rateKey); err != nil {
		logAudit(cfg, audit.Entry{
			Tool: "jump_exec", User: user, Host: host, Command: rateKey, Env: env,
			Allowed: false, Error: err.Error(), BatchID: batchID,
		})
		return errResult(err.Error()), nil
	}

	sshExec := service.NewSSHExecutor(cfg.SSH)
	// 跳板机仅支持密码认证，日常免密依赖 ControlMaster 长连接；未建立时直接给出指引
	if err := sshExec.CheckSocket(env); err != nil {
		logAudit(cfg, audit.Entry{
			Tool: "jump_exec", User: user, Host: host, Command: rateKey, Env: env,
			Allowed: false, Error: err.Error(), BatchID: batchID,
		})
		return errResult(err.Error()), nil
	}

	// 批间冷却（在超时计时之外：这是"人在看结果"的时间，不应算作执行超时）
	if cfg.Policy.Pacing.Enabled {
		waitBatchCooldown(ctx, time.Duration(cfg.Policy.Pacing.BatchCooldownMS)*time.Millisecond)
	}

	gapMin := time.Duration(cfg.Policy.Pacing.IntraBatchMinMS) * time.Millisecond
	gapMax := time.Duration(cfg.Policy.Pacing.IntraBatchMaxMS) * time.Millisecond
	if !cfg.Policy.Pacing.Enabled {
		gapMin, gapMax = 0, 0
	}

	start := time.Now()
	execCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	// host 为空 = 在跳板机执行；非空 = 经跳板机到目标机执行
	output, execErr := sshExec.ExecuteBatch(execCtx, env, host, "", cmds, gapMin, gapMax)
	dur := time.Since(start)
	markExecDone()

	// PTY 模式下退出码不可靠，输出即结果；错误记入审计
	success := execErr == nil
	for i, c := range cmds {
		logAudit(cfg, audit.Entry{
			Tool: "jump_exec", User: user, Host: host, Command: c, Env: env,
			Allowed: true, Success: &success,
			Output: truncateOutput(output, 2048), Error: errString(execErr),
			Duration: dur.String(),
			BatchID:  batchID, BatchIndex: i + 1,
		})
	}
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
		st := probeEnv(cfg, env)
		sb.linef("=== %s ===", env)
		if st.OK {
			sb.linef("  跳板机 %s: ✅ %s", st.Bastion, st.Reason)
		} else {
			sb.linef("  跳板机 %s: ❌ %s", st.Bastion, st.Reason)
			allOK = false
		}
	}

	if allOK {
		sb.line("✅ 全部正常（免密长连接已就绪，无需密码）")
	} else {
		sb.line("⚠️  存在异常：请先执行 `jump-server connect` 输入一次密码建立免密长连接")
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
