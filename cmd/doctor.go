package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bitfrost7/jump-server-cli/config"
	"github.com/bitfrost7/jump-server-cli/internal/service"
	"github.com/spf13/cobra"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "检测所有环境连通性（test + prod）",
	Long: `检测跳板机连通性。

无需参数，自动检测 test 和 prod 两个环境。

注意：跳板机服务端仅支持密码认证（公钥认证被关闭），日常免密依赖
ControlMaster 长连接（` + "`jump-server connect`" + ` 建立，4 小时有效）。
本命令只检测“免密长连接”是否可用，绝不会弹出密码输入框。`,
	Args: cobra.NoArgs,
	RunE: runDoctor,
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}

// envStatus 记录单个环境的连通性检测结果
type envStatus struct {
	Env     string
	Bastion string
	OK      bool
	Reason  string
}

// probeEnv 检测单个环境：socket 是否存在 + 通过 socket 实际探测一次。
// 全程 BatchMode，不做任何交互式密码输入；未建立长连接时如实报告。
func probeEnv(cfg config.Config, env string) envStatus {
	sshExec := service.NewSSHExecutor(cfg.SSH)
	be := cfg.SSH.BastionForEnv(env)

	if err := sshExec.CheckSocket(env); err != nil {
		return envStatus{
			Env: env, Bastion: be.Host, OK: false,
			Reason: fmt.Sprintf("需要密码认证，尚未建立免密长连接：%v", err),
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := time.Now()
	out, err := sshExec.ExecuteDirect(ctx, be.User, be.Host, "echo ok")
	dur := time.Since(start)
	if err != nil {
		return envStatus{
			Env: env, Bastion: be.Host, OK: false,
			Reason: fmt.Sprintf("探测失败（%v）：%v", dur.Round(time.Millisecond), err),
		}
	}
	if strings.TrimSpace(out) != "ok" {
		return envStatus{
			Env: env, Bastion: be.Host, OK: false,
			Reason: fmt.Sprintf("探测结果异常: %q", out),
		}
	}
	return envStatus{
		Env: env, Bastion: be.Host, OK: true,
		Reason: fmt.Sprintf("免密长连接复用 %v", dur.Round(time.Millisecond)),
	}
}

func runDoctor(cmd *cobra.Command, args []string) error {
	cfgFile := defaultConfigPath
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("❌ 加载配置失败: %w", err)
	}

	allOK := true
	for _, env := range []string{"test", "prod"} {
		st := probeEnv(cfg, env)
		fmt.Println("═══════════════════════════════════")
		fmt.Println("🔍", st.Env, "环境")
		fmt.Println("═══════════════════════════════════")
		fmt.Print("📡 跳板机 ", st.Bastion, "... ")
		if st.OK {
			fmt.Println("✅", st.Reason)
		} else {
			fmt.Println("❌")
			fmt.Printf("   %s\n", st.Reason)
			allOK = false
		}
		fmt.Println()
	}

	fmt.Println("═══════════════════════════════════")
	if allOK {
		fmt.Println("✅ 全部环境正常（免密长连接已就绪，无需密码）")
	} else {
		fmt.Println("⚠️  存在异常：请先执行 `jump-server connect` 输入一次密码建立免密长连接")
		os.Exit(1)
	}
	return nil
}

func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i]
		}
	}
	if len(s) > 80 {
		return s[:80]
	}
	return s
}
