package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/bitfrost7/jump-server-cli/config"
	"github.com/bitfrost7/jump-server-cli/internal/service"
	"github.com/spf13/cobra"
)

var connectCmd = &cobra.Command{
	Use:   "connect",
	Short: "建立免密长连接（输入一次密码，4 小时内免密）",
	Long: `建立跳板机 ControlMaster 长连接。

跳板机服务端仅支持密码认证（公钥认证被关闭），因此无法完全去掉密码；
但通过 ControlMaster 长连接（ControlPersist 4 小时），只需在建立时输入一次
密码，之后 doctor / jump_exec / jump_upload / jump_download 全部复用该连接，
无需再输密码。

用法：
  jump-server connect          # 依次建立 test + prod 两个环境的长连接
  jump-server connect -e prod  # 只建立指定环境`,
	Args: cobra.NoArgs,
	RunE: runConnect,
}

func init() {
	rootCmd.AddCommand(connectCmd)
	connectCmd.Flags().StringVarP(&envFlag, "env", "e", "",
		"环境 (test/prod)，不指定则依次建立全部环境")
}

func runConnect(cmd *cobra.Command, args []string) error {
	cfgFile := defaultConfigPath
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("❌ 加载配置失败: %w", err)
	}

	envs := []string{"test", "prod"}
	if envFlag != "" {
		envs = []string{envFlag}
	}

	allOK := true
	for _, env := range envs {
		be := cfg.SSH.BastionForEnv(env)
		sshExec := service.NewSSHExecutor(cfg.SSH)

		fmt.Println("═══════════════════════════════════")
		fmt.Printf("🔑 %s 环境: %s\n", env, be.Host)
		fmt.Println("═══════════════════════════════════")

		// 已有可用长连接则跳过
		if sshExec.CheckSocket(env) == nil && probeThroughSocket(sshExec, be) {
			fmt.Println("✅ 长连接已存在且可用，无需输入密码")
			continue
		}

		// socket 文件存在但不可用（master 已死），先清掉避免 ssh 误复用
		if sshExec.CheckSocket(env) == nil {
			if p, err := sshExec.SocketPath(env); err == nil {
				fmt.Println("⚠️  检测到 socket 文件但不可用，清理后重新建立...")
				os.Remove(p)
			}
		}

		fmt.Printf("👉 请在下面的 ssh 登录提示中输入密码（用户 %s），登录成功后输入 exit 退出：\n", be.User)
		fmt.Println()

		sshCmd := exec.Command("ssh", "-tt", "-o", "StrictHostKeyChecking=no", be.Host)
		sshCmd.Stdin = os.Stdin
		sshCmd.Stdout = os.Stdout
		sshCmd.Stderr = os.Stderr
		if err := sshCmd.Run(); err != nil {
			fmt.Printf("❌ %s 连接失败: %v\n", be.Host, err)
			allOK = false
			continue
		}

		// 验证长连接是否已建立可用
		if probeThroughSocket(sshExec, be) {
			fmt.Printf("✅ %s 免密长连接已就绪（有效 4 小时）\n", be.Host)
		} else {
			fmt.Printf("❌ %s 长连接验证失败，请重试\n", be.Host)
			allOK = false
		}
		fmt.Println()
	}

	fmt.Println("═══════════════════════════════════")
	if allOK {
		fmt.Println("✅ 免密长连接全部就绪，可直接使用 jump-server / jump_* 工具")
	} else {
		fmt.Println("⚠️  部分环境连接失败，请检查")
		os.Exit(1)
	}
	return nil
}

// probeThroughSocket 通过长连接实际探测一次，确认可用。
func probeThroughSocket(sshExec *service.SSHExecutor, be config.BastionEntry) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := sshExec.ExecuteDirect(ctx, be.User, be.Host, "echo ok")
	return err == nil && strings.TrimSpace(out) == "ok"
}
