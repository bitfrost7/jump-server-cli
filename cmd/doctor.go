package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/bitfrost7/jump-server-cli/config"
	"github.com/bitfrost7/jump-server-cli/internal/service"
	"github.com/spf13/cobra"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "检测所有环境连通性（test + prod）",
	Long: `检测跳板机连通性。

无需参数，自动检测 test 和 prod 两个环境。`,
	Args: cobra.NoArgs,
	RunE: runDoctor,
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}

type envCheck struct {
	env     string
	bastion config.BastionEntry
	cfg     config.Config
}

func runDoctor(cmd *cobra.Command, args []string) error {
	cfgFile := defaultConfigPath
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("❌ 加载配置失败: %w", err)
	}

	envs := []envCheck{
		{
			env:     "test",
			bastion: cfg.SSH.BastionForEnv("test"),
			cfg:     cfg,
		},
		{
			env:     "prod",
			bastion: cfg.SSH.BastionForEnv("prod"),
			cfg:     cfg,
		},
	}

	allOK := true

	for _, ec := range envs {
		ok := checkEnv(ec)
		if !ok {
			allOK = false
		}
		fmt.Println()
	}

	fmt.Println("═══════════════════════════════════")
	if allOK {
		fmt.Println("✅ 全部环境正常")
	} else {
		fmt.Println("⚠️  存在异常，请检查上述错误")
		os.Exit(1)
	}
	return nil
}

func checkEnv(ec envCheck) bool {
	sshExec := service.NewSSHExecutor(ec.cfg.SSH)
	ctx := context.Background()

	fmt.Println("═══════════════════════════════════")
	fmt.Println("🔍", ec.env, "环境")
	fmt.Println("═══════════════════════════════════")

	// ── 跳板机连通性 ──
	fmt.Print("📡 跳板机 ", ec.bastion.Host, "... ")
	start := time.Now()
	_, err := sshExec.ExecuteDirect(ctx, ec.bastion.User, ec.bastion.Host, "echo ok")
	dur := time.Since(start)
	if err != nil {
		fmt.Println("❌")
		fmt.Printf("   %v\n", err)
		return false
	}
	fmt.Println("✅", dur.Round(time.Millisecond))
	return true
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