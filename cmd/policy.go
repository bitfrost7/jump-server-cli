package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bitfrost7/jump-server-cli/config"
	"github.com/bitfrost7/jump-server-cli/internal/policy"
	"github.com/spf13/cobra"
)

var policyEnvFlag string

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "安全策略：查看规则 / 预检命令 / 回放审计",
	Long: `安全策略工具。策略在每次执行前对命令做准入判定。

  jump-server policy list                                    # 查看当前生效规则
  jump-server policy check -e prod 'rm -rf /tmp/x'           # 预检一条命令（不执行）
  jump-server policy replay ~/.local/jump-server/audit/*.jsonl   # 用存量审计回放规则`,
	Args: cobra.NoArgs,
}

var policyListCmd = &cobra.Command{
	Use:   "list",
	Short: "列出当前生效的规则与阈值",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(defaultConfigPath)
		if err != nil {
			return fmt.Errorf("加载配置失败: %w", err)
		}
		eng, err := buildEngine(cfg)
		if err != nil {
			return err
		}
		deny, warn, prod := eng.RuleCount()
		lim := eng.Limits()

		mode := "audit（只记录，不拦截）"
		if eng.Enforcing() {
			mode = "enforce（命中即拦截）"
		}
		fmt.Printf("模式      : %s\n", mode)
		fmt.Printf("规则文件  : %s\n", cfg.Policy.RulesFile)
		fmt.Printf("生产只读  : %v\n", eng.ProdReadOnly())
		fmt.Printf("规则条数  : deny=%d  warn=%d  prod扩展=%d\n", deny, warn, prod)
		fmt.Printf("整形阈值  : 长度 warn>%d deny>%d | 串联段 warn>=%d deny>=%d | 内嵌base64>%d\n",
			lim.WarnCommandLength, lim.MaxCommandLength, lim.WarnChainSegments, lim.DenyChainSegments, lim.InlineBase64Min)
		fmt.Println()
		fmt.Print(eng.Describe())
		return nil
	},
}

var policyCheckCmd = &cobra.Command{
	Use:   "check '<command>'",
	Short: "预检一条命令，输出判定结果（不执行）",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(defaultConfigPath)
		if err != nil {
			return fmt.Errorf("加载配置失败: %w", err)
		}
		eng, err := buildEngine(cfg)
		if err != nil {
			return err
		}
		raw := args[0]
		v := eng.Check(policyEnvFlag, raw)

		fmt.Printf("环境    : %s\n", policyEnvFlag)
		fmt.Printf("命令    : %s\n", raw)
		if n := policy.Normalize(raw); n != raw {
			fmt.Printf("归一化  : %s\n", n)
		}
		fmt.Printf("判定    : %s", v.Decision)
		if v.RuleID != "" {
			fmt.Printf("  [%s / %s]", v.RuleID, v.Severity)
		}
		fmt.Println()
		if v.Reason != "" {
			fmt.Printf("原因    : %s\n", v.Reason)
		}
		if v.Detail != "" {
			fmt.Printf("详情    : %s\n", v.Detail)
		}
		if v.Advice != "" {
			fmt.Printf("建议    : %s\n", v.Advice)
		}
		if v.Blocked() && eng.Enforcing() {
			return fmt.Errorf("该命令会被拒绝")
		}
		return nil
	},
}

var policySamples int

var policyReplayCmd = &cobra.Command{
	Use:   "replay <audit-*.jsonl>...",
	Short: "用存量审计日志回放规则，评估误报率",
	Long: `回放历史命令，统计新规则会拒绝/提示多少条，用于切 enforce 前评估误报。

  jump-server policy replay ~/.local/jump-server/audit/*.jsonl`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(defaultConfigPath)
		if err != nil {
			return fmt.Errorf("加载配置失败: %w", err)
		}
		eng, err := buildEngine(cfg)
		if err != nil {
			return err
		}

		type sample struct {
			rule, env, command string
		}
		var (
			total, denyN, warnN int
			denyByRule          = map[string]int{}
			warnByRule          = map[string]int{}
			denySamples         []sample
		)
		files, err := expandGlobs(args)
		if err != nil {
			return err
		}
		for _, f := range files {
			fh, err := os.Open(f)
			if err != nil {
				return err
			}
			sc := bufio.NewScanner(fh)
			sc.Buffer(make([]byte, 0, 1<<20), 16<<20) // 审计里的命令可能很长
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" {
					continue
				}
				var e struct {
					Command string `json:"command"`
					Env     string `json:"env"`
				}
				if err := json.Unmarshal([]byte(line), &e); err != nil {
					continue
				}
				if e.Command == "" {
					continue
				}
				total++
				v := eng.Check(e.Env, e.Command)
				switch v.Decision {
				case policy.Deny:
					denyN++
					denyByRule[v.RuleID]++
					if policySamples < 0 || len(denySamples) < policySamples {
						denySamples = append(denySamples, sample{v.RuleID, e.Env, e.Command})
					}
				case policy.Warn:
					warnN++
					warnByRule[v.RuleID]++
				}
			}
			fh.Close()
		}

		fmt.Printf("回放 %d 条命令（来自 %d 个审计文件）\n\n", total, len(files))
		if total == 0 {
			return nil
		}
		fmt.Printf("会被拒绝 %d 条 (%.1f%%)\n", denyN, float64(denyN)/float64(total)*100)
		printRuleCounts(denyByRule)
		fmt.Printf("\n会被提示 %d 条 (%.1f%%)\n", warnN, float64(warnN)/float64(total)*100)
		printRuleCounts(warnByRule)

		if len(denySamples) > 0 {
			fmt.Printf("\n── 被拒绝样本（前 %d 条，请逐条确认是否为误报）──\n", len(denySamples))
			for _, s := range denySamples {
				c := strings.ReplaceAll(s.command, "\n", " ")
				if len(c) > 120 {
					c = c[:120] + "…"
				}
				fmt.Printf("  [%s] env=%-4s %s\n", s.rule, s.env, c)
			}
		}
		return nil
	},
}

func printRuleCounts(m map[string]int) {
	type kv struct {
		k string
		v int
	}
	var list []kv
	for k, v := range m {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].v != list[j].v {
			return list[i].v > list[j].v
		}
		return list[i].k < list[j].k
	})
	for _, e := range list {
		fmt.Printf("    %-28s %d\n", e.k, e.v)
	}
}

// expandGlobs 展开 glob 参数；shell 已展开时原样返回。
func expandGlobs(args []string) ([]string, error) {
	var out []string
	for _, a := range args {
		if !strings.ContainsAny(a, "*?[") {
			out = append(out, a)
			continue
		}
		m, err := filepath.Glob(a)
		if err != nil {
			return nil, err
		}
		out = append(out, m...)
	}
	return out, nil
}

func init() {
	rootCmd.AddCommand(policyCmd)
	policyCmd.AddCommand(policyListCmd, policyCheckCmd, policyReplayCmd)
	policyCheckCmd.Flags().StringVarP(&policyEnvFlag, "env", "e", "test", "环境 (test/prod)")
	policyReplayCmd.Flags().IntVar(&policySamples, "samples", 15, "最多打印多少条被拒样本（-1 = 全部）")
}
