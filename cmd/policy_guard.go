package main

import (
	"fmt"
	"strings"

	"github.com/bitfrost7/jump-server-cli/config"
	"github.com/bitfrost7/jump-server-cli/internal/policy"
	"github.com/bitfrost7/jump-server-cli/pkg/audit"
)

// buildEngine 按配置构建策略引擎。
func buildEngine(cfg config.Config) (*policy.Engine, error) {
	mode := policy.Mode(cfg.Policy.Mode)
	if mode != policy.ModeEnforce {
		mode = policy.ModeAudit
	}
	return policy.New(mode, expandPath(cfg.Policy.RulesFile))
}

// policyError 把判定结果转成给调用方（含 LLM）看的错误信息。
//
// 拒绝信息本身就是最有效的规范传递：讲清「命中哪条红线 + 为什么 + 该怎么做」，
// 调用方下次就知道绕开，而不是反复撞墙后换一个写法继续试。
func policyError(v policy.Verdict) error {
	var sb strings.Builder
	fmt.Fprintf(&sb, "拒绝执行：命中安全红线 [%s]\n  %s", v.RuleID, v.Reason)
	if v.Detail != "" {
		fmt.Fprintf(&sb, "\n  %s", v.Detail)
	}
	if v.Advice != "" {
		fmt.Fprintf(&sb, "\n  替代做法：%s", v.Advice)
	}
	return fmt.Errorf("%s", sb.String())
}

// auditFromVerdict 把判定结果填进审计条目。
func auditFromVerdict(e *audit.Entry, v policy.Verdict, enforced bool) {
	e.Policy = string(v.Decision)
	e.RuleID = v.RuleID
	e.Severity = v.Severity
	e.Reason = v.Reason
	e.Enforced = enforced
}
