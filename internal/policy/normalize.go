// Package policy 实现跳板机命令的安全准入：黑名单拦截 + 环境策略 + 命令整形。
//
// 设计要点：
//   - 匹配前先 Normalize，把所有等价写法归一，避免 /dev//tcp、/dev/${IFS}tcp
//     这类绕过；规范化只用于匹配，不改变实际执行的命令。
//   - 规则来自内嵌默认 YAML + 用户覆盖（~/.local/jump-server/policy.yaml）。
//   - 两种模式：audit（只记录不拦截，用于灰度）/ enforce（真拦截）。
package policy

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	reIFS  = regexp.MustCompile(`\$\{?IFS\}?(:\d+:\d+)?`)
	reAnsi = regexp.MustCompile(`\$'((?:[^'\\]|\\.)*)'`)
	reHex  = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	reOct  = regexp.MustCompile(`\\([0-7]{1,3})`)
	reSlsh = regexp.MustCompile(`/{2,}`)
	reWsp  = regexp.MustCompile(`[ \t\r\n]+`)
)

// sepRE 命令分隔符（用于统计串联段数）。
var sepRE = regexp.MustCompile(`(\|\||&&|;|\|)`)

// Normalize 把命令归一成"语义等价、写法唯一"的形式，供黑名单匹配。
//
//	/dev//tcp          → /dev/tcp
//	/dev/${IFS}tcp     → /dev/ tcp        （IFS 展开为空白）
//	$'\x2f'dev/tcp     → /dev/tcp
//	""/dev/tcp         → /dev/tcp
//	n''map             → nmap
//
// 只用于匹配，绝不用于执行。
func Normalize(cmd string) string {
	s := cmd

	// $'...' ANSI-C 引用 → 解码转义
	s = reAnsi.ReplaceAllStringFunc(s, func(m string) string {
		return decodeEscapes(m[2 : len(m)-1])
	})

	// ${IFS} / $IFS → 空格（shell 展开后即分隔符）
	s = reIFS.ReplaceAllString(s, " ")

	// 去引号（保留内容）
	s = strings.NewReplacer(`"`, "", `'`, "").Replace(s)

	// 去转义反斜杠（n\map → nmap）
	s = strings.ReplaceAll(s, `\`, "")

	// 压缩连续斜杠
	s = reSlsh.ReplaceAllString(s, "/")

	// 折叠空白
	s = reWsp.ReplaceAllString(s, " ")

	return strings.TrimSpace(s)
}

func decodeEscapes(s string) string {
	s = reHex.ReplaceAllStringFunc(s, func(m string) string {
		n, err := strconv.ParseInt(m[2:], 16, 32)
		if err != nil {
			return m
		}
		return string(rune(n))
	})
	s = reOct.ReplaceAllStringFunc(s, func(m string) string {
		n, err := strconv.ParseInt(m[1:], 8, 32)
		if err != nil {
			return m
		}
		return string(rune(n))
	})
	s = strings.ReplaceAll(s, `\\`, `\`)
	s = strings.ReplaceAll(s, `\'`, `'`)
	return s
}

// Compact 去掉归一化文本里的全部空白。
//
// 用于捕获用空白变量拆分关键字的写法：`/dev/${IFS}tcp` 归一化后是
// `/dev/ tcp`，去空白后还原为 `/dev/tcp`。匹配时 norm 与 compact 各试一遍。
func Compact(norm string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r':
			return -1
		}
		return r
	}, norm)
}

// ChainSegments 统计命令的串联段数（按 ; && || | 切分）。
// 做简易引号感知：单引号/双引号内的分隔符不计数，
// 避免 awk '{print $1; $2}' 这类被误判为多段。
func ChainSegments(cmd string) int {
	n := 1
	var quote byte
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '\\':
			i++ // 跳过被转义的下一个字符
		default:
			if c == ';' || c == '&' || c == '|' {
				// && 与 || 只算一个分隔符
				if i+1 < len(cmd) && cmd[i+1] == c {
					i++
				}
				n++
			}
		}
	}
	return n
}

// redirectTargets 提取 shell 重定向 (> 与 >>) 的目标路径。
// 调用方自行排除 /dev/null 等无害目标。
//
// 只返回「像文件路径」的目标：
//   - 绝对路径 / 家目录路径 / 相对路径（含 /）
//   - 带扩展名的文件名（out.log、dump.sql）
//
// 这样可以避开 SQL 与普通比较里的 `>`：
// `where a > last_free_time`、`count > 100` 不会被当成写文件。
func redirectTargets(cmd string) []string {
	var out []string
	var quote byte
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		if c == '\\' {
			i++ // 跳过被转义的下一个字符
			continue
		}
		if c != '>' {
			continue
		}
		// 排除箭头与比较写法：`upload a -> b`、`a => b` 不是重定向
		if i > 0 && (cmd[i-1] == '-' || cmd[i-1] == '=') {
			continue
		}
		// 跳过 >> 与 fd 前缀（2>、&>）
		j := i + 1
		if j < len(cmd) && cmd[j] == '>' {
			j++
		}
		for j < len(cmd) && (cmd[j] == ' ' || cmd[j] == '\t') {
			j++
		}
		start := j
		for j < len(cmd) && cmd[j] != ' ' && cmd[j] != '\t' && cmd[j] != ';' && cmd[j] != '&' && cmd[j] != '|' {
			j++
		}
		if start < j {
			if target := cmd[start:j]; looksLikePath(target) {
				out = append(out, target)
			}
		}
		i = j - 1
	}
	return out
}

// looksLikePath 判断重定向目标是否像一个文件路径。
func looksLikePath(s string) bool {
	switch {
	case s == "", s == "&1", s == "&2":
		return false
	case strings.HasPrefix(s, "/"), strings.HasPrefix(s, "~"),
		strings.HasPrefix(s, "./"), strings.HasPrefix(s, "../"):
		return true
	case strings.Contains(s, "/"):
		return true
	}
	// 带扩展名的文件名；纯标识符（last_free_time）与数字不是路径
	if i := strings.LastIndex(s, "."); i > 0 && i < len(s)-1 {
		return true
	}
	return false
}
