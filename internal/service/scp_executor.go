package service

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type SCPExecutor struct {
	bastionHost    string
	bastionUser    string
	connectTimeout time.Duration
}

func NewSCPExecutor(bastionHost, bastionUser string, connectTimeout time.Duration) *SCPExecutor {
	return &SCPExecutor{
		bastionHost:    bastionHost,
		bastionUser:    bastionUser,
		connectTimeout: connectTimeout,
	}
}

func (c *SCPExecutor) CopyToBastion(ctx context.Context, localPath, remotePath string) (int64, error) {
	to := c.connectTimeout + 10*time.Second
	timeoutStr := fmt.Sprintf("%.0f", c.connectTimeout.Seconds())

	execCtx, cancel := context.WithTimeout(ctx, to)
	defer cancel()

	out, err := exec.CommandContext(execCtx, "scp",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout="+timeoutStr,
		localPath,
		fmt.Sprintf("%s@%s:%s", c.bastionUser, c.bastionHost, remotePath),
	).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("scp: %w\n%s", err, string(out))
	}

	// 验证文件大小（用 pipe 绕过 bastion sudosh）
	verifyCtx, verifyCancel := context.WithTimeout(ctx, 15*time.Second)
	defer verifyCancel()

	statCmd := exec.CommandContext(verifyCtx, "ssh",
		"-tt",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout="+timeoutStr,
		c.bastionHost,
	)
	statCmd.Stdin = strings.NewReader(fmt.Sprintf("echo '===JUMPSIZE===' && stat -c%%s %s; exit\n", remotePath))
	sizeOut, _ := statCmd.Output()
	// 用标记法提取文件大小
	raw := string(sizeOut)
	// 去除 ANSI
	ansi := regexp.MustCompile(`\x1b\[[0-9;?]*[a-zA-Z]`)
	osc := regexp.MustCompile(`\x1b\][^\x07]*\x07`)
	raw = ansi.ReplaceAllString(raw, "")
	raw = osc.ReplaceAllString(raw, "")
	// 按标记截取
	marker := "===JUMPSIZE==="
	if idx := strings.Index(raw, marker); idx >= 0 {
		after := raw[idx+len(marker):]
		for _, line := range strings.Split(after, "\n") {
			line = strings.TrimSpace(line)
			if n, err := strconv.ParseInt(line, 10, 64); err == nil && n > 0 {
				return n, nil
			}
		}
	}
	return 0, fmt.Errorf("upload ok but verify failed: no file size found in output (raw=%q)", raw)
}

// CopyFromBastion 从跳板机下载文件到本地。
func (c *SCPExecutor) CopyFromBastion(ctx context.Context, remotePath, localPath string) (int64, error) {
	to := c.connectTimeout + 10*time.Second
	timeoutStr := fmt.Sprintf("%.0f", c.connectTimeout.Seconds())

	execCtx, cancel := context.WithTimeout(ctx, to)
	defer cancel()

	// 先用 stat 获取远端文件大小（通过 SSH pipe 绕过 sudosh）
	statCmd := exec.CommandContext(execCtx, "ssh",
		"-tt",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout="+timeoutStr,
		c.bastionHost,
	)
	statCmd.Stdin = strings.NewReader(fmt.Sprintf("echo '===JUMPSIZE===' && stat -c%%s %s; exit\n", remotePath))
	sizeOut, _ := statCmd.Output()

	var fileSize int64
	raw := string(sizeOut)
	ansi := regexp.MustCompile(`\x1b\[[0-9;?]*[a-zA-Z]`)
	osc := regexp.MustCompile(`\x1b\][^\x07]*\x07`)
	raw = ansi.ReplaceAllString(raw, "")
	raw = osc.ReplaceAllString(raw, "")
	marker := "===JUMPSIZE==="
	if idx := strings.Index(raw, marker); idx >= 0 {
		after := raw[idx+len(marker):]
		for _, line := range strings.Split(after, "\n") {
			line = strings.TrimSpace(line)
			if n, err := strconv.ParseInt(line, 10, 64); err == nil && n > 0 {
				fileSize = n
				break
			}
		}
	}

	// 执行 scp 从 bastion → local
	out, err := exec.CommandContext(execCtx, "scp",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout="+timeoutStr,
		fmt.Sprintf("%s@%s:%s", c.bastionUser, c.bastionHost, remotePath),
		localPath,
	).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("scp download: %w\n%s", err, string(out))
	}

	if fileSize == 0 {
		return 0, fmt.Errorf("download ok but stat failed before download")
	}
	return fileSize, nil
}
