package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Entry 一条审计记录，追加写入 jsonl（按天分文件）。
type Entry struct {
	Timestamp string `json:"timestamp"`
	Tool      string `json:"tool,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	User      string `json:"user,omitempty"`
	Host      string `json:"host,omitempty"`
	Command   string `json:"command"`
	Env       string `json:"env,omitempty"`
	Allowed   bool   `json:"allowed"`
	Success   *bool  `json:"success,omitempty"`
	Output    string `json:"output,omitempty"`
	Error     string `json:"error,omitempty"`
	Duration  string `json:"duration,omitempty"`
}

// Log 追加一条记录到 <dir>/audit-YYYY-MM-DD.jsonl。
// 每次调用打开-追加-关闭（单进程 CLI 每次执行一条，开销可接受；
// O_APPEND 保证跨进程追加不覆盖）。
func Log(dir string, e Entry) error {
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("audit: mkdir %s: %w", dir, err)
	}
	if e.Timestamp == "" {
		e.Timestamp = time.Now().Format(time.RFC3339Nano)
	}
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit: marshal: %w", err)
	}

	name := filepath.Join(dir, "audit-"+time.Now().Format("2006-01-02")+".jsonl")
	f, err := os.OpenFile(name, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("audit: open %s: %w", name, err)
	}
	defer f.Close()

	if _, err := f.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("audit: write %s: %w", name, err)
	}
	return nil
}
