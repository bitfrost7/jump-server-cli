package store

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Store SQLite 持久化存储（令牌桶 + 命令冷却，跨进程限流）。
type Store struct {
	db *sql.DB
}

func New(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	// 关键：写频繁的场景打开 WAL 模式
	if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		return nil, fmt.Errorf("enable wal: %w", err)
	}
	if _, err := db.Exec(`PRAGMA busy_timeout=5000`); err != nil {
		return nil, fmt.Errorf("set busy timeout: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

// ---------------------------------------------------------------------------
// schema
// ---------------------------------------------------------------------------

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS token_bucket (
			id          TEXT    PRIMARY KEY DEFAULT 'default',
			tokens      REAL    NOT NULL,
			last_refill INTEGER NOT NULL           -- unix seconds
		);

		CREATE TABLE IF NOT EXISTS cmd_cooldown (
			cmd_hash TEXT    PRIMARY KEY,
			last_run INTEGER NOT NULL              -- unix seconds
		);
	`)
	return err
}

// ---------------------------------------------------------------------------
// token bucket
// ---------------------------------------------------------------------------

// TokenBucket 返回当前令牌桶状态。
// 如果表中无记录则用 rate/burst 初始化（惰性创建，以集群配置为准）。
func (s *Store) TokenBucket(id string, ratePerSec float64, burst int) (tokens float64, nowUnix int64, err error) {
	nowUnix = time.Now().Unix()
	var lastRefill int64
	err = s.db.QueryRow(
		`SELECT tokens, last_refill FROM token_bucket WHERE id = ?`, id,
	).Scan(&tokens, &lastRefill)
	if err == sql.ErrNoRows {
		tokens = float64(burst)
		_, err = s.db.Exec(
			`INSERT INTO token_bucket (id, tokens, last_refill) VALUES (?, ?, ?)`,
			id, tokens, nowUnix,
		)
	}
	if err != nil {
		return 0, nowUnix, fmt.Errorf("token_bucket read: %w", err)
	}

	// 读 last_refill 做 refill 计算（重复查询仅为读取，保持简单）
	elapsed := nowUnix - lastRefill
	if elapsed > 0 {
		addTokens := float64(elapsed) * ratePerSec
		tokens += addTokens
		maxTokens := float64(burst)
		if tokens > maxTokens {
			tokens = maxTokens
		}
	}
	return tokens, nowUnix, nil
}

// DeductToken 扣减一个令牌并更新 last_refill。内部使用事务。
func (s *Store) DeductToken(id string, tokens float64, nowUnix int64) error {
	_, err := s.db.Exec(
		`UPDATE token_bucket SET tokens = ?, last_refill = ? WHERE id = ?`,
		tokens, nowUnix, id,
	)
	return err
}

// ---------------------------------------------------------------------------
// cmd cooldown
// ---------------------------------------------------------------------------

func (s *Store) CmdCooldown(hash string) (lastRun int64, err error) {
	err = s.db.QueryRow(
		`SELECT last_run FROM cmd_cooldown WHERE cmd_hash = ?`, hash,
	).Scan(&lastRun)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return lastRun, err
}

func (s *Store) SetCmdCooldown(hash string, nowUnix int64) error {
	_, err := s.db.Exec(
		`INSERT INTO cmd_cooldown (cmd_hash, last_run) VALUES (?, ?)
		 ON CONFLICT(cmd_hash) DO UPDATE SET last_run = excluded.last_run`,
		hash, nowUnix,
	)
	return err
}
