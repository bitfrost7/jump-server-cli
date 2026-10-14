package config

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	SSH       SSHConfig       `yaml:"ssh"`
	SCP       SCPConfig       `yaml:"scp"`
	Audit     AuditConfig     `yaml:"audit"`
	Store     StoreConfig     `yaml:"store"`
	Ratelimit RatelimitConfig `yaml:"ratelimit"`
	Policy    PolicyConfig    `yaml:"policy"`
}

// PolicyConfig 安全策略配置。
type PolicyConfig struct {
	Mode      string       `yaml:"mode"`       // audit=只记录不拦 | enforce=真拦
	RulesFile string       `yaml:"rules_file"` // 用户覆盖规则（可选，按 id 覆盖默认）
	Pacing    PacingConfig `yaml:"pacing"`     // 命令节奏（让调用形态贴近人类操作）
}

// PacingConfig 命令节奏控制。目的：避免「高频、大片、机器般规律」的
// 调用痕迹，使跳板机侧审计呈现出人类逐个敲命令的形态。
type PacingConfig struct {
	Enabled             bool `yaml:"enabled"`
	MaxCommandsPerBatch int  `yaml:"max_commands_per_batch"` // 单次批量上限
	IntraBatchMinMS     int  `yaml:"intra_batch_min_ms"`     // 批内命令间隔下限（模拟敲键）
	IntraBatchMaxMS     int  `yaml:"intra_batch_max_ms"`     // 批内命令间隔上限
	BatchCooldownMS     int  `yaml:"batch_cooldown_ms"`      // 批间冷却（模拟看结果）
}

type StoreConfig struct {
	Path string `yaml:"path"`
}

type BastionEntry struct {
	Host       string `yaml:"host"`
	User       string `yaml:"user"`
	TargetUser string `yaml:"target_user"`
	Mode       string `yaml:"mode"`
}

type SSHConfig struct {
	Bastions        map[string]BastionEntry `yaml:"bastions"`
	SocketPattern   string                  `yaml:"socket_pattern"`
	SkipSocketCheck bool                    `yaml:"skip_socket_check"`
	DefaultUser     string                  `yaml:"default_user"`
	ConnectTimeout  int                     `yaml:"connect_timeout"`
	ExecTimeout     int                     `yaml:"exec_timeout"`
}

func (s SSHConfig) BastionForEnv(env string) BastionEntry {
	if e, ok := s.Bastions[env]; ok {
		return e
	}
	if e, ok := s.Bastions["test"]; ok {
		return e
	}
	return BastionEntry{Host: "bastion-test", User: "ops", Mode: "pipe"}
}

type SCPConfig struct {
	DefaultUser    string `yaml:"default_user"`
	ConnectTimeout int    `yaml:"connect_timeout"`
}

type AuditConfig struct {
	Dir string `yaml:"dir"`
}

type RatelimitConfig struct {
	Enabled     bool    `yaml:"enabled"`
	GlobalRate  float64 `yaml:"global_rate"`  // 令牌桶填充速率（个/分钟）
	GlobalBurst int     `yaml:"global_burst"` // 令牌桶容量（突发允许的并发数）
	CmdCooldown int     `yaml:"cmd_cooldown"` // 同一命令的冷却时间（秒）
}

func (c *Config) Verify() error {
	if len(c.SSH.Bastions) == 0 {
		return errors.New("ssh.bastions is empty")
	}
	return nil
}

func Load(path string) (Config, error) {
	home, _ := os.UserHomeDir()
	cfg := Config{
		SSH: SSHConfig{
			Bastions: map[string]BastionEntry{
				"test": {Host: "bastion-test", User: "ops", Mode: "pipe"},
				"prod": {Host: "bastion-prod", User: "deploy", Mode: "proxyjump"},
			},
			SocketPattern:  "~/.ssh/sockets/{user}@{host}:22",
			DefaultUser:    "root",
			ConnectTimeout: 10,
			ExecTimeout:    60,
		},
		SCP: SCPConfig{
			DefaultUser:    "ops",
			ConnectTimeout: 10,
		},
		Audit: AuditConfig{Dir: "audit"},
		Store: StoreConfig{
			Path: home + "/.jump-server/jump.db",
		},
		Ratelimit: RatelimitConfig{
			Enabled:     true,
			GlobalRate:  60,
			GlobalBurst: 5,
			CmdCooldown: 5,
		},
		Policy: PolicyConfig{
			// 默认 audit：只记录、不拦截。观察一段时间确认误报率后再切 enforce。
			Mode:      "audit",
			RulesFile: home + "/.local/jump-server/policy.yaml",
			Pacing: PacingConfig{
				Enabled:             true,
				MaxCommandsPerBatch: 10,
				IntraBatchMinMS:     800,
				IntraBatchMaxMS:     2500,
				BatchCooldownMS:     3000,
			},
		},
	}

	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return Config{}, fmt.Errorf("read config file error: %w", err)
		}
		if err := yaml.Unmarshal(b, &cfg); err != nil {
			return Config{}, fmt.Errorf("unmarshal config yaml error: %w", err)
		}
	}

	if err := cfg.Verify(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}
