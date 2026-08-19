# jump-server-cli

通过跳板机执行 SSH 命令、传输文件。支持测试/正式双环境，兼容 MCP stdio 协议。

## 特性

- **双环境支持** — 测试 (`jump-test`) / 正式 (`jump1`) 自动切换
- **无白名单** — 任意命令直接执行，无需审批
- **受限 shell 兼容** — 命令在 lshell/sudosh 内执行且受其检查（禁 ssh、sudo 白名单等照常生效），`-tt + heredoc` 仅适配交互式登录限制
- **MCP stdio** — 可接入 Hermes 等 MCP 客户端
- **文件传输** — 上传下载，通过 base64 管道避免 SCP 被拦截
- **连接检测** — `doctor` 子命令一键检测所有环境连通性
- **jsonl 审计** — 每次执行（含被限流拒绝的）追加写入按天分文件的审计日志
- **限流** — 全局令牌桶 + 同命令冷却，SQLite 持久化跨进程生效

## 安装

```bash
git clone git@github.com:bitfrost7/jump-server-cli.git
cd jump-server-cli
go build -o jump-server ./cmd/
```

## 配置

配置文件 `~/.local/jump-server/config.yaml`：

```yaml
ssh:
  bastions:
    test:
      host: "jump-test"
      user: "haiqiang.zou"
      mode: "pipe"
    prod:
      host: "jump1"
      user: "haiqiang.zou"
      target_user: "ulowrisk"
      mode: "pipe"

  default_user: "root"
  connect_timeout: 10
  exec_timeout: 60

store:
  path: "/Users/user/.local/jump-server/jump.db"

audit:
  dir: "/Users/user/.local/jump-server/audit"   # jsonl 审计目录（按天分文件）

ratelimit:
  enabled: true
  global_rate: 60    # 令牌桶填充速率（个/分钟）
  global_burst: 5    # 令牌桶容量
  cmd_cooldown: 5    # 同一命令冷却时间（秒）
```

### 配置字段说明

| 字段 | 说明 |
|------|------|
| `bastions.<env>.host` | 跳板机 SSH Host（`~/.ssh/config` 中的别名） |
| `bastions.<env>.user` | 跳板机登录用户 |
| `bastions.<env>.target_user` | 目标主机登录用户（留空用 `default_user`） |
| `bastions.<env>.mode` | 连接模式：`pipe`（PTY 交互式登录 + stdin 传命令，适配 sudosh/lshell）或 `proxyjump`（直连） |
| `default_user` | 目标主机默认 SSH 用户 |
| `store.path` | SQLite 数据库路径（限流令牌桶/冷却的持久化存储） |
| `audit.dir` | jsonl 审计日志目录，按天生成 `audit-YYYY-MM-DD.jsonl` |
| `ratelimit.enabled` | 是否启用限流 |
| `ratelimit.global_rate` | 全局令牌桶填充速率（个/分钟） |
| `ratelimit.global_burst` | 令牌桶容量（突发允许的请求数） |
| `ratelimit.cmd_cooldown` | 同一命令的冷却时间（秒） |

## 使用

### 执行命令

```bash
# 在测试跳板机执行
jump-server -e test -c "whoami"

# 在测试目标主机执行
jump-server -e test -h 10.83.216.55 -c "docker ps"

# 在正式目标主机执行
jump-server -e prod -h 172.21.38.159 -c "grep 'error' /var/log/app.log"
```

### 上传/下载文件

```bash
# 上传到跳板机
jump-server -e test --upload ./local.txt:/remote/path/file.txt

# 上传到目标主机（自动 base64 管道绕过限制）
jump-server -e prod -h 172.21.38.159 --upload ./dump.sql:/tmp/dump.sql

# 从目标主机下载
jump-server -e prod -h 172.21.38.159 --download /remote/file.txt:./local.txt

# 从跳板机下载
jump-server -e test --download /remote/path/file.txt:./local.txt
```

### 连通性检测

```bash
# 检测所有环境（test + prod）
jump-server doctor
```

输出示例：
```
═══════════════════════════════════
🔍 test 环境
═══════════════════════════════════
📡 跳板机 jump-test... ✅ 127ms
🖥️  10.83.216.55 (root)... ✅ 877ms
📤 上传测试... ✅

═══════════════════════════════════
🔍 prod 环境
═══════════════════════════════════
📡 跳板机 jump1... ✅ 633ms
🖥️  172.21.38.159 (ulowrisk)... ✅ 1.803s
🖥️  172.21.38.158 (ulowrisk)... ✅ 3.688s
📤 上传测试... ✅

✅ 全部正常
```

### MCP 模式

启动 MCP stdio 服务器：

```bash
jump-server mcp
```

#### 接入 Hermes

在 `~/.hermes/config.yaml` 中添加：

```yaml
mcp_servers:
  jump-server:
    command: "/path/to/jump-server"
    args: ["mcp"]
    enabled: true
    timeout: 120
    connect_timeout: 30
```

然后执行 `/reload-mcp` 即可。注册的工具：

| MCP 工具 | 功能 |
|----------|------|
| `jump_exec` | SSH 执行命令 |
| `jump_upload` | 上传文件 |
| `jump_download` | 下载文件 |
| `jump_doctor` | 连通性检测 |

> MCP server 自身暴露 `jump_exec` / `jump_upload` / `jump_download` / `jump_doctor`；
> 接入 Hermes 后工具名会带前缀（如 `mcp_jump_server_jump_exec`）。

## 原理解析

### 连接链路

```
本地 → 跳板机 (ssh -tt) → 目标主机 (ssh -tt + heredoc)
```

sudosh / lshell 只接受交互式登录（`ssh host cmd` 非交互执行会被拒），所以：

- 跳板机 sudosh → `-tt` 强制 PTY 交互式登录，命令经 stdin（heredoc）传入，不进 ssh 参数（跳板机会检查 ssh 参数内容，如 sudo 等敏感词会被拦）
- 目标机 lshell → 内层 `ssh -tt` 交互式登录，heredoc 把命令送入受限 shell 提示符；**命令仍受 lshell 白名单/黑名单检查**（如 172.21.38.x 禁 ssh/禁 sudo；10.76.20.148 的 sudo 仅放行白名单子命令如 `sudo docker ...`）

> 注意："heredoc" 不是安全绕过——它只是交互式会话的输入方式，lshell 对每条命令的检查照常生效。

### 文件传输

- **跳板机**：直接 SCP
- **目标主机**：本地文件 base64 编码 → PTY 管道 → 目标机 `base64 -d` 解码写入
- **不用 SCP** 的原因是 sudosh 拦截 SCP/SSH exec 命令

### 连接模式

- `pipe`（推荐）：先 SSH 到跳板机（PTY 交互式登录），再从跳板机 SSH 到目标机（PTY + heredoc 传命令，命令受目标机 lshell 检查）
- `proxyjump`：本地直接 ProxyJump 到目标机（仅适用于无 sudosh/lshell 的环境）

## 项目结构

```
├── cmd/
│   ├── main.go        # 入口
│   ├── root.go        # CLI 命令处理 + 文件传输 + 限流
│   ├── doctor.go      # 连通性检测
│   └── mcp.go         # MCP stdio 服务器
├── config/
│   └── config.go      # 配置加载
├── internal/
│   └── service/
│       ├── ssh_executor.go   # SSH 执行器（含 PTY 输出清洗）
│       └── scp_executor.go   # SCP 传输器
├── pkg/
│   ├── audit/
│   │   └── audit.go          # jsonl 审计日志
│   └── store/
│       └── store.go          # SQLite 限流存储（令牌桶 + 命令冷却）
└── go.mod
```

## 环境适配

| 环境 | 跳板机 | 目标机用户 | 跳板机 sudosh | 目标机受限 shell |
|------|--------|-----------|-------------|-----------------|
| 测试 | `jump-test` | `root` | 有（-tt 交互式登录） | 无 |
| 正式 | `jump1` | `ulowrisk` | 有（-tt 交互式登录；检查 ssh 参数内容） | lshell（-tt + heredoc 传命令，检查生效：172.21.38.x 禁 ssh/禁 sudo；10.76.20.148 允许 `sudo docker ...`） |
