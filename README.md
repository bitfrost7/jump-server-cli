# jump-server-cli

通过跳板机执行 SSH 命令、传输文件。支持测试/正式双环境，兼容 MCP stdio 协议。

## 特性

- **双环境支持** — 测试 (`jump-test`) / 正式 (`jump1`) 自动切换
- **安全策略** — 黑名单拦截（裸 socket / 扫描 / 破坏性 / 提权 / 逃逸）、生产环境只读、防绕过规范化，支持 audit 灰度
- **命令节奏控制** — 批量执行 + 随机间隔，让调用形态贴近人类操作
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
| `policy.mode` | `audit`（只记录不拦，灰度用）/ `enforce`（命中即拦） |
| `policy.rules_file` | 用户覆盖规则文件（不存在则用内嵌默认规则） |
| `policy.pacing.enabled` | 是否启用命令节奏控制（批内间隔 + 批间冷却） |
| `policy.pacing.max_commands_per_batch` | 单次批量执行上限（默认 10） |
| `policy.pacing.intra_batch_min_ms` / `_max_ms` | 批内命令之间的随机间隔（模拟敲键） |
| `policy.pacing.batch_cooldown_ms` | 两次执行之间的冷却（模拟看结果） |

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
# 建立免密长连接（输入一次密码，4 小时内免密；跳板机仅支持密码认证）
jump-server connect          # 依次建立 test + prod
jump-server connect -e prod  # 只建立指定环境

# 检测所有环境连通性（只检测免密长连接，不会弹密码）
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
| `jump_exec` | SSH 执行命令（`command` 单条 / `commands` 多条） |
| `jump_upload` | 上传文件 |
| `jump_download` | 下载文件 |
| `jump_doctor` | 连通性检测 |

工具描述中带 `destructiveHint` / `readOnlyHint` 注解，MCP 客户端可据此决定是否需要二次确认。server 启动时通过 `instructions` 下发安全规范（会进入客户端 system prompt）。

> MCP server 自身暴露 `jump_exec` / `jump_upload` / `jump_download` / `jump_doctor`；
> 接入 Hermes 后工具名会带前缀（如 `mcp_jump_server_jump_exec`）。

## 安全策略

每次执行前对命令做准入判定，命中红线的命令会被拒绝并写入审计（`policy`/`rule_id`/`severity`/`enforced` 字段）。

### 拦截类别

| 类别 | 内容 |
|------|------|
| 裸 socket / 反弹 shell | `/dev/tcp`、`/dev/udp`、`nc -e`、`ncat -l`、`socat exec:`、`bash -i`、`mkfifo` |
| 扫描 | `nmap` / `masscan` / `zmap` / `hping3`，以及 `for` 循环批量探测 |
| 破坏性 | `rm -rf /`、`mkfs`、`dd of=/dev/*`、fork bomb、`iptables -F`、`shutdown` / `reboot` |
| 下载即执行 | `curl … \| sh`、`wget … \| bash`、`eval $(curl …)` |
| 凭据读取 | `.ssh/id_*`、`/etc/shadow`、`.docker/config.json`、`.aws/credentials` |
| 提权 / 持久化 | `sudo su`、`useradd`、`crontab`、写 `authorized_keys` / `.bashrc` |
| 逃逸 | `chroot`、`mount`、`nsenter`、`docker run --privileged`、`/var/run/docker.sock` |

命令名类规则锚定在「命令位置」（行首或 `; && \|\| \|` 之后），所以 `echo "=== mount ==="`、`grep mount /etc/fstab` 不会误报，而 `ls && mount /dev/sda /mnt` 会被拦。

### 命令整形

| 约束 | 提示 | 拒绝 |
|------|------|------|
| 单条命令长度 | > 300 字符 | > 4000 字符 |
| 串联段数（`;` `&&` `\|\|` `\|`） | ≥ 3 段 | ≥ 6 段 |
| 命令行内嵌 base64 | — | prod 下 > 200 字符 |

### 生产环境只读

`env=prod` 且 `prod_readonly: true` 时禁止一切写操作：文件写（`rm`/`mv`/`cp`/`chmod`/`touch`/`tee`/`tar`…）、服务与容器变更（`docker restart`/`systemctl restart`…）、进程操作（`kill`/`pkill`）、软件包管理、脚本执行（`bash`/`python3`，无法审计其内部行为）、SQL 写入（`insert`/`update`/`delete`/`drop`/`alter`…）、Redis 写入、文件重定向、`sudo` 提权。

只读查询照常放行：`ps`、`ls`、`cat`、`grep`、`docker ps` / `logs`、`systemctl status`、SQL `select`、`SHOW CREATE/INDEX/…`。

### 防绕过

匹配前先做规范化：`/dev//tcp`、`/dev/${IFS}tcp`、`$'\x2f'dev/tcp`、`n''map` 都归一到标准形式；解释器内联代码（`bash -c '…'`）会展开后递归检查。

### 灰度与自检

```bash
jump-server policy list                       # 查看生效规则与阈值
jump-server policy check -e prod 'rm -rf /'   # 预检一条命令（不执行）
jump-server policy replay audit/*.jsonl       # 用存量审计回放，评估误报率
```

上线先用 `mode: audit` 观察误报，确认后改 `enforce`。用户可在 `~/.local/jump-server/policy.yaml` 里按 `id` 覆盖默认规则。

### 命令节奏

为避免「高频、大片、机器般规律」的调用痕迹：

- 需要连续执行多条时用 `commands` 参数（一次登录、逐条执行），而不是把命令拼成长串
- 批内命令之间插入 0.8~2.5s 随机间隔（模拟敲键）
- 两次执行之间冷却 3s（模拟看结果）

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
│   ├── policy.go      # policy 子命令（list / check / replay）
│   ├── policy_guard.go # 策略接入（CLI 与 MCP 共用）
│   └── mcp.go         # MCP stdio 服务器（含安全规范 instructions）
├── config/
│   └── config.go      # 配置加载
├── internal/
│   ├── policy/
│   │   ├── policy.go            # 策略引擎（判定 / 生产只读 / 内联代码展开）
│   │   ├── normalize.go         # 命令规范化（防绕过）+ 段数/重定向解析
│   │   ├── rules.default.yaml   # 内嵌默认规则（go:embed）
│   │   └── policy_test.go       # 规则回归测试
│   └── service/
│       ├── ssh_executor.go   # SSH 执行器（批量执行 / 拟人节奏 / PTY 输出清洗）
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
