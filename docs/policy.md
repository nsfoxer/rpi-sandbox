# 策略与配置

## 1. 规则模型

```rust
pub struct SandboxPolicy {
    pub enabled: bool,
    pub mode: SandboxMode,             // Auto | Required | Off
    pub writable: Vec<PathRule>,
    pub readonly: Vec<PathRule>,
    pub allow_file_writes: Vec<PathRule>,
    pub approval: ApprovalSettings,
    pub audit_log: Option<PathBuf>,
}

pub enum PathRule {
    Dir(PathBuf),   // 递归
    File(PathBuf),  // 精确文件
}
```

优先级：

```text
readonly  >  writable  >  默认只读
```

- 目录规则递归命中；文件规则精确匹配。
- 路径在编译阶段做词法归一化，并在存在时解析软链（`/srv -> /var/srv` 这类情况）。
- 不存在的写目标按“最深的已存在祖先 + 剩余组件”解析，保证规则和运行时一致。

## 2. 配置位置

| 位置 | 作用 | 权限 |
|---|---|---|
| `~/.rpi/agent/sandbox.json` | 全局策略 | 可增删可写路径、可关闭沙箱 |
| `<cwd>/.rpi/sandbox.json` | 项目策略 | **只能追加 `readonly`，不能放宽或关闭** |
| 命令行参数 | 本次运行 | 与全局同权；用户显式意图 |
| 环境变量 `RPI_SANDBOX=0` | 本次运行关闭 | 用户显式意图 |

路径展开使用 `${cwd}` / `${home}` / `${tmp}` 与 `~`。`${home}` 在 Windows 上取
`USERPROFILE`（`HOME` 在 MSYS2 下可能是 `/c/Users/...`，不是合法 Windows 路径），
`${tmp}` 优先取 `TEMP`/`TMP`。

Windows 后端（MXC）的读范围是**显式白名单**：除了系统默认目录，只暴露 `writable` 根、
`read_roots`（`--read`、rpi/launcher 目录、agent 目录）以及它们的卷根。未列出的用户目录
默认不可读；`readonly` 以 `readonly_paths` 覆盖，因此在可读范围内仍然**可读但不可写**。

推荐的全局配置：

```jsonc
{
  "enabled": true,
  "mode": "auto",
  "writable": ["${cwd}", "${tmp}", "${cwd}/.rpi"],
  "readonly": [
    "${home}/.ssh",
    "${home}/.aws",
    "${home}/.gnupg",
    "${home}/.rpi/agent"
  ],
  "allowFileWrites": ["/dev/null", "/dev/tty"],
  "approval": { "enabled": true, "defaultScope": "session" },
  "auditLog": "${home}/.rpi/audit/sandbox.jsonl"
}
```

推荐把「下次启动会被加载的东西」也放进 `readonly`，例如 `${cwd}/.git/hooks`
（阻止 prompt 注入写 git hook）与 `${cwd}/.env`。注意：把整个 `${cwd}/.git` 设为
readonly 会让沙箱内的 `git commit` 失败，因为 git 需要写 `index` 与 `refs`。

项目配置示例（只能收紧）：

```jsonc
{
  "readonly": ["${cwd}/secrets", "${cwd}/.env"]
}
```

## 3. 路径展开

支持：

- `${cwd}`：项目工作目录
- `${home}`：用户主目录
- `${tmp}`：系统临时目录
- `~` / `~/...`
- 相对路径：相对于 `cwd`

`${home}` 未知时该规则被跳过；空字符串被忽略。

## 4. 自动纳入的可写路径

以下路径即使未配置也必须可写，否则 rpi 自身无法工作：

- `cwd`
- 系统临时目录（`TMPDIR` / `/tmp`）
- 实际生效的会话目录（`--session-dir` / `sessionDir` / `RPI_CODING_AGENT_SESSION_DIR`）
- 运行时簿记文件（如 agent 目录下的 `.resource-lease`、`update-check.json`），以**文件级**
  规则加入；agent 目录本身保持只读，避免模型持久化恶意插件。

## 5. 默认值

| 字段 | 默认 |
|---|---|
| `enabled` | `false`（opt-in；本地实验可通过配置开启） |
| `mode` | `auto` |
| `approval.enabled` | `true`（在沙箱启用时） |
| `approval.defaultScope` | `session` |
| `auditLog` | 无（不建议关闭） |

## 6. 嵌套保护（`readonly`）

`readonly` 的定位是「可读不可写」：

| 平台 | 行为 |
|---|---|
| Windows（MXC） | 映射为 `readonly_paths`。MXC 按「更具体的路径优先」，因此可写父目录中的 readonly 子目录**可读、不可写**（新建、修改、删除都被拒）。已实测：`git commit` 能正常读取 `.git/hooks`。 |
| Linux（Landlock） | Landlock 只能累加权限，不能扣除子树。`readonly` 只由扩展工具层和 broker 拦截；`bash` 仍可写。**启动会警告（不拒绝）**，因为内核层没有完整实现。 |

其他规则：

- `readonly` 落在 `writable` 根之外：本来就不可写；工具层/broker 再拒绝；
- `readonly` 与某个 writable 规则相同：Linux 从内核计划中移除该规则，MXC 以只读覆盖；
- `allowFileWrites` 被 `readonly` 覆盖：文件规则被移除；
- `readonly` 路径不存在：不进入内核计划，创建后重启生效（MXC 已实测：不存在的只读路径会被忽略）；
- `bash` 不受工具层限制：Linux 上可以写 readonly；Windows MXC 上由只读子路径拦截。

**定位**：`readonly` 是「工具层 + 平台能力」的保护，不是跨平台一致的内核边界。Linux 的真正
嵌套只读（userns + 只读 bind + 丢 caps）仍在 Phase 5。

## 7. 模型提示（system prompt）

扩展通过 `before_agent_start` 把一段 `## Sandbox (rpi-sandbox)` 追加到 system prompt：

- 列出当前可写根（超过 12 条时折叠为 `+N more`）；
- 说明越权写的表现是 `EACCES`（“Permission denied” / “权限不够”），这是沙箱策略，
  不是文件系统、挂载、属主或 ACL 问题，不要用 `sudo`、`chmod`、换路径、软链、
  `/proc/*/root` 或重复同一写入来“排查”；
- 说明 `bash` 不能请求授权，越权写要走 `write` / `edit`；授权关闭时明确写“永远拒绝”；
- 说明 `write`/`edit` 返回 “blocked by `rpi-sandbox-extension`” 时可能已经由 broker 写入，
  应该用 `read` 确认而不是重试；
- readonly 只给数量，不列路径（`/sandbox` 给用户看完整列表）；
- 提示 `RPI_SANDBOX_ACTIVE=1`，模型不需要再探测挂载表。

实现约束：

- 只在 `systemPrompt` 非空时追加；空提示词时保持不变，绝不把整段 prompt 替换成沙箱说明；
- 用标题做幂等标记，`/reload` 不会重复叠加；
- host 没有该 slot 时跳过，`/sandbox` 显示 `model hint: unsupported by this host`；
- 这是“告知”，不是强制；真正的边界仍是 Landlock + broker。

## 8. 维护类命令

`install` / `uninstall` / `update` / `auth` / `extension` / `package` / `resource` /
`events` / `session` / `dev` 由用户主动发起，需要写 `~/.rpi`、`~/.local/bin` 等位置：

- launcher 默认**不隔离**这些子命令，并打印一行 `sandbox: bypassed (maintenance command)`；
- 模型在会话内无法获得同样的绕过能力（沙箱域继承，重新执行 rpi 也无法逃逸）。

## 9. 与其他配置的关系

- `models.json`、插件配置不受影响；它们只读。
- 会话目录若被自定义到白名单之外，会由扩展/launcher 自动加入可写，否则 rpi 无法写入会话。
- `--no-sandbox` / `RPI_SANDBOX=0` 只影响本次进程，不修改持久配置。
