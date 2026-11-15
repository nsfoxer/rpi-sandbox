# 策略与配置

## 1. 规则模型

```rust
pub struct SandboxPolicy {
    pub enabled: bool,
    pub mode: SandboxMode,             // Auto | Required | Off
    pub writable: Vec<PathRule>,
    pub protected: Vec<PathRule>,
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
protected  >  writable  >  默认只读
```

- 目录规则递归命中；文件规则精确匹配。
- 路径在编译阶段做词法归一化，并在存在时解析软链（`/srv -> /var/srv` 这类情况）。
- 不存在的写目标按“最深的已存在祖先 + 剩余组件”解析，保证规则和运行时一致。

## 2. 配置位置

| 位置 | 作用 | 权限 |
|---|---|---|
| `~/.rpi/agent/sandbox.json` | 全局策略 | 可增删可写路径、可关闭沙箱 |
| `<cwd>/.rpi/sandbox.json` | 项目策略 | **只能追加 `protected`，不能放宽或关闭** |
| 命令行参数 | 本次运行 | 与全局同权；用户显式意图 |
| 环境变量 `RPI_SANDBOX=0` | 本次运行关闭 | 用户显式意图 |

推荐的全局配置：

```jsonc
{
  "enabled": true,
  "mode": "auto",
  "writable": ["${cwd}", "${tmp}", "${cwd}/.rpi"],
  "protected": [
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

项目配置示例（只能收紧）：

```jsonc
{
  "protected": ["${cwd}/secrets", "${cwd}/.env"]
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

## 6. 嵌套保护（已知限制）

内核沙箱（Landlock / Seatbelt / restricted token）只能“累加权限”，不能从已允许的父目录中
扣除子目录。因此：

- `protected` 落在 `writable` 根之外：天然生效（没有规则覆盖它）。
- `protected` 落在 `writable` 根之内：内核无法排除；启动器/扩展必须
  - `mode = auto`：明确警告；
  - `mode = required`：拒绝启动；
  - 或者由扩展在工具层额外拦截（advisory，不覆盖子进程）。

后续可通过“枚举可写根的子目录并逐项授权”的方式实现，但需要评估大目录的启动成本。

## 7. 维护类命令

`install` / `uninstall` / `update` / `auth` / `extension` / `package` / `resource` /
`events` / `session` / `dev` 由用户主动发起，需要写 `~/.rpi`、`~/.local/bin` 等位置：

- launcher 默认**不隔离**这些子命令，并打印一行 `sandbox: bypassed (maintenance command)`；
- 模型在会话内无法获得同样的绕过能力（沙箱域继承，重新执行 rpi 也无法逃逸）。

## 8. 与其他配置的关系

- `models.json`、插件配置不受影响；它们只读。
- 会话目录若被自定义到白名单之外，会由扩展/launcher 自动加入可写，否则 rpi 无法写入会话。
- `--no-sandbox` / `RPI_SANDBOX=0` 只影响本次进程，不修改持久配置。
