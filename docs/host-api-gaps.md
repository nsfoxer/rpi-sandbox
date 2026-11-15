# Host API 核查与缺口

结论：**v1 不需要新增 host API**。现有扩展能力足以实现 launcher + 扩展方案；
建议只补文档与契约测试。下面逐项给出证据，避免重复造接口。

## 1. 已存在的能力

### 1.1 扩展提供/替换工具

- SDK：`PluginApi::register_tool`（`crates/rpi-plugin-sdk/src/lib.rs`）。
- 宿主合并逻辑：`crates/rpi-cli/src/session.rs::merge_extension_tools`：
  - 找到同名内置工具时 `Some(slot) => *slot = harness_tool`，即**扩展覆盖内置**；
  - 找不到时 push 新工具；
  - 仍然受 `--tools` / `--exclude-tools` / `--no-tools` 约束。
- 现状问题：这是隐含行为，未在 `docs/extensions/authoring.md` 中作为正式契约说明。

**建议**：补文档 + 一个测试（扩展注册 `write` 后宿主使用扩展实现），不加 API。

### 1.2 工具调用前拦截（veto）

- `EventTag::ToolCall`；
- `crates/rpi-extensions/src/translate.rs::dispatch_tool_call_event` 会返回 veto 字符串并阻止执行；
- handler 在异步上下文中运行，携带 `UiDialogMailbox` 与取消令牌。

**用途**：扩展可以在 `write` / `edit` / `bash` 执行前按策略判断，并弹出授权对话框。

### 1.3 用户授权对话框

- Runtime action 17：`RuntimeActionId::UiDialog`，`op = open | poll | cancel`；
- `rpi_plugin_sdk::dialogs::validate` 支持 `purpose: "permission"`，选项必须是
  `allow_once | allow_always | reject_once | reject_always`；
- TUI、`--mode rpc`、ACP（`rpi-acp` 映射为 `session/request_permission`）均可渲染；
- 参考实现：`rpi-permission-gate` 扩展。

**结论**：跨前端的授权请求已具备，不需要新 API。

### 1.4 生命周期

已存在的事件（节选）：

- `SessionStart` / `SessionShutdown`
- `BeforeAgentStart`（可改系统提示词）
- `ToolCall`（veto）
- `ToolExecutionStart/Update/End`
- `BeforeTuiStart`、`UiPromptStart/End`、`EditorChange`

**结论**：沙箱扩展需要参与的阶段都已覆盖。

### 1.5 状态、命令、资源

- `SetStatus`（action 18）：页脚状态；
- `register_command`：`/sandbox`、`/sandbox revoke`；
- `ResourcesDiscover`：扩展自带文档/资源；
- `GetExecutionContext`（action 23）：cwd、model、tools、session id；
- `GetCliFlag`（action 16）：读取 CLI 开关（可用于 `--sandbox` 等）。

**结论**：状态/命令/配置读取均已具备。

### 1.6 配置与持久化

- 扩展可读取 `RPI_CODING_AGENT_DIR` / 会话路径等环境变量；
- 可自行读写 `~/.rpi/agent/sandbox.json`、审计文件和授权持久化文件；
- 写入受整进程沙箱约束时，需要把这些路径加入 launcher 的可写白名单（或通过 broker 写）。

**结论**：不需要 host 的文件存储 API。

## 2. 真正的缺口（可选，不属于 v1）

### 2.1 保留内置工具、只替换执行环境

如果维护者希望“内置 `write`/`edit`/`bash` 继续使用，但文件/命令操作交给扩展提供的
执行环境”，那么当前 ABI 做不到：Rust trait 无法跨 C ABI。最小替代方案是通用授权事件：

```text
EventTag::BeforeFileOperation { op, path, bytes }
EventTag::BeforeShellCommand  { command, cwd }
```

- 扩展返回 allow / deny（可附带延迟授权结果）；
- 宿主仍执行操作，保留内置语义（截断、图片、mutation queue、超时等）；
- 这是 advisory 边界，不是内核边界；与 launcher 的整进程隔离互补。

**建议**：只在 PoC 证明“veto + 工具替换”不够时再提案，并提供具体失败用例。

### 2.2 Whole-process early-startup 钩子

- 如果希望用户仍然直接运行 `rpi`（不额外启动 launcher），需要 host 在创建 Tokio
  runtime 之前执行一个通用初始化钩子；
- 必须是**通用**能力（例如 pre-runtime init、seccomp、rlimit、cgroup），不能只为沙箱服务；
- 维护者要求单独设计讨论。

**建议**：v1 不做；launcher 已能覆盖整进程边界。

## 3. 需要向上游提交的最小改动

| 改动 | 类型 | 说明 |
|---|---|---|
| `docs/extensions/authoring.md`：说明同名工具覆盖规则 | 文档 | 明确优先级、与 `--tools` 的交互、失败模式 |
| 测试：扩展注册同名 `write` 后被使用 | 测试 | 放在 `rpi-cli` 或 `rpi-extensions` 的集成测试 |
| 测试：`ToolCall` veto + permission 对话框 | 测试 | 可参考现有 `dispatch_tool_call_event` 测试与 `rpi-permission-gate` |
| （可选）`before_file_operation` / `before_shell_exec` 提案 | 设计 | 仅在需要保留内置工具时提出 |

以上都不涉及插件 ABI 变更。
