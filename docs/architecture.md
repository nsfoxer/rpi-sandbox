# 架构：整进程文件系统沙箱

## 1. 目标与非目标

### 目标

- **整进程隔离**：`rpi` 本体、所有已加载插件、`bash` 及其后代共享同一个文件系统边界。
- **读不受限，写有白名单**：默认只允许写 `cwd`、系统临时目录、会话目录和显式配置。
- **动态授权**：用户可以临时允许某个路径（一次 / 本会话），由 broker 代执行。
- **跨平台**：Linux / macOS / Windows 使用各自的启动前隔离机制。
- **host 保持通用**：不把沙箱策略、配置或平台细节放进 `rpi` 上游。

### 非目标（v1）

- 不限制读操作（后续可作为 Phase 5 扩展）。
- 不限制网络、进程创建或信号（同上）。
- 不保护“未经 launcher 启动”的 `rpi` 进程。
- 不持久化未决授权到磁盘（避免重启后自动弹出越权写）。

## 2. 组件与数据流

```text
用户执行
  │
  ▼
┌──────────────────────────────────────────────────────────────────┐
│ rpis launcher                                                    │
│  1. 解析参数 / 读取策略（profile）                                 │
│  2. 创建监听 socket（Unix socket / Windows 命名管道）              │
│  3. fork broker（保持在沙箱之外）                                  │
│  4. 应用平台隔离后端                                              │
│  5. exec rpi（隔离随 exec 继承）                                   │
└───────────────┬──────────────────────────────────────────────────┘
                │ exec
                ▼
┌──────────────────────────────────────────────────────────────────┐
│ rpi host（已被整进程隔离）                                         │
│  · Tokio runtime、内置工具、所有插件                               │
│  · sandbox 扩展                                                   │
│      ├─ ToolCall veto：策略判断 + UiDialog permission              │
│      ├─ 配置 / 授权持久化 / 审计 / /sandbox / 页脚状态              │
│      └─ 已批准的越权写 ───────────────┐                            │
└───────────────────────────────────────┼──────────────────────────┘
                                        │ JSON Lines over socket
┌───────────────────────────────────────▼──────────────────────────┐
│ broker（在限制生效前 fork，保持不受限）                            │
│  · 二次校验路径与授权                                              │
│  · 执行 write / append / truncate / delete / rename / mkdir        │
│  · 追加审计日志                                                    │
└──────────────────────────────────────────────────────────────────┘
```

### 后端抽象（`core::backend`）

平台差异被收敛到三个类型里，其余代码共用：

| 类型 | 作用 |
|---|---|
| `BackendCapabilities` | 该后端能强制什么（能否扣除 protected、是否有持久副作用、是否需要读根…） |
| `BackendPlan` | 后端计划（Landlock 规则 / MXC 路径策略 / 无），可用 `--print-plan` 打印、可跨平台单测 |
| `SandboxBackend` | `plan(policy)` + `launch(plan, spec)`；`launch` **允许不返回**（Unix 内部 `exec`） |

`LaunchSpec` 里已包含 CLI 解析结果、编译后的策略、环境变量增删、扩展注入后的参数、broker
配置与读根，所以后端实现里不再出现任何 CLI/策略/协议代码。

### 启动顺序（关键）

1. launcher 在**单线程**状态下完成参数与策略解析。
2. 建立 broker 端点（Unix socket / Windows 命名管道）；broker 不加载插件、不解析模型输出。
3. 应用隔离：
   - Linux / macOS：对**自身**应用域（Landlock / Seatbelt），随后 `exec rpi`；
   - Windows：用 `mxc-sdk` 创建 MXC 容器（`Containment::Process`），把 `writable` /
     `read_roots` / `protected` 映射为 `readwrite_paths` / `readonly_paths` /
     `denied_paths`；父进程保持不受限，作为 broker 并等待容器退出。
4. 此后创建的所有线程和子进程都继承该边界。
5. rpi 加载扩展。扩展发现自己处于沙箱内（环境变量），开始执行策略与 UI。

## 3. 信任模型

| 主体 | 信任级别 | 说明 |
|---|---|---|
| 模型输出 | 不可信 | 可能被提示注入，尝试写 `~/.ssh`、插件目录等 |
| 项目仓库及其配置 | 不可信 | 只能追加保护规则，不能放宽或关闭沙箱 |
| rpi 宿主代码 | 可信 | 但仍在沙箱内运行 |
| 第三方扩展 | 不完全可信 | 与宿主同进程，因此需要 launcher 的进程级边界 |
| sandbox 扩展 | 可信 | 负责策略与授权交互 |
| broker | 受信任、极小 | 唯一有权执行越权写的组件 |
| 用户授权 | 可信 | 来自 TUI / RPC / ACP 前端 |

设计含义：`ToolCall` veto 和 `UiDialog` 只能做“询问 / 拒绝”；真正的边界由 launcher
建立的内核域提供。扩展不得声称自己在没有 launcher 时提供内核边界。

## 4. 职责划分

### launcher / broker

- 读取 profile 与策略（可复用 core 的策略编译）。
- 平台后端：
  - Linux：Landlock，`exec` 前对启动器自身应用。
  - macOS：Seatbelt，`sandbox_init` 后 `execve`；沙箱随 exec 继承。
  - Windows：MXC `processcontainer`，把策略映射为容器文件系统规则；不修改 ACL。
- broker 协议见 `protocol.md`。
- 退出码、信号与子进程状态透传；崩溃时清理 socket（MXC 没有 ACL 残留）。

### sandbox 扩展

- 配置：`~/.rpi/agent/sandbox.json`（全局）与 `.rpi/sandbox.json`（项目，只能收紧）。
- `ToolCall` veto：解析 `write` / `edit` / `bash` 参数，按策略判断。
- 授权：`UiDialog`，`purpose: "permission"`，选项 `allow_once` / `allow_always` / `reject_once`。
- 越权写：把已批准的路径和操作发给 broker。
- 审计、`/sandbox`、`/sandbox revoke`、`SetStatus` 页脚状态。
- 检测 `RPI_SANDBOX_ACTIVE`；未经过 launcher 时提示“未隔离”。
- `before_agent_start`：把可写根、拒绝语义（`EACCES` 是沙箱而非权限问题）、
  `write`/`edit` 授权路径和“blocked 可能已写入”写进 system prompt（只追加，不替换）。

### host（rpi 上游）

- v1：不需要新增 API。
- 建议补充：文档化“同名工具替换”和“ToolCall veto + permission dialog”契约，并加测试。
- 可选（非 v1）：通用 `before_file_operation` / `before_shell_exec` 授权事件。
- 可选（未来）：范围很窄的通用 pre-runtime 初始化钩子；仅在维护者希望“用户仍直接运行
  `rpi`”时单独提案。

## 5. 边界与降级

| 场景 | 行为 |
|---|---|
| 经 launcher 启动 | 整进程边界（Landlock 域 / MXC 容器）；扩展负责策略与授权 |
| 未经 launcher 启动 | 扩展提示“当前未隔离”；可选降级为工具级 gating（advisory） |
| launcher 不支持当前平台 | 按配置：警告并继续，或拒绝启动（`required`） |
| 用户关闭沙箱 | launcher 直接 `exec rpi`；扩展可提示沙箱未启用 |
| broker 不可用 | 越权写直接拒绝；基础白名单写入仍受内核保护 |

## 6. 安全不变量

1. 读操作不因沙箱失败。
2. 写操作只允许白名单内的路径；`protected` 永远优先于 `writable`（broker 强制执行；
   内核只在规则可表达时执行）。
3. 项目配置不能扩大可写范围，也不能关闭沙箱。
4. 越权写只能由 broker 在用户授权后执行；沙箱进程始终没有该路径的写权限。
5. 未经过 launcher 时不得声称“已整进程隔离”。
6. 未决授权不跨进程重启持久化。

## 7. 为什么不用“host 内置”或“纯扩展”

- **纯扩展**：扩展加载时 runtime 线程已存在；Landlock 按线程生效，无法覆盖已有线程，
  也无法约束任意原生插件。
- **host 内置**：会把平台后端、策略、审批和 UI 全部绑进上游；维护者明确要求保持 host
  通用，并建议 launcher 或单独的 early-startup 设计。
- **launcher + 扩展**：隔离在进程外建立，策略和 UX 在有 ABI 保障的扩展侧演进，二者解耦。
