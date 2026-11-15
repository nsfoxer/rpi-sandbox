# 交给下一个 AI 的执行手册

本文件是**唯一入口**。先完整读一遍，再按 Phase 0 开始。所有设计细节以
`architecture.md`、`policy.md`、`protocol.md`、`host-api-gaps.md`、`roadmap.md` 为准；
若与本文件冲突，以那些文档为准并更新本文件。

## 0. 任务与边界

**要做**：一个可用的整进程文件系统沙箱，由 launcher 建立内核边界，扩展负责策略、配置、
授权、审计、命令与状态。

**硬约束（违反即返工）**：

1. **不修改 rpi 上游 host 的架构或插件 ABI**。不要向上游提“把沙箱放进 host”的 PR。
2. 整进程隔离只能由 launcher 在 `exec rpi` 之前建立。扩展不得声称自己提供内核边界。
3. 没有经过 launcher 启动时，扩展必须明确提示“当前未隔离”，只能做 advisory gating。
4. `rpi-sandbox-core` 不依赖任何 `rpi-*` crate；扩展只依赖 `rpi-plugin-sdk`
   （需要时加 `serde`、`serde_json` 等普通依赖）。
5. 策略、配置、审批持久化、审计、命令、状态都放在扩展/核心库，不放进 host。
6. 默认 **opt-in**（`sandbox.enabled` 默认 false）；不要默默改变已有用户行为。
7. 所有新增行为必须有离线测试（不访问网络、不依赖真实模型）。

**明确不做（v1）**：

- 读/网络/进程限制；
- 未决授权跨进程持久化；
- host early-startup 钩子（仅在维护者明确要求时另案讨论）；
- GUI 客户端（复用现有 `UiDialog` 即可）。

## 1. 工作区

已创建（Phase 0）：

```text
sandbox/
├── Cargo.toml                 # workspace，edition 2021，rust-version 1.88
├── crates/
│   ├── rpi-sandbox-core/      # policy / path / protocol / broker / probe / linux
│   ├── rpi-sandbox-launcher/  # bin；Phase 1 实现
│   └── rpi-sandbox-extension/ # cdylib；Phase 2 实现
└── docs/
```

初始命令（记录用）：

```bash
cd /var/home/nsfoxer/桌面/src/rpi/sandbox
git init
cargo new --lib crates/rpi-sandbox-core
cargo new --bin crates/rpi-sandbox-launcher
cargo new --lib crates/rpi-sandbox-extension   # crate-type = ["cdylib"]
```

根 `Cargo.toml`：

```toml
[workspace]
members = [
  "crates/rpi-sandbox-core",
  "crates/rpi-sandbox-launcher",
  "crates/rpi-sandbox-extension",
]
resolver = "2"

[workspace.package]
edition = "2021"
rust-version = "1.88"
license = "MIT"
```

扩展的 `Cargo.toml`：

```toml
[lib]
crate-type = ["cdylib"]

[dependencies]
rpi-plugin-sdk = "0.24"   # 公开 SDK，与目标宿主版本一致
rpi-sandbox-core = { path = "../rpi-sandbox-core" }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

扩展可以依赖自有的 `rpi-sandbox-core`（共享 policy/protocol 类型）；硬约束是
**core 不依赖任何 `rpi-*` crate**，扩展不依赖 host 私有模块。launcher 依赖 core；
core 的 `libc` 仅在 Unix 启用。

## 2. 可复用的现有代码

参考分支：`/var/home/nsfoxer/桌面/src/rpi/pi-rust`，分支 `feat/fs-sandbox`
（对应已关闭的 host PR）。可直接搬迁、再按新边界拆分：

| 文件 | 去向 | 说明 |
|---|---|---|
| `crates/rpi-sandbox/src/policy.rs` | core | 规则、展开、归一化、优先级、项目收紧 |
| `crates/rpi-sandbox/src/linux.rs` | core | Landlock 计划与 `apply`；ABI 掩码、`ref/truncate` |
| `crates/rpi-sandbox/src/broker.rs` | core | 审批存储、协议、审计、客户端 |
| `crates/rpi-sandbox/src/approval.rs` | core | 数据类型（可精简） |
| `crates/rpi-sandbox/src/probe.rs` | core | 平台能力探测；`linux.rs` 依赖 Landlock ABI 查询 |
| `crates/rpi-cli/src/sandbox.rs` | launcher + extension | 启动顺序、绕过、回退、状态 |
| `crates/rpi-cli/src/sandbox_approval.rs` | 删除 | TUI 审批桥；由扩展的 `UiDialog` 取代 |
| `crates/rpi-cli/src/interactive_tui/extensions.rs`（审批对话框） | 删除 | 由扩展的 `UiDialog` 取代 |
| `crates/rpi-tools/src/error.rs` 的提示 | 可选 | 扩展侧生成更清晰的错误即可 |

搬迁时**不要**带走 host 侧的 `rpi-cli` / `rpi-tools` / `rpi-tui` 改动。

## 3. 分阶段任务

### Phase 0（已完成）

- [x] 建 workspace 与三个 crate 骨架
- [x] 迁入策略与 broker 代码，去掉对 `rpi-*` 的依赖
- [x] 按 `protocol.md` 修改协议：加 `v`、`hello`、错误码、绝对路径与授权复检
- [x] 单元测试：规则优先级、展开、项目收紧、协议 round-trip、审批存储
- [x] 在本目录 `git commit`（建议 `feat(core): ...`）

**完成标准**：`cargo test -p rpi-sandbox-core` 全绿；文档与代码一致。

### Phase 1（已完成）

- [x] launcher：参数解析、socket、fork broker、Landlock、`exec`
- [x] 信号/退出码/清理
- [x] 集成测试：允许写、读放行、越界写拒绝、bash 后代继承、broker 授权写
- [x] 手工验收：`rpis --write <tmp> -- rpi -p "..."`（本机以 `/bin/sh` 载荷验证）

**完成标准**：`cargo test` 全绿；`docs/platforms/linux.md` 的验收清单全部打勾。

### Phase 2（实现完成，交互验收待人工）

- [x] 读 `RPI_SANDBOX_*`；未隔离提示
- [x] `ToolCall` veto：`write`/`edit`/`bash`
- [x] `UiDialog`（`purpose: permission`）授权：once/session/directory/reject
- [x] 越权写经 broker；`check` 短路
- [x] 配置、审计、`/sandbox`、`/sandbox revoke`、`SetStatus`
- [x] 测试：策略、授权、headless 拒绝（TUI/RPC 需要宿主级测试）

**完成标准**：交互式可授权写入（待人工）；`-p` 默认拒绝；扩展只用公开 SDK。完成标准中的
交互项需要在安装了 rpi 且配置了可用 provider 的机器上人工确认。

### Phase 3 / 4

按 `roadmap.md` 与 `platforms/*.md` 执行。每个后端都必须复用同一套集成测试断言。

## 4. 关键实现提示

### launcher 启动顺序

1. 参数与策略解析必须**在单线程**完成。
2. 先建 socket 并 fork broker；broker 不能加载插件，也不能应用隔离。
3. 再应用平台隔离；Linux 用 `landlock_restrict_self`，macOS 用 `sandbox_init`，
   Windows 用 `CreateProcessAsUserW`（受限于 token 机制，Windows 的“父进程”负责等待/清理）。
4. `exec rpi`；子进程退出时把状态码透传给用户。

### 扩展注册与 veto

- 扩展只注册/覆写需要拦截的工具名；不要重复实现内置 `write`/`edit`，除非必须。
- `ToolCall` handler 中解析参数要防御式：缺字段、类型错误、相对路径都要处理。
- 授权对话框的选项必须使用 `permission` 语义（`allow_once`/`allow_always`/`reject_once`），
  不要用自由文本。
- 授权被拒后返回 veto，并给出清晰原因；不要静默继续。

### broker

- 只接受绝对路径；`realpath` 后必须仍在授权子树内。
- 每次写操作前校验授权；`once` 授权用后即焚。
- 审计失败不能阻止写操作，但要 stderr 警告。
- 协议版本不匹配直接拒绝，不做兼容猜测。

### 错误信息

面向模型/用户的错误要说明：路径、操作、为什么被拒、如何授权。
参考：`permission_denied` + “Approve interactively or add it to sandbox.writable”。

## 5. 测试与命令

每个 Phase 至少运行：

```bash
cargo fmt --all -- --check
RUSTFLAGS="-D warnings" cargo check --workspace --all-targets
RUSTFLAGS="-D warnings" cargo test --workspace
```

如果本机有 `SSH_ASKPASS`（KDE 环境常见），跑 rpi 相关测试时用：

```bash
env -u SSH_ASKPASS cargo test ...
```

平台后端测试：

- Linux：Landlock 子进程测试（参考 `crates/rpi-sandbox/tests/landlock_enforcement.rs`）。
- macOS：Seatbelt 应用后子进程写测试。
- Windows：restricted token 子进程写测试 + ACL 清理断言。

禁止依赖真实 provider / 网络；所有测试必须离线可重复。

## 6. Definition of Done（每个 PR/阶段）

- [ ] 行为与 `architecture.md`、`policy.md`、`protocol.md` 一致
- [ ] 新增/修改行为有测试，且离线可跑
- [ ] `cargo fmt --check`、`cargo check -D warnings`、`cargo test` 通过
- [ ] 文档同步更新（不要只改代码）
- [ ] 提交信息使用 Conventional Commits，例如：
  - `feat(core): add landlock ruleset planner`
  - `feat(launcher): apply isolation before exec`
  - `feat(ext): add permission-gated writes`
- [ ] 不引入对 `rpi-*` 的反向依赖；不改插件 ABI
- [ ] 在 `roadmap.md` 勾选对应任务

## 7. 已知坑

1. **Landlock 按线程生效**：必须在创建 Tokio runtime / 插件加载之前应用。
2. **Landlock 规则绑定 inode**：启动后删除重建的可写目录会失效，重启恢复。
3. **软链根**：Fedora 上 `/srv -> /var/srv`、`/home -> /var/home`；路径解析要“最深的已存在
   祖先 + 剩余组件”。
4. **嵌套 `protected`**：内核不能从可写父目录中扣除子树；启动警告或 `required` 拒绝。
5. **Windows ACL**：修改是持久的；用事务 + 崩溃清理，避免残留。
6. **Windows `bcrypt.dll`**：restricted token 下 `DllMain` 失败；准备 crypto provider 切换
   或 shim，并写进文档。
7. **macOS Seatbelt**：API deprecated；保留 `sandbox-exec` 回退方案，路径先 `realpath`。
8. **headless**：没有 TUI 时授权对话框不可用；必须默认拒绝，并给出可操作错误。
9. **维护命令**：`install/update/auth/dev` 需要写 `~/.rpi`、`~/.local/bin`；launcher 默认
   绕过并打印提示。

## 8. 第一件事

从 Phase 0 开始：建 workspace、搬 `policy`/`broker`、改协议、跑测试。完成后再动 launcher。
不要先写扩展 UI，也不要在没有 launcher 的情况下宣称整进程隔离。
