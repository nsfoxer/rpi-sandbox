# 开发路线图

总原则：**先 Linux 跑通整条链路，再补 macOS / Windows；每个阶段结束都更新本文件。**
每个 Phase 的 Definition of Done 见 `handoff.md`。

## Phase 0：工作区、契约与代码搬迁（1–2 天）

状态：**已完成**。

### 任务

- [x] 建立 Cargo workspace：`rpi-sandbox-core`、`rpi-sandbox-launcher`、`rpi-sandbox-extension`
- [x] 从已关闭的 host 分支（`feat/fs-sandbox`）迁入：
  - `policy.rs`（规则、展开、优先级、项目收紧）
  - `linux.rs`（Landlock 计划与执行）
  - `broker.rs`（审批存储、协议、审计）
  - `approval.rs`（数据类型）
  - `probe.rs`（Landlock ABI 探测，`linux.rs` 依赖）
- [x] 把 broker 协议按 `protocol.md` 定稿（加 `hello`、`v`、错误码、绝对路径校验、授权复检）
- [x] 编写 `docs/architecture.md`、`policy.md`、`protocol.md` 的最终版本
- [x] 增加协议序列化测试与策略单元测试

### 验收

- [x] `cargo test -p rpi-sandbox-core` 全绿（73 个单元测试 + 2 个 Landlock 集成测试）；
- [x] 协议请求/响应 round-trip 测试通过；
- [x] 文档中的路径、变量名与实际代码一致。

## Phase 1：Linux launcher MVP（3–5 天）

状态：**已完成**。

### 任务

- [x] launcher 参数：
  - `--profile <name>`、`--config <path>`、`--write <dir>`、`--protect <path>`
  - `--mode auto|required`、`--audit <path>`、`--no-broker`
  - `-- <rpi args...>`
- [x] 启动顺序：解析 → socket → fork broker → Landlock → `exec`
- [x] Landlock 计划按 `platforms/linux.md`：ABI 探测、`WRITE/MAKE/REMOVE/REFER/TRUNCATE`
- [x] broker：单线程服务、授权存储、`check`、写操作、审计
- [x] 退出码/信号：父进程等待并透传；崩溃清理 socket
- [x] 集成测试（子进程）：
  - 允许路径可写；任意路径可读；越界写 `EACCES`
  - `bash` 后代继承
  - 授权后 broker 写入成功；撤销后拒绝

### 验收

- [x] `rpi-sandbox --write <tmp> -- <command>` 行为符合预期（测试用 `/bin/sh` 载荷替代 `rpi`，
  因为本机未安装 rpi 宿主）；
- [x] 测试覆盖 `protocol.md` 中的所有写操作（core broker 单元测试）；
- [x] `mode=required` 在无 Landlock 内核上拒绝启动（单元测试）。

## Phase 2：扩展 MVP（3–5 天）

### 任务

- [ ] 扩展加载：读 `RPI_SANDBOX_ACTIVE` / `RPI_SANDBOX_SOCKET`；未经过 launcher 时提示
- [ ] `ToolCall` veto：
  - `write` / `edit`：解析 `path`，按策略判断
  - `bash`：整进程已隔离，默认放行；可选命令级策略
- [ ] `UiDialog` 授权：`allow_once` / `allow_always` / 目录授权 / `reject_once`
- [ ] 越权写：先 `check`，再向 broker 发 `approve` + `write`
- [ ] 配置：`~/.rpi/agent/sandbox.json` 与 `.rpi/sandbox.json`（只收紧）
- [ ] 授权持久化：会话内内存；可选把“项目级规则”写入配置（需用户确认）
- [ ] 审计：策略中的 `auditLog`；broker 写
- [ ] 命令与状态：`/sandbox`、`/sandbox revoke <path>`、`SetStatus`
- [ ] 测试：策略、授权、拒绝、headless 拒绝、RPC 前端

### 验收

- TUI 中越权写弹出授权并可写入；拒绝则不落盘；
- `-p` 默认拒绝并给出可操作错误；
- 扩展不依赖 host 私有模块，仅 `rpi-plugin-sdk`。

## Phase 3：macOS 后端（2–3 天）

### 任务

- [ ] launcher：`sandbox_init(profile)` 后 `execve`；broker 在应用前 fork
- [ ] SBPL 生成：`deny file-write*` + 允许白名单 + `/dev/null`、`/dev/tty`
- [ ] 路径 `realpath`、大小写与软链处理
- [ ] 打包：universal binary、codesign、notarize（文档 + 脚本）
- [ ] 集成测试：同一套用例（允许/拒绝/子进程/授权）

### 验收

- macOS 上 `rpi-sandbox -- rpi` 正常工作；
- 越权写被拒，授权经 broker 成功。

## Phase 4：Windows 后端（3–5 天）

### 任务

- [ ] restricted token + 合成 SID + ACL 事务（`WRITE_RESTRICTED`）
- [ ] 以受限 token 启动 rpi；broker 用正常 token + 命名管道
- [ ] 崩溃清理：标记文件 + 下次启动回收 ACE
- [ ] `bcrypt.dll` / rustls 兼容：切换 crypto provider 或提供 shim（文档化限制）
- [ ] 集成测试：允许/拒绝/子进程/授权

### 验收

- 同一套测试在 Windows 通过；
- 无残留 ACL；未授权写失败且错误可读。

## Phase 5：加固与扩展（持续）

- [ ] 读限制（Landlock `READ_FILE/READ_DIR`、SBPL、ACL）
- [ ] broker 写入加固：`openat2(RESOLVE_BENEATH)` 消除父目录符号链接竞态
- [ ] 网络限制（Landlock ABI 4+、SBPL、Windows Firewall/WFP）
- [ ] 进程/执行限制（seccomp、Job Object、SBPL process-exec）
- [ ] 多 profile 与按项目选择
- [ ] 容器/bwrap 后端（Linux）
- [ ] 向上游提交文档/契约测试 PR
- [ ] 如维护者需要，再单独提案通用 early-startup 钩子

## 风险与依赖

| 风险 | 影响 | 缓解 |
|---|---|---|
| Landlock 只能加权限，不能扣除嵌套 `protected` | 策略不完整 | 启动告警 / `required` 拒绝；Phase 5 目录枚举方案 |
| Landlock 规则绑定 inode | 目录重建后失效 | 文档说明，重启恢复 |
| macOS Seatbelt API deprecated | 未来可能移除 | 隔离封装，保留 `sandbox-exec` 回退 |
| Windows ACL 残留 / bcrypt 兼容 | 启动失败或权限泄漏 | 事务 + 清理 + crypto provider 切换 |
| 扩展无法覆盖原生插件 | 边界不完整 | 明确整进程由 launcher 提供 |
| 维护者不接受新模式 | 返工 | 先提交短 proposal，再实现 |

## 交付物

- 三个 crate 的可用实现与测试；
- 每个平台的最小集成测试；
- `docs/` 中所有文档与 `handoff.md` 任务清单全部勾选；
- 可复现的示例：`sandbox/examples/`（launcher 启动 rpi + 授权写入）。
