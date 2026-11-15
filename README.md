# rpi-sandbox（rpi 扩展）

> 本项目是 [bigfish1913/pi-rust](https://github.com/bigfish1913/pi-rust)（`rpi`）的配套扩展：
> 通过 launcher 在 `exec rpi` 前建立整进程文件系统边界，并以 `rpi-plugin-sdk` 扩展提供
> 策略、授权、审计与状态。

面向 rpi 的**整进程文件系统沙箱**：`rpi` 本体、所有已加载插件、`bash` 及其子进程都处在
同一个可写白名单边界内；越权写需要用户授权，并由一个不受限的 broker 代执行。

本仓库只实现沙箱本身，**不修改 rpi 上游的 host 架构**。上游 PR 的结论是：

- host 保持通用能力；
- 沙箱策略、配置、授权、审计、命令与状态归扩展；
- 整进程隔离由 launcher 在 `exec rpi` 前建立；
- broker 住在 launcher/helper 侧；
- 宿主最多补充文档与契约测试。

## 组件

| 组件 | 形态 | 职责 |
|---|---|---|
| `rpi-sandbox-core` | 普通库 | 策略模型、路径规则、平台后端（Landlock/Seatbelt/restricted token）、broker、审计 |
| `rpi-sandbox-launcher` | 二进制 | 读策略 → 建 socket → fork broker → 应用隔离 → `exec rpi` |
| `rpi-sandbox-extension` | `cdylib` 扩展 | `ToolCall` veto、`UiDialog` 授权、配置、授权持久化、`/sandbox`、页脚状态 |

## 文档

| 文档 | 内容 |
|---|---|
| [docs/architecture.md](docs/architecture.md) | 边界、组件、信任模型、启动流程、无 launcher 时的行为 |
| [docs/policy.md](docs/policy.md) | 规则模型、配置 schema、优先级、项目收紧 |
| [docs/protocol.md](docs/protocol.md) | launcher ↔ 扩展的握手与 socket 协议 |
| [docs/host-api-gaps.md](docs/host-api-gaps.md) | 现有扩展 API 核查与可选的最小 host 接口 |
| [docs/roadmap.md](docs/roadmap.md) | Phase 0–5 的开发顺序与验收标准 |
| [docs/handoff.md](docs/handoff.md) | 交给下一个 AI 的执行手册与硬约束 |
| [docs/platforms/linux.md](docs/platforms/linux.md) | Landlock 后端细节 |
| [docs/platforms/macos.md](docs/platforms/macos.md) | Seatbelt 后端细节 |
| [docs/platforms/windows.md](docs/platforms/windows.md) | restricted token + ACL 后端细节 |

## 当前状态

**Phase 0–2 已实现**：core、Linux launcher、扩展（策略 / veto / UiDialog / broker 写入 /
命令 / 状态）均已完成并通过离线测试。扩展已在 rpi 0.24.0 中实际加载验证；交互式授权
流程仍需人工验收。macOS / Windows 后端见 Phase 3–4。
