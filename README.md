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
| `rpi-sandbox-core` | 普通库 | 策略模型、后端抽象（能力/计划/启动）、传输（socket/命名管道）、broker、审计、状态目录 |
| `rpi-sandbox-launcher` | 二进制 `rpis` | 自动定位并启动 `rpi`：读策略 → 编译计划 → 建 broker → 施加隔离 → 启动/`exec` |
| `rpi-sandbox-extension` | `cdylib` 扩展 | `ToolCall` veto、`UiDialog` 授权、配置、授权持久化、`/sandbox`、页脚状态 |

平台差异被收在两个缝里：`core::backend`（策略 → 计划 → 启动）与 `core::transport`
（Unix socket / Windows 命名管道）。CLI、策略编译、目标解析、扩展注入、环境构造、
broker、审计全部共用一份代码。

## 快速开始

```bash
cargo build --workspace
./target/debug/rpis
```

`rpis` 是一个可直接替代 `rpi` 的入口，不需要再手写 `-- rpi`：

- 按 `--rpi <path>` → `RPI_SANDBOX_RPI` → 同目录 `rpi`/`rpi.exe` → `PATH` 的顺序定位 rpi；
- 如果同目录存在 `librpi_sandbox_extension.so`（或对应平台的动态库），自动以
  `--extension <file>` 注入，无需手动安装；
- 其余参数原样传给 rpi；如果某个参数与 `rpis` 自己的选项同名，用 `--` 强制透传。

```bash
rpis                                   # 启动 rpi（默认沙箱）
rpis -p "总结这个仓库"                  # 参数直接转给 rpi
rpis --write /srv/data --resume        # 额外可写目录 + 恢复会话
rpis --rpi /opt/rpi/bin/rpi            # 指定 rpi 二进制
rpis -- --help                         # 查看 rpi 自己的帮助
rpis --no-extension                    # 不自动加载沙箱扩展
rpis --print-plan                      # 打印后端计划（不改动磁盘）
```

长期使用时，把 `rpis` 和对应动态库放在同一目录，或把扩展安装到
`~/.rpi/agent/extensions/`。运行后页脚会显示 `🔒 sandbox (<profile>)`。

### Windows

Windows 使用 **Microsoft Execution Containers (MXC)**，不修改任何 ACL：

- 要求 Windows 11 24H2（build 26100.9278+）或更新版本，并安装对应的 MXC 更新；
- 不支持时 `rpis` 在 `mode = auto` 下降级为「不隔离」，`mode = required` 则拒绝启动。

```cmd
:: 推荐布局：rpis.exe + rpi.exe + rpi_sandbox_extension.dll 同目录
cd sandbox\work
set RPI_CODING_AGENT_DIR=C:\sandbox\agent
C:\sandbox\bin\rpis.exe -p "总结这个仓库"
```

Windows 额外选项：`--read <dir>`（额外读根）、`--print-plan`（查看 MXC 策略）。
MXC 只暴露显式列出的目录；`rpis` 会自动加入卷根、agent 目录、工具目录和系统目录。

## 模型能看到什么

扩展通过 `before_agent_start` 在 system prompt 末尾追加一段 `## Sandbox (rpi-sandbox)`：
可写根、`EACCES`（“权限不够”）代表沙箱拒绝而非权限问题、`bash` 不能走授权、越权写应改用
`write`/`edit`，以及 `write`/`edit` 返回 blocked 时可能已经由 broker 写入。这样模型不会在
`date > file` 失败后去查挂载表或反复 `touch`。

提示只是告知：真正的边界仍由 launcher 的 Landlock 域 / MXC 容器和 broker 提供。host 不支持该钩子时，
`/sandbox` 会显示 `model hint: unsupported by this host`。

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
| [docs/platforms/windows.md](docs/platforms/windows.md) | MXC 后端细节 |

## 当前状态

**Phase 0–2 + Phase 4（Windows）已实现**：

- core：策略、后端抽象、传输层、broker、审计、状态目录；Linux Landlock + Windows MXC
  两套计划器都有离线单测；
- Linux launcher：Landlock + fork broker + `exec`；8 个集成测试全绿（WSL/Debian 实测）；
- Windows launcher：MXC `processcontainer` + 命名管道 broker；8 个集成测试全绿
  （Windows 11 26H2 实测），启动/退出约 0.5s，不修改 ACL；
- 扩展：策略 / veto / UiDialog / broker 写入 / 命令 / 状态 / 模型提示；策略快照优先，
  隔离时与内核策略不可能漂移；已在 rpi 0.23.0（Windows）与 0.24.x 实际加载验证；
- `rpi.exe` 在 MXC 容器内真实启动、加载 10 个插件、完成真实模型请求（经
  `rpi-opencode-extras` 注入 session 头），模型能复述 `## Sandbox (rpi-sandbox)` 的内容。

MXC 不可用时自动降级为「不隔离」；`mode = required` 会拒绝启动。
交互式授权（TUI 弹窗）仍需人工验收；macOS 后端见 Phase 3。

