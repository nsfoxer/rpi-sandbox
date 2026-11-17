# Windows 后端：Microsoft Execution Containers (MXC)

> 状态：**已实现并本机实测**（Windows 11 26H2 / build 26300，rpi 0.23.0，2026-11）。
> 旧的 restricted token + 合成 SID + ACL 实现已移除。

## 1. 机制总览

```text
rpis.exe（不受限）
 1. 解析参数 + 编译策略
 2. 编译 MXC 计划（write / read / deny 路径）
 3. 创建命名管道 broker（DACL 授予当前用户 + ALL APPLICATION PACKAGES）
 4. 构造 ContainerRequest：
      containment    = Process（Windows 解析为 ProcessContainer/PSEC）
      filesystem     = readwrite_paths / readonly_paths（readonly 合并于此）
      network.egress = Allow
      ui             = disable=false
      stdio          = Inherit（TUI 直接用当前终端）
 5. spawn → 等待 → 透传退出码
```

`rpis` 始终不受限：它既是 broker，也是 supervisor。沙箱边界由 MXC 在容器创建时施加，
**不修改任何文件的 ACL**。

## 2. 为什么改用 MXC

旧的 ACL 后端在目录上添加可继承 ACE 时，Windows 会把它**传播到所有已存在的子对象**：

> Microsoft 文档（`SetNamedSecurityInfoW`）："the system automatically propagates any
> inheritable ACEs to existing child objects"

给一个包含 `target/`（几 GB、几十万文件）的项目根加 ACE，启动和退出各要遍历一次整棵树。
实测同一项目：旧后端约 **75 秒**，MXC **约 0.5 秒**，而且 MXC 前后 `icacls` 完全不变。

| | 旧 ACL 后端 | MXC |
|---|---|---|
| 启动/退出成本 | O(文件数) | O(1) |
| 磁盘副作用 | 持久 ACL + journal | 无 |
| 崩溃残留 | 需要清理 | 无 |
| `readonly` 扣除 | Deny ACE | `readonly_paths`（可读不可写） |
| bcrypt 兼容 | 需要 shim | 系统 `bcrypt.dll` 正常 |

## 3. 系统要求

- Windows 11 24H2（build **26100.9278**+）或 25H2/26H2，并安装对应的 MXC 更新
  （24H2/25H2：KB5120998 / KB5124010；26H1：KB5124006）；
- `rpi` 0.23.0 实测可用；
- 不需要管理员权限、专用账户、防火墙规则或额外 Windows 账户。

`rpis` 通过 `mxc_sdk::v1::platform_support()` 探测；返回不支持时：

| `mode` | 行为 |
|---|---|
| `auto`（默认） | 打印原因，**关闭沙箱**继续运行 |
| `required` | 拒绝启动并给出原因 |
| `off` | 不隔离（与配置一致） |

## 4. 策略映射

| rpi 策略 | MXC |
|---|---|
| `writable` | `readwrite_paths` |
| `read_roots`（`--read` + 自动读根） | `readonly_paths` |
| `readonly` | `readonly_paths`（可读不可写） |
| 网络 | `NetworkPolicy.egress.default = Allow` |
| 沙箱内 GUI | `UiPolicy.disable = false`（见下） |

### 读白名单

MXC 只暴露显式列出的目录（加系统默认）。`MxcPlan::build` 会自动加入：

- 每个写根/读根的**卷根**（例如 `C:\`）——rpi 启动时会探测 `\\?\C:\`，缺了会报
  `checking resource ancestor ... 拒绝访问`；
- launcher 自动收集的读根：`rpi.exe` 所在目录、`rpis.exe` 所在目录、
  `RPI_CODING_AGENT_DIR`、`--read` 指定的目录。

读根是显式白名单：未列出的用户目录（如 `~/.ssh`）默认不可读。`readonly` 映射为
`readonly_paths`，因此可写父目录中的 readonly 子目录**可读、不可写**。`.ssh` 若被列为
readonly，读仍跟随读白名单，不会额外禁读。

### 网络

MXC 的 egress 默认是 **Deny**，实测不设置时 `curl` 连 DNS 都失败。后端固定设置
`default = Allow`；与旧后端一致，网络不纳入沙箱边界。

### UI / Win32k

`UiPolicy` 默认 `disable = true` 会移除 Win32k。`rpi.exe` 静态导入
`ole32/USER32/SHELL32`，而 `ole32.dll` 在没有 Win32k 时 `DllMain` 返回失败
（`0xC0000142` / 1114）。后端设置 `disable = false`，并保持剪贴板 `None`、
输入注入 `false`。

## 5. broker 与命名管道

- 端点：`\\.\pipe\rpi-sandbox-<pid>-<nonce>`；
- DACL：当前用户 + `S-1-15-2-1`（`ALL APPLICATION PACKAGES`）。
  MXC 的 workload 运行在 AppContainer 中，仅授予交互用户的管道 DACL 会被拒绝
  （`os error 5`）；加入 `ALL APPLICATION PACKAGES` 后扩展可正常握手；
- 协议与 Unix 完全相同（JSON Lines），代码路径共用 `BrokerService`；
- 监听端在容器启动前创建；broker 线程 `accept` 一次并服务到断开；
- 已知限制：同步命名管道没有 per-call 超时；只允许一个活动连接，
  扩展重复加载时第二次连接会得到 `ERROR_PIPE_BUSY (231)`。
- 推荐把 `rpi_sandbox_extension.dll` 作为插件安装到
  `~/.rpi/agent/extensions/`（或 `$RPI_CODING_AGENT_DIR/extensions/`）。
  `rpis` 检测到插件已安装时会跳过同目录 DLL 的注入，因此不会出现两个实例。

## 6. 环境

MXC 继承宿主环境，但 `rpis` 可能运行在 MSYS2 下（`PATH=/usr/local/bin:...`、
`TEMP=/tmp`），这些值对原生 Windows 子进程无意义。后端会强制设置：

- `PATH`：rpi 程序目录 + `System32` + `C:\msys64\usr\bin` + Git 等；
- `TEMP` / `TMP`：`%LOCALAPPDATA%\Temp`；
- 其余 `RPI_SANDBOX_*`、`RPI_CODING_AGENT_DIR` 由共享层覆盖。

## 7. 已知限制

| 限制 | 说明 |
|---|---|
| MXC 仍是较新的平台能力 | 需要 Win11 24H2+ 与对应更新；旧系统自动降级为不隔离 |
| 不是内核级安全边界 | MXC 是微软的进程容器；适合防 agent 误写，不替代 VM |
| 网络全放行 | 与旧后端一致；MXC 支持 egress 规则，后续可按策略收紧 |
| 读白名单 | 需要显式列出；`rpis` 自动加卷根，因此读范围较宽 |
| 单管道实例 | 扩展重复加载时第二次连接失败（见 §5） |
| 前台退出会终止子进程 | MXC 文档行为；对 rpi 退出可接受 |
| SDK 版本 | 使用 `mxc-sdk` 1.1；升级需重新验证 |

## 8. 验收（本机实测）

| 项 | 结果 |
|---|---|
| 写根内写入 | ✅ |
| 已列出的读根可读；未列出目录不可读 | ✅ |
| 写根外写入 / 删除 / truncate | ✅ `Access is denied (os error 5)` |
| `bash`/子进程继承限制 | ✅（`spawn-write` 探针） |
| `readonly` 子目录（`.git/hooks`） | ✅ 可读；写/删除被拒 |
| broker 握手 / 授权写 / revoke（命名管道） | ✅ |
| 退出码透传 | ✅ |
| 启动 + 退出耗时 | ✅ 约 **0.5s**（含容器创建；与项目大小无关） |
| ACL 变化 | ✅ 前后 `icacls` 完全一致 |
| `rpi.exe` 在 MXC 中启动 | ✅ 加载 10 个插件 |
| 真实模型请求 | ✅ 返回 `OK` |
| 模型提示注入 `## Sandbox (rpi-sandbox)` | ✅ 模型能复述 backend 与可写根 |
| headless 越权写 | ✅ 拒绝并给出可操作错误 |

## 9. 迁移说明

已删除：

- `bcrypt-shim/`（MXC 不再需要 `bcrypt.dll` 替换）；
- `--print-sid`、`--cleanup`（没有合成 SID / ACL journal 了）；
- ACL journal 目录与相关清理逻辑。

扩展现在作为普通插件安装：

```text
<RPI_CODING_AGENT_DIR>\extensions\rpi_sandbox_extension.dll
```

`rpis.exe` 只负责建立边界和 broker；插件从 rpi 的标准扩展目录加载。

`--print-plan` 现在打印 MXC 的 `write` / `read` / `deny` 路径。
