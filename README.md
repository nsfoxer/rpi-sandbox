# rpi-sandbox

为 [rpi](https://github.com/bigfish1913/pi-rust) 提供**整进程文件系统沙箱**：
Linux 用 Landlock，Windows 用 Microsoft Execution Containers (MXC)，macOS 为 Phase 3（未实现）。

`rpis` 先建立内核边界，再启动 `rpi`。rpi 本体、插件、`bash` 及其子进程共享同一个
可写白名单；越权写需要用户授权，由沙箱外的 broker 代执行。

> **注意**：`rpi` 不会自动隔离。要沙箱就用 `rpis`。

## 安装

### 从 release 安装

下载对应平台的压缩包：

```text
rpi-sandbox-v0.1.0-x86_64-windows.zip
rpi-sandbox-v0.1.0-x86_64-linux.tar.gz
```

把 `rpis` 放到 `rpi` 同目录（或 PATH），插件放到 agent 的 `extensions/`：

```text
<bin>/rpis.exe + rpi.exe
~/.rpi/agent/extensions/rpi_sandbox_extension.dll

<bin>/rpis + rpi
~/.rpi/agent/extensions/librpi_sandbox_extension.so
```

Linux 的 `rpis` 是静态 musl，不依赖 glibc；插件是 glibc，跟随 rpi 宿主。

### 从源码安装

```bash
cargo build --release -p rpi-sandbox-launcher -p rpi-sandbox-extension
```

把两个二进制放在同一目录，插件安装到 agent 的 `extensions/`：

```text
<bin>/
  rpis.exe / rpis
  rpi.exe  / rpi
~/.rpi/agent/extensions/
  rpi_sandbox_extension.dll      # Windows
  librpi_sandbox_extension.so    # Linux
```

```bash
# Linux
mkdir -p ~/.rpi/agent/extensions
cp target/release/rpis ~/.local/bin/
cp target/release/librpi_sandbox_extension.so ~/.rpi/agent/extensions/

# Windows（PowerShell）
New-Item -ItemType Directory -Force $HOME\.rpi\agent\extensions
Copy-Item target\release\rpis.exe $env:LOCALAPPDATA\Bin\
Copy-Item target\release\rpi_sandbox_extension.dll $HOME\.rpi\agent\extensions\
```

`rpis` 按 `--rpi` → `RPI_SANDBOX_RPI` → 同目录 `rpi` → `PATH` 定位 rpi。
如果插件未安装，`rpis` 会退回到同目录的扩展 DLL/SO。

## 使用

```bash
rpis                                  # 交互式
rpis -p "总结这个仓库"                  # headless
rpis --resume
rpis --write /srv/data                # 追加可写目录
rpis --readonly .git/hooks            # 可读不可写
rpis --session-dir /srv/sessions      # 自定义会话目录
rpis --mode auto                      # 后端不可用时降级
rpis --print-plan                     # 只打印计划，不改动磁盘
rpis -- --help                        # 其余参数原样转发给 rpi
```

- **默认 `required`**：后端不可用或无法建立边界时拒绝启动。
- `--mode auto` 才允许降级；Linux 上无法扣除的嵌套 `readonly` 会显示 `partial`。
- 越权写用 `write` / `edit` 工具：扩展弹授权，broker 执行。`bash` 不能申请授权，
  被内核拒绝就是拒绝。
- `/sandbox` 查看当前策略；`/sandbox revoke <path>` 撤销授权。

## 配置

配置写在 rpi 的 `settings.json` 里，沙箱只读取其中的 `sandbox` 对象：
全局 `~/.rpi/agent/settings.json`，项目 `<cwd>/.rpi/settings.json`（只能收紧）。

```json
{
  "sandbox": {
    "enabled": true,
    "mode": "required",
    "writable": ["${cwd}", "${tmp}"],
    "readonly": ["${home}/.ssh", "${home}/.aws"],
    "approval": { "enabled": true, "defaultScope": "session" }
  }
}
```

- 没有 `sandbox` 块时使用默认值：`required`、`cwd` / 临时目录 / 会话目录可写、审批开启。
- `readonly` 永远优先于 `writable`。
- 项目配置不能扩大可写范围，也不能关闭沙箱。
- 相对路径相对于 `cwd`；支持 `${cwd}`、`${tmp}`、`${home}`。
- `mode: "auto"` 允许降级；`"off"` 关闭沙箱。
- Linux 上如果 `readonly` 位于某个 `writable` 根内，`required` 会拒绝启动；把路径移到
  可写根之外，或用 `"mode": "auto"` 接受 `partial`。

`RPI_CODING_AGENT_DIR` 可重定位 agent 目录。`~/.rpi/agent` 在沙箱内保持只读；launcher
预创建 `.resource-lease` / `update-check.json`，并按需创建显式 `--session-dir`。
更新缓存在沙箱内可能不持久化。

## 平台与限制

| 平台 | 后端 | 要求 |
|---|---|---|
| Linux | Landlock | 5.13+ |
| Windows | MXC | Windows 11 24H2 build 26100.9278+ |
| macOS | Seatbelt | Phase 3，未实现 |

- **Linux 嵌套 `readonly`**：Landlock 只能累加权限，不能扣除子树。`required` 拒绝启动；
  `auto` 继续但状态显示 `partial`，`bash` 仍可直接写该路径（broker / 工具层会拦截）。
  把只读路径移到可写根之外，或接受 `partial`。

Windows 后端的详细限制见下一节。

- **威胁模型**：同进程的第三方插件与扩展共享 PID，仍在 TCB 内；要防它需要 broker 在
  沙箱外直接展示审批 UI，v1 不做。
- **macOS**：后端未实现，`rpis` 会直接报错。

## Windows（MXC）的限制

Windows 后端是 MXC 的 **PSEC**（`processmodel.dll` + `PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT`），
容器内的进程实际运行在 **AppContainer + Low integrity** 下。文件系统策略只是这个容器的一部分，
无法单独剥离。

实测环境：Windows 11 26H2（build 26300）、rpi 0.25.0、`mxc-sdk` 1.1。

| 能力 | 结果 | 说明 |
|---|---|---|
| 写可写根（`${cwd}`、`${tmp}`） | ✅ | `readwrite_paths` |
| 写 `readonly` 路径 | ✅ 拒绝 | `readonly_paths`，内核级，可读不可写 |
| 写未列出的路径 | ✅ 拒绝 | `Access is denied (os error 5)` |
| 读取 | 白名单 | 只暴露显式列出的根 + 系统默认 |
| 多实例 | ✅ 隔离 | 每个容器独立 |
| 启动 / 退出 | ✅ 约 0.5s | 与项目大小无关，不修改 ACL |
| MSYS2 / Git Bash | ❌ | `0xC0000142`，见下 |
| 桌面通知（Toast） | ❌ | Low IL 没有 packaged identity，句柄创建失败 |
| Win32 剪贴板 | ❌ | Low IL 拒绝 `OpenClipboard` |
| `>nul` / `NUL` | ❌（推断） | 设备对象在 Low IL 下不可写，未单独实测 |
| 命名内核对象 | ⚠️ | `\BaseNamedObjects` 可读；创建受 AppContainer 重定向影响 |
| 注册表 | ⚠️ | HKLM 只读（需 `registryRead`）；HKCU 大部分被重定向 |
| `%LOCALAPPDATA%` | ⚠️ | 重定向到 `...\Packages\sandbox.{guid}\AC` |

### MSYS2 / Cygwin

`msys-2.0.dll` 用绝对 NT 路径调用 `NtCreateDirectoryObject(\BaseNamedObjects\msys-2.0*)`，
Low integrity 下被拒绝（`microsoft/mxc#1061`）：

```text
0 [main] bash: *** fatal error - NtCreateDirectoryObject(\BaseNamedObjects\msys-2.0*): 0xC0000022
```

文件系统、capability、UI 策略都无法放行。所有 MSYS2 / Cygwin 程序都会失败；原生 Windows
程序（PowerShell、cmd、原生 `git.exe`、node）不受影响。

需要 bash 时：

- `rpis --no-sandbox`（放弃隔离）；
- 把 `rpi-opencode-extras` 的 `opencodeExtras.bash.kind` 改成 `powershell` 或 `cmd`；
- 或使用 Linux 后端（Landlock）。

### 为什么不能只保留文件系统限制

```text
文件系统策略  ⊂  AppContainer 容器  ⊂  PSEC
```

`capabilities`、`ui.isolation`、`clipboard` 都只是在 Low integrity 之上放宽某个类别，
没有任何开关能取消 Low integrity 本身。因此「只限制文件系统、不影响其它」在 MXC 上不存在。

已经验证过的替代路径：

| 方案 | 结果 |
|---|---|
| `WRITE_RESTRICTED` + restricting SID | 文件系统正确，但 MSYS2 仍然失败（Cygwin 依赖 `NtSetInformationToken(TokenDefaultDacl)`，受限令牌禁止） |
| 受限用户账户 | 未验证；需要管理员初始化，通知/剪贴板跨用户行为未知 |

### 桌面通知与剪贴板

沙箱内进程没有 packaged identity，`ToastNotificationManager` 无法创建 notifier；
`%LOCALAPPDATA%` 也被重定向。当前实现会在首次失败后静默关闭通知。

剪贴板同理：`ClipboardPolicy::All` 只去掉 job object 的 UI 限制，Low integrity 仍然
拒绝 `OpenClipboard`。TUI `/copy` 回退到 OSC 52，需要终端支持。

当前版本不做宿主能力代理（通知/剪贴板）；如有需要，会在 `rpis` 侧另开一个受限通道。

## 文档

- [架构](docs/architecture.md)
- [策略与配置](docs/policy.md)
- [协议](docs/protocol.md)
- [Linux Landlock](docs/platforms/linux.md)
- [Windows MXC](docs/platforms/windows.md)
- [路线图](docs/roadmap.md)
