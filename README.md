# rpi-sandbox

为 [rpi](https://github.com/bigfish1913/pi-rust) 提供**整进程文件系统沙箱**：

- Linux：Landlock
- Windows：Microsoft Execution Containers (MXC)
- macOS：Seatbelt（Phase 3，未实现）

`rpis` 在启动 `rpi` 前建立边界；`rpi` 本体、插件、`bash` 及其子进程都在同一个可写白名单内。
越权写需要用户授权，由不受限的 broker 代执行。

## 快速开始

```bash
cargo build --workspace
./target/debug/rpis
```

`rpis` 是 `rpi` 的替代入口：

- 按 `--rpi` → `RPI_SANDBOX_RPI` → 同目录 `rpi`/`rpi.exe` → `PATH` 定位；
- 优先加载 `~/.rpi/agent/extensions` 里的沙箱插件；同目录 DLL 作为 fallback；
- 其余参数原样转发；与 `rpis` 同名时用 `--` 分隔。

```bash
rpis
rpis -p "总结这个仓库"
rpis --write /srv/data --resume
rpis --readonly .git/hooks      # 可读不可写
rpis --print-plan               # 查看后端计划，不改动磁盘
```

Windows 布局：

```text
sandbox\bin\        rpis.exe + rpi.exe
sandbox\agent\      RPI_CODING_AGENT_DIR
  extensions\       rpi_sandbox_extension.dll   ← 沙箱插件
sandbox\work\       cwd
```

MXC 要求 Windows 11 24H2 build 26100.9278+。不支持时 `auto` 模式降级为不隔离，
`required` 拒绝启动。

## 配置

`~/.rpi/agent/sandbox.json`（全局）或 `<cwd>/.rpi/sandbox.json`（项目，只能收紧）：

```json
{
  "enabled": true,
  "mode": "auto",
  "writable": ["${cwd}", "${tmp}"],
  "readonly": ["${home}/.ssh", "${cwd}/.git/hooks"],
  "approval": { "enabled": true, "defaultScope": "session" }
}
```

- Linux：工具层 + broker 拦截，`bash` 可绕过；
- Windows MXC：内核级只读（可读、不可写）。

## 平台

| 平台 | 后端 | 要求 |
|---|---|---|
| Linux | Landlock | 5.13+ |
| Windows | MXC | Windows 11 24H2 build 26100.9278+ |
| macOS | Seatbelt | Phase 3 |

## 文档

- [架构](docs/architecture.md)
- [策略与配置](docs/policy.md)
- [协议](docs/protocol.md)
- [Linux Landlock](docs/platforms/linux.md)
- [Windows MXC](docs/platforms/windows.md)
- [路线图](docs/roadmap.md)
