# bcrypt-shim

最小的 `bcrypt.dll` 替代品，只为了让 `rpi.exe` 能在 Windows **受限 token** 下启动。

## 问题

`rpi` 经 `reqwest → rustls → ring` **静态导入** `bcrypt.dll` 的 `BCryptGenRandom`。
真实 `bcrypt.dll` 的 `DllMain` 在存在 restricted SID 列表时返回 `FALSE`，加载器卸载它，
进程以 `STATUS_DLL_INIT_FAILED (0xC0000142)` 退出——`main` 都到不了。

这与 token 的 flags、ACL 授权都无关：ProcMon 里映像加载成功、全程没有 ACCESS DENIED，
就是 DLL 自己拒绝初始化。

## 用法

```bash
cd bcrypt-shim
cargo build --release
cp target/release/bcrypt.dll /path/to/rpi/   # 必须与 rpi.exe 同目录
```

Windows 优先搜索应用目录，且 `bcrypt.dll` **不在** KnownDLLs 列表里，所以同目录的 shim 会赢。
推荐布局：

```text
sandbox\
├── bin\      rpis.exe + rpi.exe + bcrypt.dll + rpi_sandbox_extension.dll
├── agent\    RPI_CODING_AGENT_DIR
└── work\     cwd
```

## 实现

- 惰性 `DllMain`（Rust `cdylib` 默认），加载不会被拒绝；
- `BCryptGenRandom` 转发到 `RtlGenRandom`（`advapi32!SystemFunction036`，沙箱内可用）；
- 算法句柄与 flags 被忽略：我们关心的用法都是 `BCRYPT_USE_SYSTEM_PREFERRED_RNG`。

## 限制

- **只导出 `BCryptGenRandom`**。如果目标程序还导入其它 `bcrypt.dll` 符号，会加载失败。
- 替换系统加密 DLL 可能触发杀软告警。
- 这是 workaround，不是修复。

## 根因修复

让 `rpi` 的 `rustls` 使用 `aws-lc-rs` crypto provider，bcrypt 导入数变为 0，无需 shim：

| 后端 | bcrypt 导入数 | 受限 token 下 |
|---|---|---|
| `ring`（rpi 当前） | 2 | ❌ `0xC0000142` |
| `aws-lc-rs` | 0 | ✅ 正常 |

需要 pi-rust 侧改 `Cargo.toml`。本仓库的 launcher 在子进程以 `0xC0000142` 退出时会打印
这条提示。

## 测试

```bash
cargo test    # 3 个单测：填充缓冲区 / 拒绝空指针 / 允许长度 0
```
