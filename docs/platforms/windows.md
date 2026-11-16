# Windows 后端：restricted token + 合成 SID + ACL

> 状态：**已实现并本机实测**（Windows 11，rpi 0.23.0 / 0.24.x，2026-11）。
> 与 Linux 的差别不在「用哪个 API」，而在**控制流**：Windows 不能给当前进程降权，
> 只能以受限 token 启动子进程。

## 1. 机制总览

```text
rpis.exe（正常 token，不受限）
 1. 解析参数 + 编译策略
 2. 清扫上次残留的 ACL journal；打开本次 journal
 3. 派生两个合成 SID（read / write，seed = profile + canonical cwd）
 4. 给读根加 Allow ACE（只读，失败仅告警）
 5. 给写根加 Allow ACE（OI|CI 继承），给 protected 加 Deny ACE
 6. CreateNamedPipeW（DACL 只授当前用户 + read/write SID）→ broker 线程
 7. CreateRestrictedToken(DISABLE_MAX_PRIVILEGE|LUA_TOKEN|WRITE_RESTRICTED,
        restricted = [write, read, logon, Everyone])
    + 设置 token 默认 DACL + 启用 SeChangeNotifyPrivilege
 8. DuplicateTokenEx → primary token
 9. CreateProcessAsUserW（显式 Unicode 环境块、私有桌面、继承 std 句柄）
10. WaitForSingleObject → GetExitCodeProcess
11. 撤销 journal 里的 ACE、删除 journal、透传退出码
```

父进程（`rpis`）始终是**不受限**的：它既是 broker 也是 supervisor，因此能在子进程退出后
把 ACL 恢复原状。

## 2. 为什么必须由 launcher 启动

restricted token 是**进程 primary token**，无法把当前进程降权；`SetThreadToken` 只影响
本线程的文件 I/O，另一个插件同线程池里的 `std::fs::write` 照样能写。整进程边界只能在创建
子进程时施加。

## 3. 关键实现约束（改动前必读）

| # | 约束 | 原因 |
|---|---|---|
| 1 | 必须 `DuplicateTokenEx` 成 **primary** token | `CreateProcessAsUserW` 只接受 primary |
| 2 | **不能**用 `SetThreadToken` + `CreateProcessW` | 子进程用进程 token，线程 impersonation 不传播 |
| 3 | restricted SID 的 `Attributes` 必须是 `0` | 传 `SE_GROUP_ENABLED` → `ERROR_INVALID_PARAMETER (87)` |
| 4 | base token 需要 6 项访问权限（含 `TOKEN_ADJUST_DEFAULT`、`TOKEN_ADJUST_PRIVILEGES`） | 缺任一项会让 `SetTokenInformation` / `AdjustTokenPrivileges` 失败 |
| 5 | 必须 `SetTokenInformation(TokenDefaultDacl)` | DLL 初始化要创建内核对象；默认 DACL 不含 logon SID 会 `0xC0000142` |
| 6 | 必须启用 `SeChangeNotifyPrivilege` | `DISABLE_MAX_PRIVILEGE` 禁用了所有特权，没有它目录遍历大面积失败 |
| 7 | restricted 列表 = `[write, read, Logon, Everyone]`，**不含** `Users` / `Authenticated Users` | `WRITE_RESTRICTED` 只约束写；把组放进去会扩大写面到这些组可写的一切位置 |
| 8 | 必须给读根加 ACE | 目标 exe/DLL 的 DACL 可能只授具体用户 SID |
| 9 | 合成 SID 必须按 `profile + cwd` **稳定派生** + 加 ACE 前**幂等检查** | 否则每次运行都在目录上堆新 ACE |
| 10 | 管道 DACL 必须显式授 capability SID | 否则沙箱内的扩展连不上 broker |
| 11 | ACE 掩码必须用**具体权限位**，不能用 `GENERIC_*` | 对象管理器会把 generic 位改写成具体位，导致幂等检查/撤销匹配不到原 ACE |

## 4. ACL 事务与清理

ACL 修改是**持久副作用**，这是 Windows 与 Linux 最大的运维差异。

- **先写 journal，再加 ACE**：journal 记录 `(path, mask, deny, sid)`，`sync_all` 后才写 ACL，
  所以「加了 ACE 就被 kill」也能在下次启动回收。
- **只撤销自己新增的**：`set_ace` 先做幂等检查，只有真正新增的 ACE 才进 journal。并发实例
  之间不会互拆。
- **撤销用 raw ACL 复制**：`GetAclInformation` / `GetAce` → `InitializeAcl` + `AddAce` 逐条
  原样拷贝（保留 ACE 顺序与 object ACE），只过滤 `(SID, mask, 类型)` 完全匹配的那条。
  继承标记（`INHERITED_ACE`）的条目跳过，让对象管理器重新传播，避免把继承 ACE 固化成显式 ACE。
- **崩溃恢复**：启动时扫描 `<state>/acl/*.json`；owner PID 已消失才回收（`OpenProcess` +
  `GetExitCodeProcess`）。活着的实例不会被误伤。
- **`rpis --cleanup`**：不依赖原命令行，journal 里带路径；另外按当前策略重新推算 plan 再撤一遍，
  兜底 journal 丢失的情况。

状态目录（`RPI_SANDBOX_STATE_DIR` 可覆盖）：

```text
<RPI_CODING_AGENT_DIR>/sandbox/       # 默认
├── acl/<pid>-<nonce>.json            # ACL journal
├── policy-<pid>-<nonce>.json         # 策略快照（扩展优先读取）
└── audit.jsonl                       # 配置了 auditLog 时
```

策略快照超过 1 小时会在下次启动时清理（Unix exec 后无法自行删除）。

## 5. 卷能力检查

exFAT / FAT32 / 部分网络共享**不支持持久 ACL**。启动时对每个计划路径调用
`GetVolumePathNameW` + `GetVolumeInformationW`，检查 `FILE_PERSISTENT_ACLS`：

- `mode = required`：直接拒绝启动；
- `mode = auto`：告警并继续（明确告诉用户该处不可靠）。

`System32` 等 owner 为 `TrustedInstaller` 的目录无法加 ACE，这类路径不会出现在写根里；
读根加 ACE 失败只告警（读走原始用户 SID）。

## 6. `protected` 在 Windows 上是内核级

`build_plan` 会为每个存在的 `protected` 路径添加 Deny ACE（写类权限 + `DELETE` +
`FILE_DELETE_CHILD`），因此：

- 「可写目录里嵌套 protected」在 Windows 上**可强制**，`BackendCapabilities::can_subtract_protected = true`；
- `/sandbox` 不再显示 Landlock 那句「内核扣不出子树」的警告；
- 撤销/删除也会被拒（删除需要父目录的 `FILE_DELETE_CHILD`，而那条 deny ACE 继承到了子项）。

对象级 ACL 还有一个附带好处：junction / symlink / hardlink 都绕不过去——访问检查发生在目标
对象上，而目标对象的 DACL 里没有 capability SID 就是拒绝。

## 7. broker 与命名管道

- 端点：`\\.\pipe\rpi-sandbox-<pid>-<nonce>`；
- DACL：`D:P(A;;GA;;;<当前用户>)(A;;GA;;;<read SID>)(A;;GA;;;<write SID>)`；
- 协议与 Unix 完全相同（JSON Lines），代码路径共用 `BrokerService`；
- 监听端在**子进程启动前**创建，扩展在 DLL 初始化阶段即可握手；
- broker 跑在 launcher 的独立线程，主线程 `WaitForSingleObject`；
- 已知限制：同步命名管道没有 per-call 超时，客户端 `set_read_timeout` 是 no-op。

## 8. `bcrypt.dll` 与 rustls

`rpi` 经 `reqwest → rustls → ring` **静态导入** `bcrypt!BCryptGenRandom`。真实 `bcrypt.dll`
的 `DllMain` 在存在 restricted SID 列表时返回 `FALSE`，加载器卸载它，进程以
`STATUS_DLL_INIT_FAILED (0xC0000142)` 退出，`main` 都到不了。与 token flags、ACL 无关。

两种解法：

1. **首选（本仓库提供）**：把 `bcrypt-shim/` 构建出的 `bcrypt.dll` 放在 `rpi.exe` 同目录。
   Windows 优先搜索应用目录，且 `bcrypt.dll` 不在 KnownDLLs 里。
2. **根因修复**：pi-rust 侧把 rustls 的 crypto provider 从 `ring` 换成 `aws-lc-rs`
   （bcrypt 导入数 0）。

launcher 在子进程以 `0xC0000142` 退出时会打印可操作提示。

推荐布局（`rpis` 的 rpi 解析顺序天然支持）：

```text
sandbox\
├── bin\      rpis.exe + rpi.exe + bcrypt.dll + rpi_sandbox_extension.dll
├── agent\    RPI_CODING_AGENT_DIR（rpi 状态）
└── work\     cwd（项目）
```

## 9. 已知限制

| 限制 | 说明 |
|---|---|
| 不是内核级沙盒 | 共享内核；防误写/agent 乱来足够，防恶意代码需要 Windows Sandbox / VM |
| ACL 是全局副作用 | 异常退出会残留，靠 journal + 下次启动回收 + `--cleanup` |
| `bcrypt.dll` shim | 替换系统加密 DLL，可能触发杀软；只导出 `BCryptGenRandom` |
| 私有桌面 best-effort | `SetSecurityInfo(desktop)` 失败时回退默认桌面 |
| 无 per-call IPC 超时 | 同步管道限制；broker 挂死时扩展会阻塞 |
| 句柄继承 | `bInheritHandles = TRUE`（std 句柄需要）；launcher 不持有其他可继承的敏感句柄。后续可用 `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` 收紧 |

## 10. 验收（本机实测）

| 项 | 结果 |
|---|---|
| 写根内写入 | ✅ |
| 任意路径读取 | ✅ |
| 写根外写入 / 删除 / truncate | ✅ `Access is denied (os error 5)` |
| `bash`/子进程继承限制 | ✅（`spawn-write` 探针） |
| 沙箱内改写自身 DACL | ✅ 被拒 |
| broker 握手 / 授权写 / revoke（命名管道） | ✅ |
| 退出码透传 | ✅ |
| 正常退出后无残留 ACE | ✅ |
| launcher 被 kill 后下次启动回收 | ✅ |
| `rpis --print-plan` 不改动磁盘 | ✅ |
| `rpi.exe` 在受限 token 下启动 | ✅（bcrypt shim + 10 个插件全部加载） |
| 真实模型请求（经 `rpi-opencode-extras` 注入 session 头） | ✅ 返回 `OK` |
| 模型提示注入 `## Sandbox (rpi-sandbox)` | ✅ 模型能背出 backend 与可写根 |
| headless 越权写 | ✅ 拒绝并给出可操作错误 |
