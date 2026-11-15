# Windows 后端：restricted token + ACL

## 机制

参考 OpenAI Codex `windows-sandbox-rs` 与既有 `sbx` 实验：

1. 按沙盒名派生**合成 SID**（稳定，可复用，避免每次堆 ACE）；
2. 为每个可写根添加 Allow ACE（`OI|CI` 继承）；
3. `CreateRestrictedToken(..., WRITE_RESTRICTED)`：写操作要求用户身份 **且** 合成 SID；
4. `DuplicateTokenEx` 成 primary token；
5. `CreateProcessAsUserW` 以受限 token 启动 `rpi.exe`；
6. launcher（父进程）保持正常 token，作为 broker + 等待子进程。

## 为什么必须由 launcher 启动

restricted token 是进程 primary token，无法把当前进程“降权”；只能在创建子进程时施加。
因此 Windows 的 launcher 不是可选项，`rpi` 自身无法完成整进程限制。

## ACL 事务与清理

- 修改的是真实文件 ACL，**持久**；
- 需要：
  - 启动前记录本次新增的 ACE；
  - 正常退出时撤销；
  - 崩溃后用标记文件在下次启动时回收；
  - 提供 `--cleanup` 手工清理。
- 只对用户可写的目录添加 ACE（通常是项目目录、临时目录、agent 目录）；系统目录不改。

## `bcrypt.dll` 与 rustls

受限 token 下，`bcrypt.dll` 的 `DllMain` 会拒绝初始化，导致静态依赖它的程序在 `main`
之前以 `0xC0000142` 退出。`rustls -> ring -> BCryptGenRandom` 会触发这个问题。

解决顺序：

1. **首选**：切换 rustls crypto provider（例如 `aws-lc-rs`），去掉对 `bcrypt.dll` 的
   静态依赖；需要确认宿主二进制与扩展均正常。
2. **兜底**：在 `rpi.exe` 同目录放一个最小 `bcrypt.dll` shim，只导出 `BCryptGenRandom`。
   这是 workaround，不是长期方案。

无论选哪种，都要写进发布说明。

## broker 与 IPC

- launcher 以正常 token 运行 broker；
- 使用命名管道 `\\.\pipe\rpi-sandbox-<pid>-<nonce>`；ACL 仅当前用户；
- 协议与 `protocol.md` 相同（JSON Lines）。

## 路径与文件系统

- 处理 junction / symlink：`realpath` 后仍需在授权子树内；
- 长路径（`\\?\`）需要显式支持；
- 大小写不敏感：授权/校验使用规范化后的路径比较。

## 已知限制

- ACL 修改是全局副作用，异常退出会残留；
- 某些系统 API（网络、服务控制）不受文件 ACL 影响（v1 本来也不限制网络）；
- 受限于 token 机制，无法阻止具有 `SeBackupPrivilege` 等特权的进程。

## 验收

- [ ] 可写根内写入成功
- [ ] 任意路径可读
- [ ] 根外写入失败（`Access is denied`）
- [ ] `bash`/子进程继承限制（若使用 Git Bash）
- [ ] 授权后 broker 写入成功
- [ ] 正常/异常退出后无残留 ACE
- [ ] `rpi.exe` 在受限 token 下能正常启动（bcrypt 问题已解决）
