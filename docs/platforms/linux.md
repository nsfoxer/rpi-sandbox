# Linux 后端：Landlock

## 机制

- `landlock_create_ruleset`：声明要处理的写侧访问位；
- `landlock_add_rule(PATH_BENEATH)`：为每个可写根授权；
- `prctl(PR_SET_NO_NEW_PRIVS)`；
- `landlock_restrict_self`：对调用线程生效；
- 域由子进程和线程继承，**不可撤销、不可扩展**。

## 处理位

| 位 | ABI | 说明 |
|---|---|---|
| `WRITE_FILE` | v1 | 文件内容写入 |
| `REMOVE_DIR` / `REMOVE_FILE` | v1 | 删除 |
| `MAKE_*` | v1 | 创建目录/文件/符号链接等 |
| `REFER` | v2（5.19） | rename/link 跨目录 |
| `TRUNCATE` | v3（6.2） | `truncate` / `ftruncate` |
| `READ_FILE` / `READ_DIR` / `EXECUTE` | v1 | **不处理** = 放行（v1 不做读限制） |

启动时探测 ABI，低版本按能力降级；低于 v1 直接失败。

## 计划构建

```text
handled = BASE(v1 位)
if abi >= 2: handled |= REFER
if abi >= 3: handled |= TRUNCATE

for rule in writable:
    if Dir: access = handled
    if File: access = handled & (WRITE_FILE | TRUNCATE)
    if path 不存在: 跳过
规则按路径去重并合并 access
```

- 文件规则不能用 `MAKE_*`/`REMOVE_*`/`REFER`，内核会返回 `EINVAL`。
- 不存在的写目标跳过（它无法被打开）；父目录可写时，后续创建仍受规则约束。

## 应用顺序

1. launcher 单线程解析参数/策略（`args.rs` / `setup.rs`，与 Windows 共用）；
2. `Listener::bind` 建 Unix socket、fork broker（父进程在独立线程上服务审批）；
3. 子进程（即将 exec 的 launcher 本体）调用 `linux::apply`；
4. `exec rpi`。

后端实现：`crates/rpi-sandbox-launcher/src/linux.rs`（`SandboxBackend` 的 Landlock impl）。

错误处理：`landlock_create_ruleset` / `add_rule` / `restrict_self` 任一步失败都必须
按 `mode` 决定继续（警告）或拒绝启动。

## 已知限制

- 规则绑定 inode：启动后删除重建的可写目录失效；重启恢复。
- 软链：规则和查询都要解析到真实路径；父目录不存在时按“最深已存在祖先 + 剩余组件”。
- 嵌套 `protected` 无法由内核扣除；启动警告或 `required` 拒绝。
- 已打开的 fd 不受影响（launcher 自身日志/会话 fd 属于预期）。
- `chmod`/`chown`/`utimes` 不在 Landlock 覆盖范围内。

## 验收

- [x] 可写根内写入成功
- [x] 任意路径可读
- [x] 根外写入返回 `EACCES`
- [x] `bash` 后代同样受限
- [x] 授权后 broker 写入成功；撤销后拒绝
- [x] ABI v1/v2/v3 的掩码单测
- [x] `mode=required` 在无 Landlock 内核上拒绝启动

实现与测试：`crates/rpi-sandbox-core/src/linux.rs`、
`crates/rpi-sandbox-core/tests/landlock_enforcement.rs`、
`crates/rpi-sandbox-launcher/tests/linux_enforcement.rs`。
