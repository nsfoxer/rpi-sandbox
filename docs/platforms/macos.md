# macOS 后端：Seatbelt

## 机制

- launcher 调用 `sandbox_init(profile, 0, &err)`，把当前进程置于 Seatbelt 沙箱；
- 随后 `execve("rpi")`；Seatbelt 沙箱会随 exec 继承给 rpi 及其后代；
- broker 必须在 `sandbox_init` **之前** fork，否则它也会被限制。

> `sandbox_init` 已被标记 deprecated，但当前系统仍可用。备选：`sandbox-exec -p <profile> rpi`
> （同样 deprecated）；封装成内部接口，便于未来替换。

## Profile 形态

```scheme
(version 1)
(allow default)
(deny file-write*)
(allow file-write* (subpath "/Users/me/project"))
(allow file-write* (subpath "/private/tmp"))
(allow file-write* (subpath "/Users/me/.rpi/sessions"))
(allow file-write* (literal "/dev/null"))
(allow file-write* (literal "/dev/tty"))
```

- 路径必须先 `realpath`：macOS 上 `/tmp -> /private/tmp`、`/var -> /private/var`。
- 单文件用 `(literal ...)`，目录用 `(subpath ...)`。
- 读权限不 `deny`，保持默认放行。
- 需要额外放行系统临时目录（`$TMPDIR`，通常在 `/var/folders/...`）。

## 启动顺序

1. 解析参数/策略；
2. 建 Unix socket、fork broker；
3. 子进程 `sandbox_init`；
4. `execve rpi`。

## 打包

- 构建 universal binary（`x86_64-apple-darwin` + `aarch64-apple-darwin`）。
- 对外分发需要 codesign；notarization 需要 Apple Developer 账号。
- 在 README 中说明“未签名本地构建”和“已签名发布版”的差异。

## 已知限制

- Seatbelt API deprecated，未来系统版本可能移除；保留 `sandbox-exec` 回退。
- 路径匹配基于 vnode 路径；大小写不敏感文件系统（默认 APFS）需注意规范化。
- 不能从允许的父目录中扣除 `readonly` 子树（与 Landlock 同类限制）。
- 某些系统服务（mach lookup、keychain）可能需要额外规则；v1 只处理文件写。

## 验收

- [ ] 可写根内写入成功
- [ ] 任意路径可读
- [ ] 根外写入失败（`Operation not permitted`）
- [ ] `bash` 后代同样受限
- [ ] 授权后 broker 写入成功
- [ ] 未签名本地构建可用；签名流程文档化
