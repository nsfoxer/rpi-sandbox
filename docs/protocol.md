# Launcher ↔ 扩展协议

## 1. 传输与握手

| 平台 | 传输 |
|---|---|
| Linux / macOS | Unix domain socket（`SOCK_STREAM`） |
| Windows | 命名管道（`\\.\pipe\rpi-sandbox-<pid>-<nonce>`） |

launcher 在 `exec rpi` 前设置环境变量：

| 变量 | 含义 |
|---|---|
| `RPI_SANDBOX_ACTIVE=1` | 当前进程处于 launcher 建立的沙箱内 |
| `RPI_SANDBOX_SOCKET` | broker 的 socket 路径 / 命名管道名 |
| `RPI_SANDBOX_PROFILE` | 当前 profile 名称（用于日志与展示） |
| `RPI_SANDBOX_VERSION=1` | 协议版本 |

扩展启动时：

1. 读取 `RPI_SANDBOX_ACTIVE`；缺失则提示“当前未隔离”，进入降级模式。
2. 连接 `RPI_SANDBOX_SOCKET`；失败则提示“broker 不可用”，越权写一律拒绝。
3. 发一次 `hello`，校验版本。

## 2. 帧格式

一行一个 JSON 对象（UTF-8），`\n` 结尾：

```json
{"v":1,"id":7,"op":"write","path":"/home/u/file.txt","data":"aGVsbG8=","append":false}
```

响应：

```json
{"v":1,"id":7,"ok":true}
{"v":1,"id":7,"ok":false,"code":"not_approved","error":"write to /home/u/file.txt is not approved"}
```

- `id`：客户端自增，响应必须回显。
- 同一连接上的请求按顺序处理；扩展内部需要用互斥锁串行化。
- 字符串长度上限、单次数据大小上限由实现定义（建议 16 MiB），超限返回 `too_large`。

## 3. 操作

### `hello`

```json
{"v":1,"id":1,"op":"hello","client":"rpi-sandbox-extension","version":"0.1.0"}
```

响应：`{"ok":true,"sandbox":"landlock","profile":"default"}`

### `approve`

```json
{"v":1,"id":2,"op":"approve","path":"/home/u/.ssh","operations":["create","overwrite"],"scope":"session","recursive":false}
```

- `scope`：`once` | `session`。
- `recursive`：`true` 表示覆盖 `path` 的子树（目录授权）。
- 只记录授权，不执行写入。

### `check`

```json
{"v":1,"id":3,"op":"check","path":"/home/u/a.txt","operation":"overwrite"}
```

不消耗 `once` 授权。响应 `ok=true` 表示已有可用授权。

### `write` / `append`

```json
{"v":1,"id":4,"op":"write","path":"/home/u/a.txt","data":"<base64>","append":false}
```

- 未授权返回 `not_approved`。
- `write` 会在需要时创建父目录；`append` 直接追加。
- 成功后 broker 负责设置权限、刷新并写审计。

### `truncate`

```json
{"v":1,"id":5,"op":"truncate","path":"/home/u/a.txt","len":0}
```

### `delete`

```json
{"v":1,"id":6,"op":"delete","path":"/home/u/a.txt"}
```

### `rename`

```json
{"v":1,"id":7,"op":"rename","path":"/home/u/a.txt","target":"/home/u/b.txt"}
```

需要源路径 `rename` 授权、目标路径 `create` 授权。

### `mkdir`

```json
{"v":1,"id":8,"op":"mkdir","path":"/home/u/newdir"}
```

### `revoke`

```json
{"v":1,"id":9,"op":"revoke","path":"/home/u/a.txt","recursive":true}
```

## 4. 错误码

| code | 含义 |
|---|---|
| `not_approved` | 没有对应授权 |
| `invalid_path` | 非绝对路径 / 无法解析 |
| `unsafe_path` | 软链或规范化后逃逸 |
| `io` | 底层 IO 错误 |
| `too_large` | 负载超限 |
| `unsupported` | 未知操作 |
| `version` | 协议版本不匹配 |
| `internal` | broker 内部错误（保留） |

## 5. 审计

broker 每处理一个请求追加一行 JSON：

```json
{"time":1794640000,"op":"write","path":"/home/u/a.txt","ok":true,"error":null,"scope":"session"}
```

- 审计文件位于策略中的 `auditLog`；不可写时 broker 仍继续工作，但在 stderr 警告。
- 审计由 broker 写，沙箱内进程无权修改。

## 6. 安全要求

- socket / 命名管道只允许当前用户访问（Unix 权限 `0600`；Windows 管道 ACL 仅当前用户）。
- broker 必须重新 `realpath` 并校验路径仍在授权范围内；不信任扩展传来的字符串。
- broker 不解析模型输出，只接受结构化路径 + 操作。
- 扩展的授权决定来自前端（TUI/RPC/ACP），不由模型文本直接触发。

## 7. 并发与超时

- 建议 broker 单线程顺序处理；扩展侧一个请求一个响应。
- 请求超时（默认 10 秒）返回 `io`/`timeout`；授权对话框本身的超时由扩展负责（建议 5 分钟，超时视为拒绝）。
- 连接断开：launcher/broker 退出，rpi 的越权写请求失败并明确报错。
