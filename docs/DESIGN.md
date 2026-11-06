# vlt — 设计说明

`vlt` 是给自动化 agent 用的 Vaultwarden 命令行客户端：读写、查找密码，默认不把明文带进命令行、日志和临时文件。

## 非目标

- 不做交互式 TUI、不做浏览器插件、不做多用户组织管理。
- 不实现 Bitwarden 全协议（attachments、sends、organizations、emergency access 一律不做）。
- 不做常驻服务、不做本地加密缓存。

## 使用面

```
vlt get <name> [--field password|username|totp|uri|notes|name] [--stdout] [--json]
vlt set <name> [--username U] [--uri U]
               [--password-stdin | --password-file F | --generate [--length N]]
               [--note-stdin | --note-file F] [--type login|note] [--folder agent]
vlt ls [query] [--json] [--folder F]
vlt find <query> [--json]
vlt rm <name> [--yes]
vlt run --env KEY=<name>.<field> [--env ...] -- <command> [args...]
vlt doctor
vlt lock
```

约定：

- `<name>` 是条目名，默认落在 folder `agent` 下，命名 `用途/系统`（如 `svc/gitea`、`api/newapi`）。
- `get` 默认只打印元信息，机密字段打码。`--field` 输出单值；机密字段在 stdout 为 TTY 时拒绝执行，需 `--stdout` 或 `--reveal` 显式要求。
- `--json` 输出结构化结果；不含机密，除非同时给 `--stdout`。
- `set` 按名字 upsert：存在则更新给定字段，不存在则新建；未给的字段保持原值。
- `run` 把值注入子进程环境变量，不落 argv，透传 stdin/stdout/stderr 与退出码；`<name>` 不带字段时默认取 password。
- 退出码：0 成功，1 通用错误，2 用法错误，3 未找到，4 认证失败，5 网络/服务错误。

## 泄漏面与对策

| 面 | 对策 |
|---|---|
| 进程命令行 `ps` | 机密只能从 stdin、600 权限文件或 `--generate` 进入；任何命令都不接受明文密码参数 |
| 终端回显 | 机密字段默认打码；`--field password/totp/notes` 在 TTY 下拒绝，需 `--reveal` |
| shell 历史 | 文档只给管道用法；工具本身不提示输入明文 |
| 日志/报错 | 不写日志文件；错误信息对已解析的机密做字符串替换后再输出 |
| 本地落盘 | 不写明文缓存；会话 token 缓存可选，600 权限、TTL 15 分钟、`vlt lock` 可清 |
| 子进程 | `run` 走环境变量，不走参数 |
| 文件权限 | 启动时检查配置文件与所在目录权限，不合规直接退出 |

## 配置

读环境文件（默认 `~/.secrets/vlt.env`，可用 `VLT_CONFIG` 覆盖），三个键：

```
BW_SERVER=https://vault.example.com
BW_EMAIL=agent@example.com
BW_PASSWORD=...
```

允许 `VLT_PASSWORD_FILE` 指向单独的主密码文件。权限必须是 600/400，目录 700。

## 协议要点（对照 Vaultwarden 2026.6.0 实测）

- 登录取参：`POST /identity/accounts/prelogin`，body `{"email":"..."}` → `Kdf`、`KdfIterations`。
- 派生：
  - `masterKey = PBKDF2-SHA256(password, lower(email), iterations, 32)`
  - `masterPasswordHash = base64(PBKDF2-SHA256(masterKey, password, 1, 32))`
  - `encKey = HMAC-SHA256(masterKey, "enc" || 0x01)`，`macKey = HMAC-SHA256(masterKey, "mac" || 0x01)`
  - 注意是 **HKDF-Expand**，不做 Extract；用 RFC 5869 的完整 HKDF 会得到不同的键。
- 登录：`POST /identity/connect/token`，form：`grant_type=password`、`username`、`password=<masterPasswordHash>`、`scope=api offline_access`、`client_id=cli`、`deviceType=8`、`deviceIdentifier=<uuid>`、`deviceName=vlt`。
- 用户密钥：登录响应 `Key`（EncString）用拉伸后的主密钥解密，得到 64 字节（前 32 加密、后 32 MAC）。
- EncString：`2.<b64 iv>|<b64 ciphertext>|<b64 mac>`；AES-256-CBC + PKCS7；MAC = HMAC-SHA256(macKey, iv || ciphertext)。
- 账号信息：`GET /api/accounts/profile`，拿 `id`（uuid，用于 `encryptedFor`）。
- 条目：
  - 列表/同步：`GET /api/sync`（一次拿 profile、folders、ciphers）或 `GET /api/ciphers`。
  - 新建：`POST /api/ciphers`；更新：`PUT /api/ciphers/<id>`；删除：`DELETE /api/ciphers/<id>`。
  - 请求体必须带 `"encryptedFor": "<账号 uuid>"`，缺失或为 null 会 422。这是 2025 版官方 CLI 写不进去的原因。
  - login 条目形如 `{"type":1,"name":enc,"notes":enc,"favorite":false,"reprompt":0,"folderId":null,"organizationId":null,"encryptedFor":uid,"login":{"uris":[{"uri":"..."}],"username":enc,"password":enc,"totp":enc|null}}`。
- 文件夹：`GET /api/folders`，`POST /api/folders` body `{"name": enc}`。
- TOTP：`login.totp` 可能是 `otpauth://` URI 或裸 base32；按 RFC 6238（SHA1、6 位、30 秒）计算。
- 限流：登录接口有按 IP 的限流（429）。同一次调用内复用 token；跨调用可用 token 缓存（见上）。

## 代码结构

```
cmd/vlt/main.go        命令解析、TTY 判定、输出
internal/vw/           API 客户端：prelogin / login / sync / ciphers / folders
internal/crypt/        派生与 EncString 编解码
internal/secret/       配置读取、权限检查、脱敏
internal/store/        名称索引、upsert、搜索
internal/totp/         RFC 6238
```

只依赖标准库和 `golang.org/x/crypto`（PBKDF2 与 Argon2id）。

## 发布

- Go 1.22+，`CGO_ENABLED=0`，纯静态二进制。
- GitHub Actions：push/PR 跑 gofmt、vet、test、build；打 `v*` 标签跑 GoReleaser 出全平台产物（linux/darwin/windows/freebsd/openbsd/netbsd × amd64/arm64/386/armv6/armv7/mips/mipsle/mips64/mips64le/ppc64le/s390x/riscv64/loong64，按 Go 实际支持矩阵取舍）。
- 产物：tar.gz / zip、sha256 校验和、CHANGELOG。

## 安全模型（写进 README）

- 主密码文件即最高权限；文件 600、目录 700，谁读得到谁就拥有这个库。
- 服务端默认走 HTTPS；纯 HTTP 只用于可信内网。
- token 缓存是可选项，默认 15 分钟过期，`vlt lock` 立即清除。
- 本工具不防同机同用户的进程——同一 uid 的进程本来就能读配置文件。
