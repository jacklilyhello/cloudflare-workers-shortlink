# 新业务 API

本文件描述 `src/core.ts` 实现的接口。真实环境成功与拒绝路径仍须在用户手动部署后验收。旧 `/api/v1/link`、旧 Token 和旧响应不兼容。

## 创建

唯一机器入口：`POST https://link-admin.lily.lat/api/shorten`。请求必须含 `Authorization: Bearer <业务Token>` 和 `Content-Type: application/json`。

```json
{"url":"https://example.com/a?sig=a%2Bb#section","domain":"test.gfw.mom","slug":"optional-code"}
```

`url`、`domain` 必填；`slug` 可省略，不能为空。只接受这三个字段，拒绝数组、重复 JSON 成员和所有高级配置字段。请求体 UTF-8 最多 16 KiB，完整 URL 最多 8 KiB。只接受 HTTP / HTTPS，不访问目标检测可达性；拒绝用户信息、控制字符、反斜杠和无效百分编码。域名须为小写裸 hostname。

测试环境只允许 `test.gfw.mom`，且数据库域名须已登记、已绑定并启用，同时此 Token 获准使用该域名。登记其他域名不会创建 DNS 或声明绑定。后台与 workers.dev 无法通过参数成为短链域名。业务 Token 不具有任何管理或查询能力；机器接口不启用 CORS、不要求浏览器验证码或交互式 Access 登录。

Token 由管理员后台生成，仅首次响应显示明文；D1 只保存 SHA-256 摘要。不存在默认 Token、部署用业务 Token 或 GitHub 固定测试业务 Token。撤销和到期均返回统一 `TOKEN_INVALID`。

创建成功：`201`、JSON、`Cache-Control: no-store`。

```json
{"ok":true,"data":{"slug":"Ab9xQ2mR","domain":"test.gfw.mom","short_url":"https://test.gfw.mom/Ab9xQ2mR"},"request_id":"opaque-id"}
```

错误结构：

```json
{"ok":false,"error":{"code":"SLUG_CONFLICT","message":"短码已被占用"},"request_id":"opaque-id"}
```

| HTTP | code | 含义 |
| --- | --- | --- |
| 400 | INVALID_JSON / INVALID_FIELD / UNKNOWN_FIELD | 格式、重复成员、非法幂等键或越权字段 |
| 400 | INVALID_URL / INVALID_DOMAIN / INVALID_SLUG | URL、域名或短码不合法 |
| 401 | TOKEN_REQUIRED / TOKEN_INVALID | 缺失、无效、撤销或到期的业务 Token |
| 403 | DOMAIN_FORBIDDEN / HOST_FORBIDDEN | 未授权域名或错误入口 |
| 404 | NOT_FOUND | 未知接口；没有旧接口兜底 |
| 405 | METHOD_NOT_ALLOWED | 只接受 POST，携带 Allow |
| 409 | SLUG_CONFLICT / IDEMPOTENCY_CONFLICT | 短码占用或幂等键内容不一致 |
| 413 | BODY_TOO_LARGE / URL_TOO_LONG | 超出字节上限 |
| 415 | UNSUPPORTED_MEDIA_TYPE | 非 JSON 请求 |
| 429 | RATE_LIMITED | 携带 Retry-After 秒数 |
| 500 | INTERNAL_ERROR | 内部失败，不暴露原始异常 |
| 503 | TEMPORARILY_UNAVAILABLE / SLUG_GENERATION_EXHAUSTED | 服务不可用或有限随机冲突重试用尽 |

客户端应依赖稳定 `code`，文字可能调整。按 `Retry-After` 等待，对网络失败使用有限退避；创建重试应携带幂等键。

## 幂等和短码

可选头 `Idempotency-Key` 为 1–128 个 ASCII 字母、数字或 `._:-`。它绑定 Token 身份、domain、原始完整 URL 和可选 slug，数据库约束保证同键并发只产生一个映射。同键同内容返回 `200` 和 `Idempotency-Replayed: true`，同键不同内容返回 `409`。键与永久映射共同保留，不因停用或统计清理而重用；撤销 Token 或停用域名后不能通过旧幂等键绕过权限。

不携带幂等键时，相同 URL 每次创建独立短链，网络超时后的重发可能产生第二条。自定义短码区分大小写、1–64 个 `[A-Za-z0-9_-]`；禁止保留路径 `api, admin, login, logout, assets, static, robots, favicon, health, config, _internal`。随机短码使用 60 位密码学随机值、D1 唯一约束和最多 8 次冲突重试。到期、停用或迁移的映射仍占用短码，不覆盖、不物理删除。

```bash
curl --request POST https://link-admin.lily.lat/api/shorten \
  --header "Authorization: Bearer $SHORTLINK_BUSINESS_TOKEN" \
  --header 'Content-Type: application/json' \
  --header 'Idempotency-Key: bot-message-unique-id' \
  --data '{"url":"https://example.com/a?x=a%2Bb#part","domain":"test.gfw.mom"}'
```

`SHORTLINK_BUSINESS_TOKEN` 是调用者自己的安全运行时变量，不能使用 Cloudflare 部署凭据或把真实值提交到仓库。

## 跳转、参数和生命周期

默认永久、启用、直接 `302` 跳转。管理员可设置到期、停用、确认页及纯文本说明。到期或停用先于确认页，返回 `410` 应用页面，映射永久保留。确认页中的继续访问按钮指向最终目标，不使用短链 query 作为内部命令。

D1 保存原始 URL，不重新序列化其 query、编码、参数顺序、重复项或 fragment。短链附加 query 的同名参数以目标为准，其他参数保留原编码并追加到 fragment 前。非 ASCII 字符仅在 HTTP Location 传输时转为 UTF-8 百分编码，国际化域名用 IDNA；已有百分编码保持原样。

默认 `merge` 策略识别 `sig, signature, hmac, x-amz-signature, x-goog-signature, awsaccesskeyid, key-pair-id, policy`。识别到签名且新增参数会改写 query 时，返回 `400` 页面，说明不能添加新参数；没有附加参数时保持原样。此清单不能识别所有签名方案。管理员可将单条链接设为 `preserve`，完全忽略短链附加 query，适用于自定义签名或迁移映射。普通调用者不能设置该策略。

## 匿名和管理员接口

前台创建：`POST /api/public/shorten`，仅接受 `url, slug?, turnstile_token`，domain 固定为测试前台。必须通过 Origin、真实服务端 Siteverify、精确 hostname 和 `action=create` 验证。匿名限流使用边缘连接 IP 的分钟摘要，属于频率控制；不存 IP 白名单或匿名历史。默认每连接摘要 10 次/分钟、每域名 120 次/分钟，业务 Token 默认 60 次/分钟，均由管理员设置。

管理员页面仅后台主机 `/admin`；后台根路径在 Access 验证后跳转至 `/admin`。所有 `/api/admin/*` 操作需 RS256 Access JWT 的签名、issuer、真实 audience、有效期、type=app 和两指定邮箱，写操作还需准确 Origin 与 JWT 绑定的 X-CSRF-Token。业务 Bearer 和伪造邮箱头不被接受。公共主机和 workers.dev 拒绝管理员和机器路由。

管理员 API 提供 links 列表/创建/高级属性 PATCH/批量状态或到期、域名登记/启停、Token 创建/撤销、聚合统计、设置、审计、迁移汇总、备份和下载。列表游标为不透明字符串；链接导出每页最多 500 条，前端显式读完所有页，导出过程中新增或修改不构成一致性快照。一致性备份使用 D1 单事务快照，再分片存至私有 R2。

Cloudflare 入口规则与 IP 切换说明见 [OPERATIONS.md](OPERATIONS.md)。正式 IP 白名单不在应用、数据库或业务 Token 中；测试临时全 IP 通行不代表正式白名单验收。
