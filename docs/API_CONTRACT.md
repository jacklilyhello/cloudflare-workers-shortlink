# 新业务 API

本文件描述 `src/core.ts` 实现的接口。真实环境成功与拒绝路径仍须在已授权的 Actions `workflow_dispatch` 部署后验收；agent 可通过 gh / GitHub API 触发新测试环境流程，不能在本地直接执行 CF 写入。旧 `/api/v1/link`、旧 Token 和旧响应不兼容。

## 创建

唯一机器入口：`POST https://link-admin.lily.lat/api/shorten`。请求必须含 `Authorization: Bearer <业务Token>` 和 `Content-Type: application/json`。

```json
{"url":"https://example.com/a?sig=a%2Bb#section","domain":"test.gfw.mom","slug":"optional-code"}
```

`url`、`domain` 必填；`slug` 可省略，不能为空。只接受这三个字段，拒绝数组、重复 JSON 成员和所有高级配置字段。请求体 UTF-8 最多 16 KiB，完整 URL 最多 8 KiB。只接受 HTTP / HTTPS，不访问目标检测可达性；拒绝用户信息、控制字符、反斜杠和无效百分编码。域名须为小写裸 hostname。

domain 选择本次返回的公共短链前缀；数据库域名须已登记、真实绑定核验且启用，同时此 Token 获准使用该域名。同一短码在本项目所有有效公共域名前缀下解析同一逻辑映射，后加入的有效域名也适用。这不扩大 Token 的域名授权或管理能力，机器响应只返回选定前缀，不返回其他前缀列表。登记其他域名不会创建 DNS 或声明绑定。后台与 workers.dev 无法通过参数成为短链域名。业务 Token 不具有任何管理或查询能力；机器接口不启用 CORS、不要求浏览器验证码或交互式 Access 登录。

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
| 410 | LINK_DELETED | 旧幂等请求对应的映射已彻底删除，不重新创建 |
| 413 | BODY_TOO_LARGE / URL_TOO_LONG | 超出字节上限 |
| 415 | UNSUPPORTED_MEDIA_TYPE | 非 JSON 请求 |
| 429 | RATE_LIMITED | 携带 Retry-After 秒数 |
| 500 | INTERNAL_ERROR | 内部失败，不暴露原始异常 |
| 503 | TEMPORARILY_UNAVAILABLE / SLUG_GENERATION_EXHAUSTED | 服务不可用或有限随机冲突重试用尽 |

客户端应依赖稳定 `code`，文字可能调整。按 `Retry-After` 等待，对网络失败使用有限退避；创建重试应携带幂等键。

## 幂等和短码

可选头 `Idempotency-Key` 为 1–128 个 ASCII 字母、数字或 `._:-`。它绑定 Token 身份、domain、原始完整 URL 和可选 slug，数据库约束保证同键并发只产生一个映射。同键同内容返回 `200` 和 `Idempotency-Replayed: true`，同键不同内容返回 `409`。键与永久映射共同保留，不因停用或统计清理而重用；撤销 Token 或停用域名后不能通过旧幂等键绕过权限。

不携带幂等键时，相同 URL 每次创建独立短链，网络超时后的重发可能产生第二条。自定义短码区分大小写、1–64 个 `[A-Za-z0-9_-]`；禁止保留路径 `api, admin, login, logout, assets, static, robots, favicon, health, config, _internal`。随机短码使用 60 位密码学随机值、D1 唯一约束和最多 8 次冲突重试。短码在全部公共域名下大小写敏感全局唯一。到期、停用、迁移及已彻底删除的短码仍占用，不覆盖或复用；正常创建同 URL 仍独立生成。管理员可确认后物理删除在线映射，保留无目标 URL 的占用/幂等标记；旧键重放返回410 LINK_DELETED。

```bash
curl --request POST https://link-admin.lily.lat/api/shorten \
  --header "Authorization: Bearer $SHORTLINK_BUSINESS_TOKEN" \
  --header 'Content-Type: application/json' \
  --header 'Idempotency-Key: bot-message-unique-id' \
  --data '{"url":"https://example.com/a?x=a%2Bb#part","domain":"test.gfw.mom"}'
```

`SHORTLINK_BUSINESS_TOKEN` 是调用者自己的安全运行时变量，不能使用 Cloudflare 部署凭据或把真实值提交到仓库。

## 跳转、参数和生命周期

默认永久、启用、直接 `302` 跳转。管理员可设置到期、停用、确认页及纯文本说明。到期或停用先于确认页，返回 `410` 应用页面。映射属性对所有有效公共前缀一致；停用公共域名本身返回410“该短链域名已停用”，其他域名仍可使用。彻底删除的在线映射在所有前缀下404；删除不立即清理历史备份。确认页中的继续访问按钮指向最终目标，不使用短链 query 作为内部命令。

D1 保存原始 URL，不重新序列化其 query、编码、参数顺序、重复项或 fragment。短链附加 query 的同名参数以目标为准，其他参数保留原编码并追加到 fragment 前。非 ASCII 字符仅在 HTTP Location 传输时转为 UTF-8 百分编码，国际化域名用 IDNA；已有百分编码保持原样。

默认 `merge` 策略识别 `sig, signature, hmac, x-amz-signature, x-goog-signature, awsaccesskeyid, key-pair-id, policy`。识别到签名且新增参数会改写 query 时，返回 `400` 页面，说明不能添加新参数；没有附加参数时保持原样。此清单不能识别所有签名方案。管理员可将单条链接设为 `preserve`，完全忽略短链附加 query，适用于自定义签名或迁移映射。普通调用者不能设置该策略。

## 匿名和管理员接口

前台创建：`POST /api/public/shorten`，仅接受 `url, slug?, turnstile_token`，domain 由当前已核验启用的公共请求主机选定（workers.dev使用测试主前缀）。成功数据除slug/domain/short_url外有 `public_urls:[{domain,short_url}]`，仅列出当时核验启用的公共域名。必须通过 Origin、真实服务端 Siteverify、精确 hostname 和 `action=create` 验证。匿名限流使用边缘连接 IP 的分钟摘要，属于频率控制；不存 IP 白名单或匿名历史。默认每连接摘要 10 次/分钟、每域名 120 次/分钟，业务 Token 默认 60 次/分钟，均由管理员设置。

管理员页面仅后台主机 `/admin`；后台根路径在 Access 验证后跳转至 `/admin`。所有 `/api/admin/*` 操作需 RS256 Access JWT 的签名、issuer、真实 audience、有效期、type=app 和两指定邮箱，写操作还需准确 Origin 与 JWT 绑定的 X-CSRF-Token。业务 Bearer 和伪造邮箱头不被接受。公共主机和 workers.dev 拒绝管理员和机器路由。

管理员 API 提供 links 列表/创建/高级属性 PATCH/批量状态或到期/单条 DELETE、域名登记/真实刷新核验/启停、Token 创建/撤销、真实聚合统计、设置、审计与自动迁移/备份状态。`DELETE /api/admin/links/:id` 正文为 `{}`，需要上述管理员身份和Origin/CSRF；返回deleted/slug/all_public_prefixes，不提供匿名或Bearer删除。`POST /api/admin/domains/:hostname/verify` 正文为 `{}`，只使用独立只读凭据核验CF归属和HTTPS就绪，不创建绑定；读取失败记录failed而非不存在，最后检查与成功时间分开。停用域名不删除CF绑定，重新启用实时核验。列表游标为不透明字符串。`GET /api/admin/export` 保留每页最多 500 条的游标响应；内部受保护的兼容工具使用 `GET /api/admin/export/download`，由服务器读完所有页并完成序列化后返回 HTTP 附件，正文为 `{ "schema_version": 1, "links": [...] }`。读取失败返回错误响应，不返回不完整附件。两个导出入口都要求管理员 Access 身份；业务 Token 不能下载管理数据。分页读取期间新增或修改不构成一致性快照。一致性备份使用 D1 单事务快照，再分片存至私有 R2。

Cloudflare 入口规则与 IP 切换说明见 [OPERATIONS.md](OPERATIONS.md)。IP 白名单仅在 CF Custom Rules，当前要求87.83.110.180，不授权IPv6；不在应用、数据库或业务 Token 中。无该实际出口时名单内真实请求须列未验证。

## 自动计划与时间字段

`GET /api/admin/backups` 与 `GET /api/admin/migrations` 返回items/run及schedule：enabled、interval_hours、last_success_at、next_due_at、state、last_error_code、retry_count；备份还返回retention_days和digest_algorithm。记录内created_at/started_at/last_attempt_at/completed_at/retry_at均为Unix毫秒；失败不更新last_success_at。绑定last_checked_at代表尝试，last_verified_at代表成功。

`PUT /api/admin/settings`接受backup_enabled/migration_enabled为0或1；backup_interval_hours/migration_interval_hours为1..720；analytics_retention_days/audit_retention_days/backup_retention_days为0..3650（0=永久），限流值为1..1000。不能以0关闭访问记录或产生连续任务。

统计返回timezone=Asia/Singapore（事件/任务时间默认展示）和daily_timezone=UTC（历史趋势日桶的真实边界）。近似请求事件不是独立访客。内部export/backup download兼容接口继续受Access保护；日常后台只自动计划/状态，不要求管理员反复下载。
