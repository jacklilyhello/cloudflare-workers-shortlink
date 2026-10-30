# 新业务 API

本文件描述 `src/core.ts` 实现的接口。正式公共入口为 `gfw.mom` 与 `gfw.lat`，主域名为 `gfw.mom`。部署和基础设施变更只经已授权的 GitHub Actions `workflow_dispatch`，本地 Cloudflare 凭据与浏览器只读。旧 `/api/v1/link`、旧 Token 和旧响应不兼容。

## 创建

唯一机器入口：`POST https://link-admin.lily.lat/api/shorten`。请求必须含 `Authorization: Bearer <业务Token>` 和 `Content-Type: application/json`。

```json
{
  "url": "https://example.com/a?sig=a%2Bb#section",
  "domain": "gfw.mom",
  "slug": "optional-code"
}
```

`url`、`domain` 必填；`slug` 可省略，不能为空。只接受这三个字段，拒绝数组、重复 JSON 成员和所有高级配置字段。请求体 UTF-8 最多 16 KiB，完整 URL 最多 8 KiB。只接受 HTTP / HTTPS，不访问目标检测可达性；拒绝用户信息、控制字符、反斜杠和无效百分编码。域名须为小写裸 hostname。

domain 选择本次返回的公共短链前缀；数据库域名须已登记、真实绑定核验且启用，同时此 Token 获准使用该域名。同一短码在本项目所有有效公共域名前缀下解析同一逻辑映射，后加入的有效域名也适用。这不扩大 Token 的域名授权或管理能力，机器响应只返回选定前缀，不返回其他前缀列表。登记其他域名不会创建 DNS 或声明绑定。后台、已停用的 `test.gfw.mom` / `test.gfw.lat` 与 workers.dev 无法通过参数成为短链域名。业务 Token 不具有任何管理或查询能力；机器接口不启用 CORS、不要求浏览器验证码或交互式 Access 登录。

Token 由管理员后台生成，仅首次响应显示明文；D1 只保存 SHA-256 摘要。不存在默认 Token、部署用业务 Token 或 GitHub 固定测试业务 Token。撤销和到期均返回统一 `TOKEN_INVALID`。

创建成功：`201`、JSON、`Cache-Control: no-store`。

```json
{
  "ok": true,
  "data": {
    "slug": "Ab9xQ2mR",
    "domain": "gfw.mom",
    "short_url": "https://gfw.mom/Ab9xQ2mR"
  },
  "request_id": "opaque-id"
}
```

错误结构：

```json
{
  "ok": false,
  "error": { "code": "SLUG_CONFLICT", "message": "短码已被占用" },
  "request_id": "opaque-id"
}
```

| HTTP | code                                                | 含义                                       |
| ---- | --------------------------------------------------- | ------------------------------------------ |
| 400  | INVALID_JSON / INVALID_FIELD / UNKNOWN_FIELD        | 格式、重复成员、非法幂等键或越权字段       |
| 400  | INVALID_URL / INVALID_DOMAIN / INVALID_SLUG         | URL、域名或短码不合法                      |
| 401  | TOKEN_REQUIRED / TOKEN_INVALID                      | 缺失、无效、撤销或到期的业务 Token         |
| 403  | DOMAIN_FORBIDDEN / HOST_FORBIDDEN                   | 未授权域名或错误入口                       |
| 404  | NOT_FOUND                                           | 未知接口；没有旧接口兜底                   |
| 405  | METHOD_NOT_ALLOWED                                  | 只接受 POST，携带 Allow                    |
| 409  | SLUG_CONFLICT / IDEMPOTENCY_CONFLICT                | 短码占用或幂等键内容不一致                 |
| 410  | LINK_DELETED                                        | 旧幂等请求对应的映射已彻底删除，不重新创建 |
| 413  | BODY_TOO_LARGE / URL_TOO_LONG                       | 超出字节上限                               |
| 415  | UNSUPPORTED_MEDIA_TYPE                              | 非 JSON 请求                               |
| 429  | RATE_LIMITED                                        | 携带 Retry-After 秒数                      |
| 500  | INTERNAL_ERROR                                      | 内部失败，不暴露原始异常                   |
| 503  | TEMPORARILY_UNAVAILABLE / SLUG_GENERATION_EXHAUSTED | 服务不可用或有限随机冲突重试用尽           |

客户端应依赖稳定 `code`，文字可能调整。按 `Retry-After` 等待，对网络失败使用有限退避；创建重试应携带幂等键。

## 幂等和短码

可选头 `Idempotency-Key` 为 1–128 个 ASCII 字母、数字或 `._:-`。它绑定 Token 身份、domain、原始完整 URL 和可选 slug，数据库约束保证同键并发只产生一个映射。同键同内容返回 `200` 和 `Idempotency-Replayed: true`，同键不同内容返回 `409`。键与永久映射共同保留，不因停用或统计清理而重用；撤销 Token 或停用域名后不能通过旧幂等键绕过权限。

不携带幂等键时，相同 URL 每次创建独立短链，网络超时后的重发可能产生第二条。自定义短码区分大小写、1–64 个 `[A-Za-z0-9_-]`；禁止保留路径 `api, admin, login, logout, assets, static, robots, favicon, health, config, _internal`。随机短码使用 60 位密码学随机值、D1 唯一约束和最多 8 次冲突重试。短码在全部公共域名下大小写敏感全局唯一。到期、停用、迁移及已彻底删除的短码仍占用，不覆盖或复用；正常创建同 URL 仍独立生成。管理员可确认后物理删除在线映射，保留无目标 URL 的占用/幂等标记；旧键重放返回410 LINK_DELETED。

```bash
curl --request POST https://link-admin.lily.lat/api/shorten \
  --header "Authorization: Bearer $SHORTLINK_BUSINESS_TOKEN" \
  --header 'Content-Type: application/json' \
  --header 'Idempotency-Key: bot-message-unique-id' \
  --data '{"url":"https://example.com/a?x=a%2Bb#part","domain":"gfw.mom"}'
```

`SHORTLINK_BUSINESS_TOKEN` 是调用者自己的安全运行时变量，不能使用 Cloudflare 部署凭据或把真实值提交到仓库。已撤销、过期或彻底删除的 Token 不能创建短链或通过旧幂等键取回结果；幂等结果在返回前同样核对当前 Token 状态、域名授权及域名启用/绑定状态。

## 跳转、参数和生命周期

默认永久、启用、直接 `302` 跳转。管理员可设置到期、停用、链接确认页及域名中间页。到期或停用先于所有展示页，返回 `410` 应用页面。映射属性对所有有效公共前缀一致；域名中间页按实际访问的域名独立选择。停用公共域名本身返回410“该短链域名已停用”，其他域名仍可使用。彻底删除的在线映射在所有前缀下404；删除不立即清理历史备份。页面中的继续访问按钮指向最终目标，不使用短链 query 作为内部命令。

D1 保存原始 URL，不重新序列化其 query、编码、参数顺序、重复项或 fragment。短链附加 query 的同名参数以目标为准，其他参数保留原编码并追加到 fragment 前。非 ASCII 字符仅在 HTTP Location 传输时转为 UTF-8 百分编码，国际化域名用 IDNA；已有百分编码保持原样。

默认 `merge` 策略识别 `sig, signature, hmac, x-amz-signature, x-goog-signature, awsaccesskeyid, key-pair-id, policy`。识别到签名且新增参数会改写 query 时，返回 `400` 页面，说明不能添加新参数；没有附加参数时保持原样。此清单不能识别所有签名方案。管理员可将单条链接设为 `preserve`，完全忽略短链附加 query，适用于自定义签名或迁移映射。普通调用者不能设置该策略。

管理员另可设置 `query_policy: "origin"`：最终目标只保留协议、主机与端口并使用根路径 `/`，移除原路径、查询参数和片段，也忽略短链附加查询参数。例如 `https://a.bcd.com/123456?x=1#part` 跳到 `https://a.bcd.com/`。原始目标 URL 仍原样保存在 D1，切回 `merge` 或 `preserve` 后恢复使用。

### 域名中间页与链接确认页

`PATCH /api/admin/domains/:hostname` 可独立提交 `interstitial_enabled`（boolean）、`interstitial_delay`（0–300 秒整数，默认 5）和 `interstitial_html`（UTF-8 最多 128 KiB）。这些设置不创建或修改 Cloudflare 绑定，也不自动启用域名；原有 `enabled` 仍须通过绑定核验。域名列表返回上述配置。启用中间页后，通过该域名访问有效短链会显示自定义内容，倒计时结束自动前往最终目标，也可点击系统继续按钮。空内容使用默认页面；禁用时直接跳转。

`PATCH /api/admin/links/:id` 可设置 `confirmation_enabled`、`confirmation_mode: "text" | "html"` 和 `confirmation_text`。模式默认 `text`，历史内容不会自动变为可执行 HTML；纯文本最多 2000 字符，HTML 模式内容最多 128 KiB UTF-8。链接确认页开启时，在所有有效公共前缀下优先于域名中间页，并保留手动确认；关闭后使用实际域名的中间页设置。格式和内容可以一起修改，切换格式时内容必须符合该格式限制；并发修改冲突返回 409。

HTML 模式支持内嵌 HTML、CSS 和 JavaScript。自定义内容只能在 `sandbox="allow-scripts"` 的隔离 iframe 中运行，不授予 `allow-same-origin`、顶层导航、表单或弹窗权限；继续按钮、目标与倒计时由外层系统页面控制。CSP 禁止网络连接和外部脚本、样式、嵌套 frame，仅允许内嵌脚本/样式及 data 图片/字体。这些配置接口的 JSON 请求体上限为 `6 × 128 KiB + 8192` 字节，以容纳 JSON 转义及批量 ID。后台源码编辑器不执行内容。隔离语义依据 [HTML iframe 标准](https://html.spec.whatwg.org/multipage/iframe-embed-object.html) 和 [CSP 标准](https://www.w3.org/TR/CSP3/)。

`GET /api/admin/links?confirmation=enabled` 筛选显式开启链接确认页覆盖的映射，可与来源域名、状态、搜索和原有游标组合。只有域名中间页开启的链接不计入此筛选。本页全选只选择当前已加载的一页，切换页或筛选后清除选择。

`POST /api/admin/links/bulk` 新增 `action: "confirmation"`，接受 1–100 个 `ids`，可提交 `confirmation_enabled` 开启/关闭且保留内容，或同时提交 `confirmation_mode` 与 `confirmation_text` 统一更新内容且保留各自启用状态，也可一起提交；不接受到期字段。原有启停与到期操作不接受确认页字段。所有写入沿用管理员 Access、Origin 与 CSRF 校验，审计只记录字段/数量，不记录源码或目标 URL。

迁移 `0008_interstitial_pages.sql` 仅增加域名中间页和链接显示/根目录策略字段，默认关闭新功能，不改写原始 URL、旧确认文字、现有行 ID 或短码占用。部署须先应用迁移；新一致性快照包含这些配置。回退旧 Worker 会忽略新配置，应先关闭新展示功能及将 `origin` 改回所需策略；保留增量 schema，不删除历史数据。

## 匿名和管理员接口

前台创建：`POST /api/public/shorten`，仅接受 `url, slug?, turnstile_token`，domain 由当前已核验启用的公共请求主机选定；`test.gfw.mom`、`test.gfw.lat` 与全部 workers.dev 请求不能创建或跳转。成功数据除slug/domain/short_url外有 `public_urls:[{domain,short_url}]`，仅列出当时核验启用的公共域名。必须通过 Origin、真实服务端 Siteverify、精确 hostname 和 `action=create` 验证。匿名限流使用边缘连接 IP 的分钟摘要，属于频率控制；不存 IP 白名单或匿名历史。默认每连接摘要 10 次/分钟、每域名 120 次/分钟，业务 Token 默认 60 次/分钟，均由管理员设置。

管理员页面仅后台主机 `/admin`；后台根路径在 Access 验证后跳转至 `/admin`。所有 `/api/admin/*` 操作需 RS256 Access JWT 的签名、issuer、真实 audience、有效期、type=app 和准确管理员名单 `lilyyaloveyou@gmail.com`、`admin@888888.mom`、`moshaoli688@gmail.com`（三者同权），写操作还需准确 Origin 与 JWT 绑定的 X-CSRF-Token。业务 Bearer 和伪造邮箱头不被接受。公共主机和 workers.dev 拒绝管理员和机器路由。

管理员 API 提供 links 列表/创建/高级属性 PATCH/批量状态、到期或确认页/单条 DELETE、域名登记/真实刷新核验/启停/中间页配置、Token 创建/编辑/撤销、真实聚合统计、设置、审计与自动迁移/备份状态。`DELETE /api/admin/links/:id` 正文为 `{}`，需要上述管理员身份和Origin/CSRF；返回deleted/slug/all_public_prefixes，不提供匿名或Bearer删除。`POST /api/admin/domains/:hostname/verify` 正文为 `{}`，只使用独立只读凭据核验CF归属和HTTPS就绪，不创建绑定；读取失败记录failed而非不存在，最后检查与成功时间分开。停用域名不删除CF绑定，重新启用实时核验。列表游标为不透明字符串。`GET /api/admin/export` 保留每页最多 500 条的游标响应；内部受保护的兼容工具使用 `GET /api/admin/export/download`，由服务器读完所有页并完成序列化后返回 HTTP 附件，正文为 `{ "schema_version": 1, "links": [...] }`。读取失败返回错误响应，不返回不完整附件。两个导出入口都要求管理员 Access 身份；业务 Token 不能下载管理数据。分页读取期间新增或修改不构成一致性快照。一致性备份使用 D1 单事务快照，再分片存至私有 R2。

Cloudflare 入口规则与 IP 切换说明见 [OPERATIONS.md](OPERATIONS.md)。精确 `link-admin.lily.lat/api/shorten` 的 WAF 来源名单为 `103.118.43.47/32` 与 `45.77.252.181/32`，名单外 IPv4 和全部 IPv6 拒绝；它不影响后台浏览器、公网跳转或 lily.lat 其他服务。IP 策略只在 CF Custom Rules，不在应用、数据库、后台设置或业务 Token 中。保留业务 Bearer、域名授权、字段校验、应用限流、Access 与匿名 Turnstile。普通部署核验策略而不改写名单，生产维护禁止临时全 IP 放开。CF 拒绝发生在 Worker 前时，响应不属于上表中的应用 JSON 契约。

管理员列表与两个导出入口的 `domain` / `source_domain` 都保留链接创建或导入时的原始来源域名，查询参数 `domain` 按这一来源筛选，列表另标明 `domain_filter=source_domain`。不全表改写 `links.domain`。`public_urls` 列出当前登记、启用、真实绑定且已核验的公共地址，优先主域名；`current_domain` / `short_url` 取列表首项，没有可用公共域名时为 `null`。后台展示与复制使用这一当前地址，来源域名只作来源展示；历史测试域名来源的短码仍可由当前有效正式域名解析。机器创建响应继续使用调用者获准并指定的 `domain`，不改变 Token 域名权限、请求散列或幂等语义。

## 业务 Token 编辑、撤销与彻底删除

`PATCH /api/admin/tokens/:id` 可部分更新 `name`（非空、最多 100 字符）、`domains`（1–20 个已核验启用的公共域名）、`expires_at`（未来 Unix 毫秒或 `null`）及 `rate_per_minute`（1–1000 整数），至少提供一项。管理员 Access、Origin 和 CSRF 校验与创建/撤销一致；拒绝其他字段及非法 UUID。接口不更换或返回原 Token 明文/摘要，也不改变 Token ID、创建时间或既有短链。列表显示每分钟创建上限，并提供编辑弹窗。

已撤销 Token 返回 409，已删除或未知 Token 返回 404，不能通过编辑恢复凭据。已过期但未撤销的 Token 可由管理员延长到期时间；修改域名授权后，创建和幂等重放均按当前授权判断。更新与审计在同一事务完成，并在事务内复核 Token 和域名状态；并发撤销、删除或域名停用会拒绝冲突更新。`token.update` 审计只记录字段名，不记录凭据。

`DELETE /api/admin/tokens/:id` 保留原有“撤销”语义：凭据失效，Token 仍在管理列表中，重复撤销返回成功且不重复生成撤销审计。新增 `POST /api/admin/tokens/:id/delete`，正文只能为 `{ "confirm": true }`；需要管理员 Access、准确 Origin 及 JWT 绑定的 CSRF，ID 必须为标准小写 UUID，未知 ID 返回 404，缺少明确确认或包含其他字段返回 400。可对有效、已过期或已撤销 Token 执行，界面二次确认默认取消。成功返回 `{ "deleted": true, "id": "..." }`，重复请求保持成功且只生成一次 `token.delete` 审计。

彻底删除在同一事务中使 Token 失效、将原认证摘要替换为不能匹配认证结果的唯一标记、移除所有域名授权，并记下删除时间。已删除 Token 不再出现在管理列表，也没有恢复入口；已有短链接、原 Token ID/名称及生命周期信息、幂等占用和历史审计保留。数据库保留不可认证的身份占位以维护既有外键和审计来源，不物理删除历史短链或改写它们的创建者。认证、新建及幂等重放均核对当前删除/撤销状态，删除后不能借用在途请求重新创建。

新增迁移 `0007_token_deletion.sql` 只增加可空 `tokens.deleted_at`，不自动删除或撤销既有 Token。新版本需要先应用该迁移；新建一致性备份包含删除状态和不可认证标记，恢复此类快照也需使用已升级的数据库结构。删除不重写或清理既有备份；若恢复删除之前的旧快照，需要重新应用其后发生的撤销及删除决定，不能把恢复旧状态视为恢复凭据的授权。

## 审计日志操作者

`GET /api/admin/audit` 保留原有 `actor`、操作、对象、详情、时间及每页最多 50 条的游标语义，每条额外返回 `actor_identity:{type,name,token_id,created_by}`。`type` 为 `admin`（已验证管理员登录邮箱）、`business_token`（机器调用的业务 Token）、`anonymous`（公共网页匿名访客）、`system`（系统定时任务或生产迁移备份）或 `unknown`（无法识别的历史标识）；不适用或无法核实的字段为 `null`。系统明确识别现有 `system:scheduled` 和 `system:production-migration`，保留原始标识供核对；其他未知标识不猜测归属。若旧版接口未返回身份扩展字段，页面仍可从原始已知标识显示管理员邮箱、系统操作和匿名访客；旧前端继续使用保留的原有字段。

业务 Token 操作者的 `name` 来自对应 Token 名称，`token_id` 为非凭据的完整 Token ID；已撤销或过期的 Token 仍可解释历史记录。`created_by` 只在留存的该 Token 创建审计记录能唯一确认创建管理员邮箱时返回，查询包含当前分页以外的记录。创建管理员不代表实际调用机器接口的人，日志不据此推断调用人。缺失或不一致的创建记录显示“创建管理员：未记录”，缺失名称显示“名称未记录”；无法识别的操作者保留原始标识供核对。接口不返回 Token 明文或摘要，也不回写历史审计数据。

审计列表支持组合查询参数，均在数据库筛选后再分页，响应额外标明 `filtering_supported:true`：

| 参数 | 语义 |
| --- | --- |
| `q` | 去掉首尾空白后最多 200 字符，按字面子串搜索原始操作者、操作代码、对象 ID 或业务 Token 名称；不搜索 Token 明文、摘要、审计详情或创建管理员关联信息。ASCII 大小写不敏感，`%` / `_` 不作为通配符。 |
| `from` / `to` | 包含端点的 Unix 毫秒，可只传一端；须为 0..8640000000000000 的整数，开始不得晚于结束。页面按 Asia/Singapore（UTC+8）解释输入，并包含结束时间所选整秒。 |
| `actor` | 精确匹配原始操作者邮箱或 ID，1–200 字符且不含控制字符；省略表示不限。 |
| `system_only=1` | 只匹配 `system:scheduled` 与 `system:production-migration`。与其他条件同时生效，未知 `system:*` 不自动归入系统。 |
| `exclude_action` | 可重复传入，最多 20 项，去重后排除匹配的操作代码；每项须满足 `[a-z][a-z0-9_.-]{0,79}`。仅隐藏查询结果，不删除日志。 |
| `cursor` | 保留原有倒序行游标；加载后续页需同时携带相同筛选条件。 |

单值筛选参数重复、时间倒序或字段超限返回 400；不提供筛选时保留原有列表行为。页面应用或重置筛选后从第一页开始；编辑条件但尚未提交时，“加载更多”仍使用上次已应用的条件。若旧接口缺少筛选支持标识，页面拒绝将未筛选的结果展示为筛选结果。

`GET /api/admin/audit/options` 同样要求管理员身份，返回 `{actors:[{actor,actor_identity}],actions,actors_truncated,actions_truncated}`。选项来自全部留存审计，不受当前列表分页或筛选限制；操作者最多 200 项、操作代码最多 100 项并按原始标识排序，达到上限会标明截断。业务 Token 选项只包含当前有效或已撤销的记录，已撤销后过期的仍可选；已删除、仅过期但未撤销、以及已无对应 Token 的历史机器身份在 SQL 限额之前排除，不占用下拉项数。未产生审计的 Token 不额外列入选项。管理员、已知系统和匿名访客的选择保持不变；真实未知的非 Token 身份仍保留。

选项的 `created_by` 固定为 `null`，不会为选项重复扫描创建人历史；创建管理员说明仍由日志行提供。移出下拉不删除或隐藏历史审计，仍可通过名称、原始 Token ID 或直接 `actor` 参数查询。历史条目超过选项数量时，可通过关键词继续查询。此接口不返回 Token 明文、摘要、审计详情或目标 URL。

## 自动计划与时间字段

`GET /api/admin/backups` 与 `GET /api/admin/migrations` 返回items/run及schedule：enabled、interval_hours、last_success_at、next_due_at、state、last_error_code、retry_count；备份还返回retention_days和digest_algorithm。记录内created_at/started_at/last_attempt_at/completed_at/retry_at均为Unix毫秒；失败不更新last_success_at。绑定last_checked_at代表尝试，last_verified_at代表成功。

`PUT /api/admin/settings`接受backup_enabled/migration_enabled为0或1；backup_interval_hours/migration_interval_hours为1..720；analytics_retention_days/audit_retention_days/backup_retention_days为0..3650（0=永久），限流值为1..1000。不能以0关闭访问记录或产生连续任务。

统计返回timezone=Asia/Singapore（事件/任务时间默认展示）和daily_timezone=UTC（历史趋势日桶的真实边界）。近似请求事件不是独立访客。内部export/backup download兼容接口继续受Access保护；日常后台只自动计划/状态，不要求管理员反复下载。

`GET /api/admin/stats` 另返回 `browsers:[{name,count}]`，根据请求 UA 推断固定、有限的浏览器类别，不保留原始 UA。迁移 `0009_browser_stats.sql` 增加独立的 `daily_browser_stats` 日聚合，不改写旧地域/设备/来源统计及其主键；新访问在同一 D1 事务内写入两类聚合，失败时一起回滚。历史未保存 UA 的访问计入 `unknown`，不能反推浏览器。新表进入一致性快照及同一访问统计保留策略（0 表示永久）。

统计页地图沿国家形状高亮；趋势使用细线、悬停十字线和提示卡，也支持方向键。地区、设备、来源和浏览器排行默认展示前五项，展开大弹窗可搜索全部排行；地区附国旗，未知地区显示通用标记。趋势继续如实标注 UTC 日桶，不按新加坡时区伪造历史重分桶。

Access Allow 与 Worker 独立 JWT 校验同时接受上述准确名单并拒绝名单外身份；业务 Bearer Token 权限不因管理员名单变更而变化。

## 应用错误页

后台左侧“应用错误页”独立管理 `error_403`（403）、`error_404`（404）、`error_disabled`（链接停用或过期，410）和 `error_500`（其他应用错误）。原有纯文字设置继续有效，每项可切换为自定义 HTML；公共域名自身停用时仍显示固定的域名停用说明，API 错误仍返回原 JSON。Cloudflare WAF / Access 在 Worker 之前返回的拦截页不由此配置管理。

`GET /api/admin/error-pages` 返回以这四个键索引的对象，每项为 `{ "mode": "text" | "html", "text": "...", "html": "..." }`。`PUT /api/admin/error-pages` 一次保存一项，只接受 `key, mode, text, html` 四个字段；需要管理员 Access 身份及准确 Origin / CSRF。文字最多 500 字符，HTML 为单个 UTF-8 文件，最多 128 KiB，HTML 模式不接受空白内容。此上传接口的 JSON 请求体上限为 `6 × 128 KiB + 4096` 字节，以容纳 JSON 转义；链接确认页和域名中间页配置接口的上限见前文，其余接口仍为 16 KiB。文字、模式与 HTML 在同一 D1 事务中写入 settings，既有一致性备份自动涵盖这些内容，审计仅记录类别、模式及 HTML 字节数。

前端上传文件只载入草稿；点击“预览”后，在受保护的 `GET /api/admin/error-pages/preview` 隔离页面中载入内容，完成后才解锁保存。更换文件、文字或模式会使预览失效，需要再次预览。预览不写入数据库；保存后才影响应用错误页。

HTML 文件可包含内嵌 CSS、JavaScript，以及 data URL 图片和字体。预览与正式 HTML 错误页均使用响应头 CSP sandbox，仅允许脚本运行，不授予同源身份；外部资源、接口请求、表单、嵌套框架及弹窗受限。不能依赖外部 CDN、独立 CSS / JS 文件或后台会话。sandbox 仍允许页面自身导航，不保证上传脚本正确运行；预览载入不等同于浏览器功能验收。正式 HTML 错误页保留原 HTTP 状态，禁止嵌入且不缓存；HTML 配置缺失、无效或数据库读取失败时回退到文字页。
