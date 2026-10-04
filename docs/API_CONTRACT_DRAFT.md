# 新业务 API 契约草案

> 本文件保留初始化草案。当前实现契约见 [API_CONTRACT.md](API_CONTRACT.md)；首次精准 WAF / Access 接入已经获准通过用户手动 Actions 实施，应用仍不管理 IP 白名单。

**尚未实现、未部署、未远程测试。** 以下身份、域名、能力与数据保护边界已确定；数字限制和可选项是待开发阶段验证的建议。旧 `/api/v1/link`、`key`、旧响应、旧业务 Token 与 DWZLA 均不兼容、不导入。

## 入口与请求

计划唯一机器入口：`POST https://link-admin.lily.lat/api/shorten`。调用者是服务器、脚本或机器人。

```http
POST /api/shorten HTTP/1.1
Host: link-admin.lily.lat
Authorization: Bearer <业务Token>
Content-Type: application/json
```

```json
{"url":"https://example.com/a?sig=a%2Bb#section","domain":"test.gfw.mom","slug":"optional-code"}
```

`url` 和 `domain` 必须为字符串；`slug` 可省略，提供时必须为非空字符串。请求体只接受这三个创建字段和单个 JSON 对象，不接受数组、批量、重复 JSON 成员或额外字段。拒绝到期时间、启停、确认文字、统计设置、Token 权限等管理字段，不通过字段透传或批量赋值处理输入。

`domain` 必须是管理员已登记、实际绑定、启用且该业务 Token 获准使用的短链域名；测试阶段只开放 `test.gfw.mom`。不能通过参数创建 DNS/绑定域名，不能用 Host 或转发头覆盖登记域名。裸小写 hostname，不接受协议、路径、端口、尾点、wildcard 或任意同账户域名；规范化方案需一致验证。

## 身份与路由隔离

业务 Token 只能由管理员后台生成和管理：高熵随机，仅首次显示明文，D1 保存不可逆摘要，支持撤销、轮换、到期和管理员配置的域名权限。无默认 Token、无固定 `TEST_API_TOKEN`；部署 Token 和 Analytics Token 不能作为业务身份，不进入浏览器。

机器 API 仅创建，能力与匿名创建一致；没有列表、历史、读取管理数据、修改、删除、统计或管理能力。网络层 IP 放行不代替 Bearer 鉴权。程序不实现 IP 白名单、每 Token IP 限制、`API_ALLOWED_IPS`/`API_ALLOWED_CIDRS` 或 WAF 同步。

机器调用不要求浏览器 Turnstile 或交互式 Access 登录。若需 Access 豁免，只能针对精确主机及 `/api/shorten`，不能豁免 `/api/*`；Worker 仍逐项校验主机、路径、POST 方法、业务 Token 与域名权限。未知路径/方法必须拒绝，不能落入匿名创建兜底。机器跨源浏览器调用默认不开放 CORS；机器不是依赖浏览器 Origin 的身份。

后台浏览器内部接口另设受保护路径，需 Access JWT 签名、issuer、真实 AUD、有效期、允许邮箱以及 Origin/CSRF 验证。客户端自填 `Cf-Access-Authenticated-User-Email` 或转发头不可信；业务 Token 不能授权管理员操作。

前台 `test.gfw.mom` 与新 Worker `workers.dev` 不提供后台或机器接口，即使请求携带正确业务 Token 也拒绝。前台匿名创建保留 Turnstile、输入校验和防滥用，不能成为免验证码机器备用入口。错误响应不泄漏 Token、目标 URL 或管理信息。

## URL、短码与生命周期

只接受完整 HTTP/HTTPS URL；建议拒绝用户信息、控制字符、无主机或非法编码。使用 URL 解析器做合法性验证后保留原字符串，不重新序列化改变 query、编码顺序、重复参数、`+`/`%20`、fragment 或签名。不要重复 decode、拆散后重拼目标，也不抓取目标来验证可达性。

短链附加 query 仅作为目标参数，不解释为管理命令、权限或内部配置。目标中已存在的同名参数优先且保留所有原有重复项；附加同名参数丢弃，新的参数在 fragment 之前追加。合并应保留目标 query 字节串，通过单次解析识别参数名，同时保留附加参数原编码；不对目标全部调用 `URLSearchParams.toString()`。原目标 fragment 始终保留。

签名 URL 有按完整 query 校验的情形：任何新增参数都可能使签名失效，不能声称通用合并对所有签名有效。建议允许原样访问；当附加 query 会改写敏感签名 URL 时显式拒绝并说明原因，或由管理员配置明确的原样透传策略。签名识别范围、错误页和设置方案待定，不能静默重编码或丢弃用户参数。原 URL 不带附加 query 时必须逐字保持。

随机短码使用密码学安全随机数、数据库唯一约束和有限冲突重试；禁止覆盖已有映射。自定义短码已用（含过期/停用）统一冲突；拒绝保留路径、斜杠、点段、Unicode 混淆、危险百分号编码/双重编码。建议短码区分大小写、ASCII `[A-Za-z0-9_-]`、长度 1–64；保留路径清单至少覆盖 `api`、`admin`、`login`、`robots.txt`、`favicon.ico` 等未来系统路由，最终规则待确定。

链接默认永久。相同 URL 每次正常创建独立短码，不全局去重。过期/停用先于确认页和跳转，永久保留映射、不物理删除、不复用；只有管理员可配置高级属性。

## 响应草案

创建成功建议 `201 Created`、`Content-Type: application/json`、`Cache-Control: no-store`：

```json
{"ok":true,"data":{"slug":"Ab9xQ2mR","domain":"test.gfw.mom","short_url":"https://test.gfw.mom/Ab9xQ2mR"},"request_id":"opaque-request-id"}
```

失败建议统一格式：

```json
{"ok":false,"error":{"code":"SLUG_CONFLICT","message":"短码已被占用"},"request_id":"opaque-request-id"}
```

`message` 可本地化，客户端依赖稳定 `code`。不回传输入 URL/认证头，不将内部异常作为响应。

| HTTP | 稳定错误码草案 | 语义与重试 |
| --- | --- | --- |
| 400 | `INVALID_JSON`, `INVALID_FIELD`, `UNKNOWN_FIELD`, `INVALID_URL`, `INVALID_DOMAIN`, `INVALID_SLUG` | 修正请求；管理字段拒绝 |
| 401 | `TOKEN_REQUIRED`, `TOKEN_INVALID` | 缺失、无效、撤销或过期；统一无效响应，不泄漏是否存在 |
| 403 | `DOMAIN_FORBIDDEN`, `HOST_FORBIDDEN`, `TARGET_FORBIDDEN` | 域名未授权/禁用、错误主机或禁止目标；不重试绕过 |
| 404 | `NOT_FOUND` | 未知路径，无旧接口兜底 |
| 405 | `METHOD_NOT_ALLOWED` | 已知路由非 POST，`Allow: POST` |
| 409 | `SLUG_CONFLICT`, `IDEMPOTENCY_CONFLICT` | 短码已占用或可选幂等键内容不同 |
| 413 | `BODY_TOO_LARGE`, `URL_TOO_LONG` | 缩减输入 |
| 415 | `UNSUPPORTED_MEDIA_TYPE` | 只接受 application/json |
| 429 | `RATE_LIMITED` | 携合理 `Retry-After`；按值等待，不能改 IP/Token 绕过 |
| 500 | `INTERNAL_ERROR` | 不返回内部信息；是否已提交需明确处理 |
| 503 | `TEMPORARILY_UNAVAILABLE`, `SLUG_GENERATION_EXHAUSTED` | 有限退避；无幂等性时不得假设重试不会重复创建 |

建议限制：请求体最多 16 KiB，URL UTF-8 最多 8 KiB，domain 最多 253 字节，自定义短码最多 64 ASCII 字符，拒绝重复字段和未知值；读取流时设置上限，不仅检查 Content-Length。数字待实际设计验证，不是当前已实施限制。

限流建议基于业务 Token 与域名分别设短窗口/持续速率，管理员可配置上限；避免单个客户消耗全部创建配额。具体值待容量设计，本次无压力测试；不加入应用 IP 白名单。

客户端对网络超时/5xx 有有限指数退避，但没有幂等保证时创建结果可能不确定，重发可能创建新短码。可选 `Idempotency-Key` 尚未决定：若实现，绑定业务 Token 身份、domain、完整请求（包括原 URL 和 slug）及有限保存窗口，同键同内容返回首次结果，同键不同内容 409，并处理并发原子性。它不等于同 URL 全局去重，不默认启用。

## 后续验收用例（本次不实现产品测试）

- 缺 Token、错误格式、撤销/过期/轮换 Token，部署 Token 不能成为业务身份；域名越权、未绑定/停用域名。
- 前台和 workers.dev 携正确 Token 调机器路由仍失败；转发头/Host 覆盖域名失败；未知路径、非 POST、旧接口不兜底。
- 伪造 Access 邮箱头、无签名/错 issuer/aud/过期 JWT、非法邮箱、Origin/CSRF 不通过；业务 Token 不能读管理接口。
- 有效期/启停/确认文字/统计/Token 权限注入、额外字段、数组、重复成员、超大请求和错误 Content-Type。
- 自定义短码冲突、停用短码不复用、保留路径、双重编码/点段、随机碰撞重试；并发同 slug 只允许一个写入，永不覆盖。
- 相同 URL 两次正常创建得到不同短码；默认永久、管理员到期/停用、确认页处理顺序。
- 完整 URL 含签名、重复 query、Unicode、`%2F`、`+`/`%20`、空 query、fragment；同名目标优先、新参数追加位置与编码保真；签名附加参数的明确拒绝/透传边界。
- 429/Retry-After、网络结果不确定、可选幂等键同内容/不同内容/并发/跨 Token 和域名隔离。
- 匿名前台无历史持久化，真实 Turnstile 成功/失败均正确阻断或允许；机器入口不依赖浏览器 challenge。
