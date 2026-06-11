# Codex 交接说明：`worker_updated_v3.js` 最新状态

本文件用于给后续 Codex / 维护者快速同步当前仓库状态。当前应以 `worker_updated_v3.js` 为唯一推荐部署版本；`README.md` 已同步到该版本的行为。

## 当前基线

- 推荐部署脚本：`worker_updated_v3.js`。
- 数据存储：Cloudflare KV 绑定名必须为 `LINKS`。
- 后台鉴权模型：后台页面只输入管理密码；后台列表 / 删除 API 使用 `Authorization: <ADMIN_PASS>` 精确匹配。
- 当前不使用 `ADMIN_USER`，后续不要强行新增用户名鉴权，否则会破坏已有后台 UI 与管理 API 兼容性。
- 所有短链永久保存，不设置 TTL。
- 随机后缀模式会写入 SHA-512 去重索引；自定义后缀不会写入去重索引。

## 当前已实现能力

### 1. 后台路径与 API 路径可配置

- `ADMIN_PATH` 控制后台入口路径，未配置时默认 `/admin`。
- `ADMIN_API_BASE` 控制后台 API base，未配置时默认 `<ADMIN_PATH>/api`。
- 后台 HTML 会注入最终计算出的 `adminApiBase`，因此自定义 `ADMIN_API_BASE` 后前端会请求新路径。
- Worker 同时兼容旧版 `<ADMIN_PATH>/api/all` 与 `<ADMIN_PATH>/api/delete/:key`，避免已有调用方立刻失效。

### 2. 后台列表、搜索、排序与删除

- 后台列表 API 支持 `page`、`size`、`sort`、`q` 参数。
- `size` 当前限制为 1 到 10。
- `sort=time` 按 `createdAt` 倒序；其他值默认按后缀名称排序。
- 搜索会匹配短链后缀与长链接内容。
- 后台列表索引使用约 4 秒内存缓存；新增或删除短链后会调用缓存失效逻辑。
- 删除短链时，如果能读取到长链接，会同步删除 `后缀 -> 长链接` 与 `SHA-512(长链接) -> 后缀` 两类 KV 记录。

### 3. 普通短链创建与跳转

- `POST /` 或任意全局 `POST` 当前会进入普通短链创建逻辑，因此更具体的 POST 路由必须放在它之前。
- 请求体字段：`url` 为必需；`key` 为可选自定义后缀；`cf_token` 为 Turnstile token。
- 仅支持 `http:` 与 `https:` 长链接。
- 随机后缀仍使用 6 位 `Math.random().toString(36).substring(2, 8)`。
- 同一长链接在随机后缀模式下会复用已有短链，除非已有后缀当前命中后缀黑名单。
- 访问黑名单后缀会 302 到 `https://403.lily.lat/` 并保留 query string。
- KV 命中时会 302 到目标长链接并追加当前请求 query string。
- 未命中后缀会 302 到 `https://404.lily.lat/` 并保留 query string。

### 4. Turnstile 与 UI 配置

- `GET /api/get-ui-config` 返回 `{ captchaEnabled, siteKey }`。
- `CAPTCHA_ENABLED` 支持 `true`、`1`、`yes`、`y`、`on` 作为启用值。
- `TURNSTILE_SITE_KEY` 供前端加载 Turnstile。
- `TURNSTILE_SECRET_KEY` 用于服务端调用 Cloudflare siteverify。
- 当前服务端是宽松校验：开启验证码且请求携带 `cf_token` 时会尝试校验，但不会因为校验异常或 `vo.success` 为假直接阻断短链创建。

### 5. 黑名单配置

- 长链接域名黑名单主变量：`LONG_DOMAIN_BLACKLIST`。
- 长链接域名黑名单兼容变量：`DOMAIN_BLACKLIST`、`LONG_URL_DOMAIN_BLACKLIST`。
- 短链后缀黑名单主变量：`SUFFIX_BLACKLIST`。
- 短链后缀黑名单兼容变量：`SHORT_SUFFIX_BLACKLIST`、`SHORT_LINK_SUFFIX_BLACKLIST`。
- 黑名单支持多行或逗号分隔；每行 `#` 后内容会被当作注释丢弃。
- 域名规则会移除协议、路径、端口、前导 `.` 与 `*.`，并按根域 / 子域包含逻辑匹配。
- 后缀规则会移除前导 `/` 并转为小写；创建自定义后缀和访问后缀时都会检查。

### 6. 内部 DWZLA 代理 API

- 路由：`POST /api/v1/link`。
- 该路由必须位于全局普通 `POST` 创建逻辑之前。
- IP 白名单：读取 `CF-Connecting-IP`，必须命中 `API_ALLOWED_IPS`。
- Token 鉴权：必须使用 `Authorization: Bearer <INTERNAL_API_TOKEN>`。
- 请求体只接受 `{ "url": "https://example.com/long-url" }`。
- 仅支持 `http:` 与 `https:` URL。
- 上游 base：`DWZLA_API_BASE`，未配置时默认 `https://dwzhila.com/api/v1`，并会去除末尾 `/`。
- 上游 token：`DWZLA_API_TOKEN`，必须作为 Worker Secret 配置。
- 上游请求固定发送到 `${DWZLA_API_BASE}/link`，body 为 `{ "type": "direct", "url": "<用户传入的url>" }`。
- 成功响应会标准化为 `{ "status": "success", "short_url": "..." }`。
- 以下字段会被用于提取短链：`data.link.short_url`、`data.short_url`、`data.data.short_url`、`data.data.link.short_url`。
- 鉴权或 IP 不通过统一返回 `403 { "status": "error", "message": "Forbidden" }`。
- URL 缺失、JSON 解析失败或 URL 非法统一返回 `400 { "status": "error", "message": "Invalid url" }`。
- `DWZLA_API_TOKEN` 缺失、上游非 2xx、fetch 异常、上游非 JSON、找不到 `short_url` 时统一返回 `502 { "status": "error", "message": "Upstream request failed" }`。

## Cloudflare 变量 / Secret 清单

### 必需

1. `ADMIN_PASS`：后台管理 API 鉴权，格式为 `Authorization: <ADMIN_PASS>`。
2. `INTERNAL_API_TOKEN`：内部 DWZLA 代理 API 鉴权，格式为 `Authorization: Bearer <INTERNAL_API_TOKEN>`。
3. `DWZLA_API_TOKEN`：Worker 调用 DWZLA 上游 API 的 Bearer token；必须作为 Worker Secret 配置。
4. `API_ALLOWED_IPS`：内部 DWZLA 代理 API 的公网出口 IP 白名单，英文逗号或多行分隔。

### 可选

1. `ADMIN_PATH`：后台入口路径，默认 `/admin`。
2. `ADMIN_API_BASE`：后台 API base，默认 `<ADMIN_PATH>/api`。
3. `DWZLA_API_BASE`：DWZLA API base，默认 `https://dwzhila.com/api/v1`。
4. `CAPTCHA_ENABLED`：Turnstile 开关。
5. `TURNSTILE_SITE_KEY`：Turnstile site key。
6. `TURNSTILE_SECRET_KEY`：Turnstile secret key，建议作为 Worker Secret。
7. `LONG_DOMAIN_BLACKLIST` / `DOMAIN_BLACKLIST` / `LONG_URL_DOMAIN_BLACKLIST`：长链接域名黑名单。
8. `SUFFIX_BLACKLIST` / `SHORT_SUFFIX_BLACKLIST` / `SHORT_LINK_SUFFIX_BLACKLIST`：短链后缀黑名单。

## 当前主要路由顺序

`handleRequest(request)` 当前主要路由顺序如下：

1. 后台页面：`adminBase` 或 `adminBase + "/"`。
2. 后台列表 API：`adminApiBase + "/all"`，并兼容 `legacyAdminApiBase + "/all"`。
3. 后台删除 API：`adminApiBase + "/delete/"`，并兼容 `legacyAdminApiBase + "/delete/"`。
4. 内部 DWZLA 代理：`POST /api/v1/link`。
5. UI 配置 API：`GET /api/get-ui-config`。
6. 全局普通短链创建：`if (request.method === "POST")`。
7. 首页返回。
8. 黑名单后缀跳转 403。
9. KV 命中短链跳转。
10. 未命中后缀跳转 404。

## 重要兼容性提醒

- 不要把 `POST /api/v1/link` 移到全局普通 `POST` 创建逻辑之后。
- 不要把内部接口鉴权改成后台 `Authorization: <ADMIN_PASS>` 模型。
- 不要让内部接口透传 DWZLA 完整原始响应。
- 不要向 DWZLA 上游转发 alias 或自定义后缀。
- 不要引入 `ADMIN_USER`。
- 不要把真实 token、真实密码、真实生产 IP 写入仓库。
- 当前 403 / 404 跳转地址仍在脚本中硬编码；此前明确暂不环境变量化。
- 当前 `DWZLA_API_BASE` 保留默认上游地址；不要无故移除默认值。

## 建议检查命令

只修改文档时建议运行：

```bash
git diff --check
```

修改 `worker_updated_v3.js` 后建议至少运行：

```bash
node --check worker_updated_v3.js
git diff --check
rg -n "lilyadmin888|INTERNAL_CONFIG|admin_pass" worker_updated_v3.js || true
```

如涉及安全配置，也建议额外扫描是否误写真实敏感值。
