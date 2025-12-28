# Cloudflare Workers Shortlink

基于 **Cloudflare Workers + KV** 的轻量级短链接服务，支持：

- 自助生成短链接（可选自定义后缀），短链永久有效；
- 可选接入 Cloudflare Turnstile 人机验证，防止滥用；
- 带搜索、分页、排序功能的可视化管理后台，可查看长链接、创建时间并一键删除；
- 支持长链接域名黑名单、自定义后缀黑名单；
- 未生成的后缀、被封禁的后缀统一跳转到自定义 404 / 403 页面。


![image](https://photo.lily.lat/file/AgACAgQAAyEGAASLgSpZAAIM7mlQxiwJG0OxlGA4jLlxSAcZ3T6iAAKdC2sbon6IUrl_fHUWwtsvAQADAgADdwADNgQ.png)

![image](https://photo.lily.lat/file/AgACAgQAAyEGAASLgSpZAAIM8GlQxuanZefqwX6TFGtuUHj-k6fZAAKkC2sbon6IUlEhIaEeBHP4AQADAgADdwADNgQ.png)

## 功能特性

- ⚙️ **Cloudflare Workers + KV 持久化**
  - 使用 KV 存储短链映射关系，所有短链默认永久有效（不设置 TTL）。
- 🧾 **去重短链**
  - 同一个长链接自动复用同一个短链（仅随机后缀模式），避免重复生成。
- 🔍 **后台管理面板**
  - 后台路径可通过环境变量配置（例如 `/admin` 或 `/secret-admin`）。
  - 支持按后缀 / 创建时间排序，支持关键字搜索（可按后缀和长链接内容搜索）。
  - 删除短链时会同步清理内部哈希索引。
- 🔐 **人机验证（可选）**
  - 通过 Turnstile site key / secret key 控制是否启用验证码。
  - 开关及 key 完全由环境变量控制，无需改代码。
- 🚫 **黑名单机制**
  - 可配置长链接域名黑名单：例如拦截某些敏感或高风险域名及其所有子域名。
  - 可配置短链后缀黑名单：例如禁止 `xjp`、`hjt` 等特殊后缀。
- 🧭 **统一错误跳转**
  - 访问被封禁后缀时跳转到指定的 403 页面域名。
  - 访问不存在的后缀时跳转到指定的 404 页面域名。

## 目录结构（核心）

本项目核心逻辑集中在一个 Worker 脚本中，主要包括：

- 首页模板：短链接生成页面（表单 + 复制结果）；
- 管理后台模板：带搜索、排序、分页和删除按钮的管理界面；
- 请求处理逻辑：
  - `POST /`：创建短链接；
  - `GET /api/get-ui-config`：前端拉取验证码配置；
  - `GET <ADMIN_PATH>`：管理后台 HTML；
  - `GET <ADMIN_PATH>/api/all`：后台分页列表接口；
  - `GET <ADMIN_PATH>/api/delete/:key`：删除指定后缀；
  - `GET /<path>`：短链重定向或 404/403 跳转。  [oai_citation:0‡worker_updated_v3.js](sediment://file_0000000037247208a3289a306cc28d6c)

## Cloudflare 配置说明（简要）

### 1. KV 命名空间

在 Cloudflare Dashboard 中为 Worker 绑定一个 KV 命名空间，例如：

- 命名空间名称：`LINKS`
- 绑定变量名：`LINKS`（需与代码中保持一致）

### 2. 环境变量 / Secrets

在 Worker 的 “变量和机密” 中配置以下键值（按需）：

- 文本变量：
  - `ADMIN_PATH`：后台入口路径，例如 `/admin`（可选，不配置则默认为 `/admin`）。
  - `CAPTCHA_ENABLED`：是否启用 Turnstile 验证，`true` / `false`。
  - `TURNSTILE_SITE_KEY`：Turnstile 的 site key（启用验证码时必填）。
  - `LONG_DOMAIN_BLACKLIST`：长链接域名黑名单，多行或逗号分隔。
  - `SUFFIX_BLACKLIST`：短链后缀黑名单，多行或逗号分隔。
- 机密变量：
  - `TURNSTILE_SECRET_KEY`：Turnstile secret key。

### 3. 自定义 403 / 404 页面域名

代码中默认将：

- 被封禁后缀跳转到：`https://403.lily.lat/`
- 未创建后缀跳转到：`https://404.lily.lat/`

如需改为自己的域名，可以在代码中相应修改这两个 URL。

## 使用方式（概览）

1. 将本仓库代码部署到 Cloudflare Workers，并绑定 KV 命名空间 `LINKS`。
2. 在 **变量和机密** 中配置好后台路径、验证码开关、黑名单等参数。
3. 访问根路径 `/` 即可打开短链接生成页面。
4. 访问 `ADMIN_PATH`（例如 `/admin`）进入管理后台，输入管理密码后，即可查看和管理所有短链接。

