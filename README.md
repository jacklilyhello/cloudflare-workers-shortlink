# Cloudflare Workers Shortlink

基于 **Cloudflare Workers + KV** 的轻量级短链接服务，提供完整的前后端方案，包括短链接创建、后台管理、人机验证、黑名单机制及自定义错误跳转。

该项目已在生产环境中长期稳定运行。

---

## 功能特性

### 1. Cloudflare Workers + KV 持久化
- 所有短链数据均存储于 KV 中，**永久有效（无 TTL）**。
- 同一长链接自动复用同一个短链（随机后缀模式）。

### 2. 自助短链接生成
- 支持随机后缀、自定义后缀。
- 支持 Turnstile 人机验证（可选启用）。
- 支持长链接域名黑名单、后缀黑名单。

### 3. 可视化管理后台
- 后台路径可自定义（如 `/admin` 或 `/secret-admin`）。
- 支持搜索、分页、排序（按后缀 / 创建时间）。
- 一键删除短链，并同步清理索引。
- 后台无 TTL，所有短链永久保存。

### 4. 统一错误处理
- 被封禁后缀 → 跳转到自定义 **403 页面**。
- 未创建后缀 → 跳转到自定义 **404 页面**。
- 默认跳转：
  - 403 → `https://403.lily.lat/`
  - 404 → `https://404.lily.lat/`  
  可在脚本中轻松修改。

### 5. 高扩展性
- 全量逻辑集中于一个 Workers 脚本，部署极其简单。
- 所有行为均可通过 Worker 变量控制，无需修改代码。

---

## Version History（版本历史）

本仓库包含多个历史版本，方便对比不同阶段的实现逻辑。

### `worker_updated.js`（v1）
- 初代版本，包含基础短链逻辑。
- 管理后台简化，黑名单机制较弱。

### `worker_updated_v2.js`（v2）
- 重构路由结构。
- 后台增强。
- 接口返回格式调整、交互优化。

### `worker_updated_v3.js`（v3 / 最新正式版）
当前稳定使用版本，特性包括：
- 短链创建 / 去重 / 永久保存（无 TTL）
- 完整后台：搜索、分页、排序、删除
- Turnstile 验证（可启用 / 可关闭）
- 长链接域名黑名单
- 自定义后缀黑名单
- 统一 403 / 404 跳转
- UI 配置接口 `/api/get-ui-config`

此版本为 **推荐部署** 的版本。

---

## Active Version（当前使用版本）

当前推荐使用版本：  
**worker_updated_v3.js**

此版本涵盖完整逻辑，是你部署到 Cloudflare Workers 的最终版本。

---

## 运行效果预览

![UI1](https://photo.lily.lat/file/AgACAgQAAyEGAASLgSpZAAIM7mlQxiwJG0OxlGA4jLlxSAcZ3T6iAAKdC2sbon6IUrl_fHUWwtsvAQADAgADdwADNgQ.png)

![UI2](https://photo.lily.lat/file/AgACAgQAAyEGAASLgSpZAAIM8GlQxuanZefqwX6TFGtuUHj-k6fZAAKkC2sbon6IUlEhIaEeBHP4AQADAgADdwADNgQ.png)

---

## 目录结构（核心）

本项目核心逻辑集中在一个 Worker 脚本中，主要包括：

- 首页模板：短链接生成页面（表单 + 复制结果）
- 管理后台模板：带搜索、排序、分页和删除按钮的管理界面
- 请求处理逻辑：
  - `POST /`：创建短链接
  - `GET /api/get-ui-config`：前端拉取验证码配置
  - `GET <ADMIN_PATH>`：管理后台 HTML
  - `GET <ADMIN_PATH>/api/all`：后台分页列表接口
  - `GET <ADMIN_PATH>/api/delete/:key`：删除指定后缀
  - `GET /<path>`：短链重定向或 404/403 跳转

---

## Cloudflare 配置说明（简要）

### 1. KV 命名空间

在 Cloudflare Dashboard 中为 Worker 绑定一个 KV 命名空间，例如：

- 命名空间名称：`LINKS`
- 绑定变量名：`LINKS`（需与代码中保持一致）

### 2. 环境变量 / Secrets

在 Worker 的 “变量和机密” 中配置以下键值（按需）：

#### 文本变量（Text）
- `ADMIN_PATH`：后台入口路径，例如 `/admin`（可选，不配置则默认为 `/admin`）
- `CAPTCHA_ENABLED`：是否启用 Turnstile 验证，`true` / `false`
- `TURNSTILE_SITE_KEY`：Turnstile 的 site key（启用验证码时必填）
- `LONG_DOMAIN_BLACKLIST`：长链接域名黑名单，多行或逗号分隔
- `SUFFIX_BLACKLIST`：短链后缀黑名单，多行或逗号分隔

#### 机密变量（Secret）
- `TURNSTILE_SECRET_KEY`：Turnstile secret key

### 3. 自定义 403 / 404 页面域名

代码中默认将：
- 被封禁后缀跳转到：`https://403.lily.lat/`
- 未创建后缀跳转到：`https://404.lily.lat/`

如需改为自己的域名，可以在代码中相应修改这两个 URL。

---

## 使用方式

### 1. 部署 Worker
将 `worker_updated_v3.js` 上传或粘贴到 Cloudflare Workers 编辑器中。

### 2. 配置 KV 和变量
确保：
- 已绑定 `LINKS` 命名空间
- 已设置必要变量
- 如开启 Turnstile，请配置 site key 和 secret key

### 3. 访问入口
| 路径 | 功能 |
|------|------|
| `/` | 短链接创建页面 |
| `/admin`（或自定义路径） | 管理后台 |
| `/abc123` | 访问短链，自动跳转 |

后台可直接查看、搜索、删除所有短链。

---

## 主要 API

| 方法 | 路径 | 说明 |
|------|------|------|
| `POST /` | 创建短链 |
| `GET /api/get-ui-config` | 前端配置拉取 |
| `GET <ADMIN_PATH>` | 后台页面 |
| `GET <ADMIN_PATH>/api/all` | 后台列表分页 |
| `GET <ADMIN_PATH>/api/delete/:key` | 删除短链 |
| `GET /<suffix>` | 短链跳转 |

---

## 开发者说明

### 支持的黑名单格式示例

`LONG_DOMAIN_BLACKLIST` 与 `SUFFIX_BLACKLIST` 均支持 **多行** 或 **逗号分隔** 的写法。建议一行一个规则，便于维护。

#### 1) 长链接域名黑名单（LONG_DOMAIN_BLACKLIST）

示例（推荐：一行一个）：
example.com
spam.com
sub.spam.com
malware.site

示例（逗号分隔）：
example.com, spam.com, sub.spam.com, malware.site

说明：
- 建议填写 **根域名** 或 **明确的子域名**。
- 若你的 v3 脚本实现支持通配（例如 `*.example.com`），可按脚本逻辑填写；否则请显式列出子域名。

#### 2) 后缀黑名单（SUFFIX_BLACKLIST）

示例（推荐：一行一个）：
admin
login
api

示例（逗号分隔）：
admin,login,api

建议：
- 将常见敏感路径（如 `admin`、`login`、`api`、`robots.txt` 等）加入黑名单，避免与站点路由或爬虫行为冲突。
- 若你有自定义 403/404 站点，可把这些敏感后缀统一导向 403。

---

### Worker 性能与限制说明

- Workers 无冷启动问题，边缘执行延迟低，适合高频短链跳转场景。
- KV 适合 **读多写少** 的映射场景；短链跳转通常为 KV 读取 + 302/301 返回。
- KV 写入存在最终一致性特性：在极少数情况下，刚创建的短链可能需要短暂时间在所有边缘可读（通常很快）。
- 若未来需要强一致或更复杂的统计分析，可考虑 D1 / Durable Objects（按业务需要选择）。

---

### 安全建议（推荐）

- 将后台入口路径设置为不易猜测的路径，例如：
  - `ADMIN_PATH=/secret-admin-9x8y`
- 面向公开服务，建议开启 Turnstile。
- 定期维护黑名单：
  - 封禁高风险域名
  - 封禁敏感后缀、恶意探测常用后缀
- 配置 403/404 自定义页面时，建议页面中不要泄露内部信息（如 KV 变量名、路由结构等）。

---

## 当前推荐版本

**worker_updated_v3.js**

该版本为生产环境使用的正式版本，具备最佳的稳定性与易用性。

