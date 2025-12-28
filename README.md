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

## 运行效果预览

![UI1](https://photo.lily.lat/file/AgACAgQAAyEGAASLgSpZAAIM7mlQxiwJG0OxlGA4jLlxSAcZ3T6iAAKdC2sbon6IUrl_fHUWwtsvAQADAgADdwADNgQ.png)

![UI2](https://photo.lily.lat/file/AgACAgQAAyEGAASLgSpZAAIM8GlQxuanZefqwX6TFGtuUHj-k6fZAAKkC2sbon6IUlEhIaEeBHP4AQADAgADdwADNgQ.png)

---

## 目录结构

本项目核心逻辑集中在一个 Worker 文件中（v3），主要模块如下：

- 首页表单模板
- 管理后台模板（搜索、分页、删除、排序）
- 路由处理（POST/GET）
  - `POST /`：创建短链
  - `GET /api/get-ui-config`：获取前端配置
  - `GET <ADMIN_PATH>`：后台入口
  - `GET <ADMIN_PATH>/api/all`：后台分页接口
  - `GET <ADMIN_PATH>/api/delete/:key`：删除短链
  - `GET /<path>`：短链重定向（含 403/404）

---

## 部署说明

### 1. 创建并绑定 KV 命名空间
在 Cloudflare Dashboard → Workers → KV → Create：

- KV 命名空间：`LINKS`
- Worker 绑定变量名：`LINKS`  
（与脚本中的变量名保持一致）

---

### 2. 配置 Worker 环境变量

在 Workers → Settings → Variables：

#### 文本变量（Text）
| 变量名 | 说明 |
|-------|------|
| `ADMIN_PATH` | 后台入口路径，例如 `/admin`（默认 `/admin`） |
| `CAPTCHA_ENABLED` | 是否启用 Turnstile 验证：`true` / `false` |
| `TURNSTILE_SITE_KEY` | Turnstile site key |
| `LONG_DOMAIN_BLACKLIST` | 长链接域名黑名单（多行 / 逗号分隔） |
| `SUFFIX_BLACKLIST` | 自定义后缀黑名单（多行 / 逗号分隔） |

#### 机密变量（Secret）
| 变量名 | 说明 |
|-------|------|
| `TURNSTILE_SECRET_KEY` | Turnstile secret key |

---

### 3. 自定义 403 / 404 跳转

在主 Worker 脚本中可调整以下常量：

const ERROR_403_REDIRECT = "https://403.example.com/";
const ERROR_404_REDIRECT = "https://404.example.com/";

## 使用方式

### 1. 部署 Worker
将 `worker_updated_v3.js` 上传或粘贴到 Cloudflare Workers 编辑器中。

### 2. 配置 KV 和变量
确保：
- 已绑定 `LINKS` 命名空间
- 已设置必要变量
- 如开启 Turnstile，请配置 site key 和 secret key

### 3. 使用方式
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
