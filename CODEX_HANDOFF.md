# Codex 交接说明：Worker 环境变量与安全配置准备

本文档用于让下一次 Codex 对话快速理解当前仓库中 `worker_updated_v3.js` 已完成的配置迁移、PR 修改、兼容性约束与后续注意事项。

## 当前基线

- 当前主要文件：`worker_updated_v3.js`
- 当前后台鉴权模型：后台页面只输入管理密码，后台 API 使用 `Authorization: <ADMIN_PASS>`。
- 当前版本不使用 `ADMIN_USER`，也不应该强行新增用户名鉴权，否则会破坏已有后台 UI 与管理 API 兼容性。
- 本仓库当前阶段的目标是逐步把关键安全配置与后续 API 所需配置接入 Cloudflare Worker 环境变量 / Worker Secret。

## 已完成的 PR / 修改摘要

### PR #1：移除硬编码后台密码并迁移到 `ADMIN_PASS`

已完成事项：

1. 移除了 `worker_updated_v3.js` 顶部真实硬编码后台密码。
2. 后台密码改为通过 Cloudflare Worker Secret / 环境变量 `ADMIN_PASS` 配置。
3. 新增 `isAdminAuthorized()` 辅助函数。
4. 后台列表 API 与后台删除 API 均改为校验 `ADMIN_PASS`。
5. 缺失或错误时统一返回非敏感的 `401 Unauthorized`。
6. 保持后台鉴权兼容：仍然是 `Authorization` header 与 `ADMIN_PASS` 精确匹配。
7. 没有引入 `ADMIN_USER`。

相关约束：

- 后续不要重复迁移 `ADMIN_PASS`。
- 后续不要把后台鉴权改成用户名 + 密码模式。
- 后续不要在代码、注释或 README 中写入真实后台密码。

### 后续 PR：支持后台路径与后台 API 路径环境变量

已完成事项：

1. `ADMIN_PATH` 用于控制后台入口路径。
2. `ADMIN_API_BASE` 用于控制后台 API base path。
3. `ADMIN_API_BASE` 未配置时默认回退到 `ADMIN_PATH + "/api"`，保持旧行为兼容。
4. 后台 HTML 模板中注入最终计算出的 `adminApiBase`，避免配置 `ADMIN_API_BASE` 后前端仍请求旧路径。
5. 后台列表 API 保留旧路径兼容：`{adminBase}/api/all`。
6. 后台删除 API 保留旧路径兼容：`{adminBase}/api/delete/{key}`。

相关约束：

- 后续修改后台 API 路径时，必须同时保证前端脚本使用最终 `adminApiBase`。
- 未配置 `ADMIN_API_BASE` 时必须保持默认行为不变。
- 不要破坏已打开旧后台页面对 legacy API path 的兼容。

### 后续 PR：准备内部 API 与 DWZLA 代理所需环境变量

已完成或已存在的变量读取逻辑：

1. `INTERNAL_API_TOKEN`
   - Worker Secret。
   - 后续内部 API 使用 `Authorization: Bearer <token>` 鉴权。
   - 代码中只能出现变量名和通用格式说明，不能写真实 token。

2. `API_ALLOWED_IPS`
   - 文本环境变量。
   - 格式示例：`1.2.3.4,5.6.7.8`。
   - 当前 `parseAllowedIps()` 已复用 `splitEnvList()`，因此支持英文逗号分隔，也兼容换行与 `#` 注释剥离。

3. `DWZLA_API_BASE`
   - 文本环境变量，非敏感。
   - 未配置时默认使用 `https://dwzhila.com/api/v1`。
   - 当前通过 `normalizeUrlBase(raw, fallback)` 规范化，会 trim 并去除末尾多余 `/`，避免后续拼接出现双斜杠。

4. `DWZLA_API_TOKEN`
   - Worker Secret。
   - 后续调用 DWZLA 上游 API 时使用。
   - 不能在代码、注释或文档中写入真实 token。

相关约束：

- 不允许写死任何真实 token、真实密码、真实 IP。
- 如果后续新增或调整内部 API，应继续使用已有变量读取逻辑，不要另建硬编码配置。
- 如需检查 IP 白名单，应使用 `CF-Connecting-IP` 请求头读取 Cloudflare 转发的客户端 IP。

### 最新一次 Codex 修改：规范化 `DWZLA_API_BASE` 并复用环境列表解析

最新一次修改曾包含以下代码层面变化：

1. 将 `parseAllowedIps(raw)` 从手动 `split(",")` 改为直接调用已有 `splitEnvList(raw)`。
2. 新增 `normalizeUrlBase(raw, fallback)`：
   - 如果 `raw` 是非空字符串则使用 `raw.trim()`。
   - 否则使用 `fallback`。
   - 最终通过 `.replace(/\/+$/, "")` 去掉末尾 `/`。
3. 将 `dwzlaApiBase` 初始化改为通过 `normalizeUrlBase()` 处理：
   - `DWZLA_API_BASE` 有值时使用环境变量值。
   - 未配置时使用 `defaultDwzlaApiBase`。
   - 统一去除末尾多余 `/`。

## 当前主要路由顺序

`worker_updated_v3.js` 的 `handleRequest(request)` 当前主要路由顺序如下：

1. 后台页面：`adminBase` 或 `adminBase + "/"`。
2. 后台列表 API：`adminApiBase + "/all"`，并兼容 `legacyAdminApiBase + "/all"`。
3. 后台删除 API：`adminApiBase + "/delete/"`，并兼容 `legacyAdminApiBase + "/delete/"`。
4. `POST /api/v1/link` 相关逻辑如果存在或后续继续调整，必须位于全局 POST 创建短链逻辑之前。
5. UI 配置 API：`/api/get-ui-config`。
6. 全局普通短链创建：`if (request.method === "POST")`。
7. 首页返回与短链跳转。
8. 黑名单后缀跳转 403。
9. KV 命中短链跳转。
10. 未命中跳转 404。

## 重要兼容性提醒

### 为什么专用 POST API 必须放在全局 POST 之前

现有普通短链创建逻辑使用全局条件：

```js
if (request.method === "POST") {
  // 普通短链创建
}
```

该条件不限制路径。因此任何更具体的 POST 路由，例如 `POST /api/v1/link`，都必须放在它之前。否则请求会被普通短链创建逻辑提前吞掉，导致：

1. 专用 API 鉴权不会执行。
2. IP 白名单不会执行。
3. DWZLA 上游代理逻辑不会执行。
4. 请求体可能被错误解析为普通短链创建请求。

### 当前不要处理的可选项

以下事项此前已明确暂不处理：

1. 不把 403 / 404 跳转地址环境变量化。
2. 不移除 `DWZLA_API_BASE` 的默认上游地址。
3. 不引入 `ADMIN_USER`。
4. 不重复迁移 `ADMIN_PASS`。

## 后续开发建议

如果下一阶段要继续实现或调整内部 `POST /api/v1/link`，建议遵循：

1. 使用 `INTERNAL_API_TOKEN` 做 Bearer token 鉴权。
2. 使用 `API_ALLOWED_IPS` 做 IP 白名单校验。
3. 使用 `DWZLA_API_BASE` 与 `DWZLA_API_TOKEN` 调用上游 DWZLA API。
4. 保持 `DWZLA_API_BASE` 通过 `normalizeUrlBase()` 去除末尾 `/`。
5. 将专用 POST 路由放在全局 `if (request.method === "POST")` 之前。
6. 不修改后台现有 `Authorization: <ADMIN_PASS>` 鉴权模型。
7. 不新增真实 token、真实密码、真实 IP 到仓库。

## 建议检查命令

每次修改 `worker_updated_v3.js` 后建议运行：

```bash
node --check worker_updated_v3.js
git diff --check
rg -n "lilyadmin888|INTERNAL_CONFIG|admin_pass" worker_updated_v3.js || true
```

如涉及安全配置，也建议额外扫描是否误写真实敏感值。
