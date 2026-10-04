# 新系统需求与版本边界

状态：2026-10-04 所有者已授权正式开发、有效测试、修复、提交、PR、CI 和符合规则的合并。本文定义业务要求；Cloudflare 写入仍只由用户手动 Actions，生产域名切换仍需单独授权。

## 已确定

### 架构与交付

应用运行、托管、数据和统计均使用 Cloudflare；代码继续使用同一 GitHub 仓库。新 Worker `shortlink-new` 与旧 Worker `short-link` 并存，新 D1 独立建立；保留旧 Worker、KV 及账户内全部已有资源。测试前台为 `test.gfw.mom`，还需使用核实后的新 Worker 自身 `workers.dev` 地址；后台和机器 API 为 `link-admin.lily.lat`。

本地 CF 只读，后续写入只走 GitHub Actions。写脚本必须校验账户、环境、资源标识和域名，拒绝触及未授权资源。测试和生产部署分别使用用户手动触发的 `workflow_dispatch`；禁止 push、合并 main 或定时自动部署。生产切换需单独明确授权，不属于初始化或默认测试开发范围。

### 匿名前台

匿名免登录，无注册、用户体系或匿名用户历史。生成结果仅在当前操作展示，不用 Cookie、localStorage、IndexedDB 或服务端匿名账户保存历史。保留简洁的 URL 输入、可选自定义短码、验证码、生成和复制体验；输入直接展示，不复杂折叠。

保留玻璃效果，参考苹果官网 Liquid Glass，兼顾文本清晰度、移动端和减少动态效果偏好。前台保持直接输入，不增加匿名账户、历史找回或高级配置入口。

公开匿名创建需 Turnstile、严格输入校验及必要防滥用。复用已有 Widget，不创建新 Widget、不轮换 Secret、不改共享 hostname。

### 后台与权限

后台独立位于 `link-admin.lily.lat`，Cloudflare Access 邮箱 OTP 仅允许 `lilyyaloveyou@gmail.com`、`admin@888888.mom`。不建立本地用户名/密码系统。后台管理链接、域名、业务 Token、有效期、确认页、错误文案、统计、导出、备份和审计；新增高级功能只允许管理员设置。

管理员内部接口另设受保护路径。Worker 自身校验 Access JWT 的签名、issuer、audience、有效期和邮箱，并处理 Origin/CSRF；不得相信客户端邮箱头或业务 Token 的管理员身份。前台域名和 `workers.dev` 禁止暴露后台或机器 API；请求主机由 Worker 独立校验。

程序 API 仅有创建能力，详见 [API 契约](API_CONTRACT.md)。不保留旧接口、旧业务 Token、旧字段或响应兼容，不依赖 DWZLA。应用不实现 IP 白名单，不读取 `API_ALLOWED_CIDRS`/`API_ALLOWED_IPS`，不增加每 Token IP 限制。首次精确 WAF / Access 接入由本项目用户手动 Actions 配置；测试期仅允许后台精确 `/api/shorten` 全 IPv4 / IPv6。正式名单由所有者在 CF Custom Rules 面板维护；普通部署只能核验，不能把已收紧规则恢复为全放行。业务 Bearer 鉴权始终独立生效。

### 链接生命周期与页面

- 默认永久；同一完整长链接每次正常创建独立短码，不做全局去重。
- 映射永久保留；过期或停用显示停用页面，不物理删除、不复用短码。管理员可调整到期时间和停用状态。
- 默认直接跳转；仅管理员可给单条链接启用确认页并填写文字。先检查停用/到期，再决定确认页。
- 内置简洁 403、404、停用及其他应用错误页；后台可配置文案。CF 边缘拦截页面由 CF 配置独立管理。
- 合法 HTTP/HTTPS 目标需完整保留 query、编码及 fragment；附加短链 query 合并时同名目标参数优先。签名 URL 的字节保真边界和拒绝改写策略需明确验证。
- 安全随机短码，数据库唯一约束与冲突重试，不覆盖旧映射。自定义短码占用返回冲突，拒绝保留路径和危险编码。

### 存储、统计和备份

D1 存链接、业务 Token 不可逆摘要、域名设置、审计、迁移记录等。管理员统计可包括来源、地区、设备与趋势；R2 用于备份。链接永久保留不意味着原始访问日志永久保留。

## 实现设计

- 采用 D1 异步日聚合，记录日期、国家、设备类别和来源 hostname，明确为近似请求事件数；不保存原始 IP、User-Agent 或来源路径。以 [Sink 官方仓库](https://github.com/miantiao-me/Sink) 和 CF 后台为功能参考，没有复制或依赖 Sink 源码。
- 匿名创建、机器创建、管理员接口分别限定主机、路径、方法和字段；Vite 构建静态页面，由 Worker 在主机与身份检查后提供。
- 资源配置记录实际创建返回的标识，通过私有 R2 checkpoint、D1 所有权和 Worker 绑定互证；部署脚本将旧资源设为保护对象，不能凭 Token 范围推断业务授权。
- 机器创建支持显式幂等键，限定 Token、域名和请求内容，D1 唯一约束保护并发；同键同内容重放返回既有结果，不做全局 URL 去重。

## 迁移方案边界

后续只读旧 KV，写新 D1，保留短码。实测前的代码结构证据：`worker_updated_v3.js` 使用短码→URL 字符串、SHA-512 的 128 位十六进制 key→短码字符串，短码 metadata 中可有 `createdAt`（epoch 毫秒）；列表还过滤 `SYS_CONFIG_`。不能将所有长度 128 的 key 自动当索引，必须结合格式、值和关联关系校验；未知或系统 key 单独审阅，历史缺 metadata 不伪造创建时间。

迁移需冲突清单、进度、可重复执行/断点恢复、内容校验和审计。旧业务仍可能写入，切换前增量补齐并再次校验；一次读取不构成一致性快照。正式切换的冻结/增量截止方案另定。不调用旧后台读取数据：其 GET 列表可删除缺失项，GET 删除接口本身会改数据。

## 默认策略与真实环境待验收项

- 统计默认保留 90 天、审计 365 天、备份每 24 小时及保留 30 天，后台可调整。Worker 每 10 分钟 Cron 推进快照/分片和保留期清理，清理不删除链接映射。R2 一致性备份以 D1 单事务 staging snapshot 为基础。
- 新 D1 计划名称 `shortlink-new-test`，私有桶 `shortlink-new-backups`；真实资源 ID、Access 应用/AUD 和创建归属在用户手动初始化后记录返回值并核验，不预填占位 ID。当前不使用 Analytics Engine。
- UI、统计字段、API 数字限制、限流、幂等和签名 query 策略见当前实现、`API_CONTRACT.md` 与 `OPERATIONS.md`。本地验证不能替代真实 Access OTP、Turnstile、WAF 命中、部署和 KV 迁移验收。
- 生产域名接入、迁移增量截止和切换计划均需单独授权。测试临时全 IP 策略不代表正式白名单或生产发布条件通过。

## 旧资料适用范围

`README.md`、`CODEX_HANDOFF.md` 与三个 Worker 保留原文，仅用于旧系统参考。现场 `main` 基线 `4eb246fb41d5f15fd8262cfda84cbe930fa37b3c` 的 `/api/v1/link` 已通过 `handleInternalApiLink` 直接写 KV（约 1312–1379 行）；README/旧交接仍称 DWZLA 代理，属于旧说明漂移，不作为新实现要求。旧密码、IP 白名单、宽松验证码、随机 `Math.random()` 短码、URL 去重、物理删除及 query 拼接行为不自动继承。本次不修复旧生产系统。
