# 新系统正式环境运维

本文件适用于复用原资源的 `shortlink-new`。正式公共域名为 `gfw.mom` 与 `gfw.lat`，主域名为 `gfw.mom`；后台继续为 `link-admin.lily.lat`，机器接口唯一入口为 `POST https://link-admin.lily.lat/api/shorten`。数据库继续使用 `shortlink-new-test` 的原 ID 和数据，私有 R2 继续使用 `shortlink-new-backups`。名称中的 test 不表示数据库应重建或重命名。

`APP_ENV=production` 与 `PUBLIC_HOSTNAME=gfw.mom` 同时用于请求和 scheduled 校验。Cloudflare Custom Domain 的 service `environment=production` 表示 Worker 默认服务环境，与业务 `APP_ENV` 是不同字段。`test.gfw.mom`、`test.gfw.lat` 保留 DNS、CF 绑定和数据库来源记录，但停止创建与跳转，运行时拒绝重新启用；普通部署不能把它们恢复为公共服务。新 Worker 的 workers.dev 和 Preview 都关闭，运行时也拒绝 workers.dev。

## 执行边界

Cloudflare 写操作只通过默认分支的 GitHub Actions `workflow_dispatch`。本地 Cloudflare 凭据和已登录主账号浏览器只读；不下载部署 Secrets、不使用 OAuth 或 Global API Key、不扩大 Token 权限、不绕过真实环境审批和分支保护。账号、原 D1/R2、旧 Worker `short-link` / LINKS KV、迁移历史及无关域名和资源继续受保护。CI 正常执行仓库既有检查，部署不会由 push、merge 或 schedule 自动触发。

正式切换允许对已确认 ID 的两个根域 Web DNS、旧路由和旧 Custom Domain 关联执行必要变更。MX、TXT、CAA、邮件和其他用途记录不属于 Web 入口，不能为了绑定检查而删除。旧 Worker 保留代码及 LINKS 绑定，在切换前安装经过摘要核验的只读入口保护，拒绝旧新增与其他写方法；识别它所有 Custom Domain、路由与 workers.dev 入口，关闭 workers.dev / Preview，保留旧 KV 和数据。

## 归属与可恢复阶段

私有 R2 的 `delivery/ownership.json` 保存 owner UUID、原 D1 ID、R2 名称、Worker、Access/规则/域名 ID 和阶段。D1 `delivery_ownership`、Worker 的 `RESOURCE_OWNER_ID` / DB / BACKUPS 绑定与该记录互证。旧测试 manifest 可升级当前阶段，但历史 test 标签、安全原像和摘要继续作为当时事实保留，不全局替换。

生产切换私有 checkpoint 保存变更前基础设施、准确资源 ID、旧 Worker 来源摘要与只读版本摘要、分阶段结果。执行顺序为：

1. 核对 main、开放 PR、共享 CF 执行组和实际资源归属，保存切换前记录。
2. 通过独立安全维护 Actions 将精确机器 API 收紧到两个正式 IPv4，并读回规则。
3. 停止旧入口新增，读回旧 Worker 来源与绑定、workers.dev / Preview 的实际状态。
4. 在旧迁移身份与原数据库中完成末次增量扫描，分批沿同一 run / cursor 恢复。
5. 使用现有一致性备份机制产生包含末次增量的新快照，核对完成状态、对象与摘要。
6. 写当前设置 `migration_enabled=0` 并停用旧 KV 自动同步调度，保留 Worker 维护 Cron 和日常 R2 备份。
7. 部署原 Worker 的生产配置，接管 `gfw.mom` / `gfw.lat`；停用两个测试域名业务，关闭新 workers.dev / Preview。
8. 读回最终配置、归属、安全规则、迁移及备份结果，并核对无关 DNS、路由与域名关联保持。

写入结果不明时先读回 checkpoint 与现场，不盲目重发。恢复仅针对本次记录过的变更，不回滚业务数据，不恢复全 IP 放开。不能确认归属、真实权限不足或平台审批阻挡时只暂停受影响步骤。

## 手动工作流

正式操作使用 `shortlink-production` GitHub Environment、固定账户与 `gfw.mom` / `gfw.lat` / `lily.lat` 三个 Zone。环境 Variables 按 [CONFIGURATION.md](CONFIGURATION.md) 核对；部署 Secret 只传入云端执行步骤，不进入本地或业务 Worker。测试 bootstrap、测试部署和测试安全初始化入口不再具备覆盖正式 Worker 的能力，生产安全维护禁止 `allow-test-all-ip`。

- [部署及切换](https://github.com/jacklilyhello/cloudflare-workers-shortlink/actions/workflows/deploy-production.yml)：原资源升级，按已记录阶段恢复，不重新 bootstrap。
- [安全维护](https://github.com/jacklilyhello/cloudflare-workers-shortlink/actions/workflows/security-maintenance.yml)：保留规则与 Access 身份，精确名单转换和必要名称维护。
- [部署凭据只读诊断](https://github.com/jacklilyhello/cloudflare-workers-shortlink/actions/workflows/credential-diagnostic.yml)：固定官方 GET，覆盖三个 Zone、域名/DNS/路由、旧 LINKS 绑定和归属记录，输出脱敏结果；读取成功不证明写权限。
- [生产基础设施只读诊断](https://github.com/jacklilyhello/cloudflare-workers-shortlink/actions/workflows/runtime-diagnostic.yml)：确认文本 `diagnose shortlink-new production infrastructure read only`，使用 `--infra-only`。只读 owner、D1 固定 SELECT 与可选精确后台路径安全事件；不请求 Siteverify 或后台业务 API，不创建 Token 或链接。
- [独立域名只读凭据资格](https://github.com/jacklilyhello/cloudflare-workers-shortlink/actions/workflows/domain-read-credential.yml)：确认文本 `qualify shortlink-new domain reader read only`。验证候选 active、自身只读 policy、固定账户/Zone 范围、Worker owner / DB / R2 与已记录 Custom Domain。切换阶段核验保留的测试主域，完成正式域名绑定后核验两个正式域名。
- [精确机器 API Custom Errors 维护](https://github.com/jacklilyhello/cloudflare-workers-shortlink/actions/workflows/security-api-errors.yml)：仅调整已审阅规则对精确主机/路径的例外，保留原像与规则其他行为，不替换整套规则。

Secret 名称存在、Token active 或列表读取成功都不能代替具体端点权限和归属核验。独立只读凭据未通过资格时不注入 Worker；部署 Token 永远不能成为 `DOMAIN_BINDING_READ_TOKEN`。真实业务 Token 由所有者手动在后台生成，仓库、Actions 和迁移工具不代建默认、测试或生产业务 Token。

## Access 与 WAF

后台维持三名同权管理员：`lilyyaloveyou@gmail.com`、`admin@888888.mom`、`moshaoli688@gmail.com`。保留三个 Access 应用、独立策略 ID、AUD、owner UUID、稳定 ref、动作、路径、precedence、会话与身份提供方。Worker 独立验证 Access JWT 签名、issuer、AUD、有效期、type 与准确邮箱，写操作仍要求 Origin 和 JWT 绑定的 CSRF。

精确机器 Access 应用继续免交互登录；`/api/shorten/*` 及其他后台路径继续要求管理员身份。WAF 的路径保护阻断以 `/api/shorten` 开始但不完全相等的路径。机器网络名单只存在于 lily.lat Custom Rules，精确匹配 `http.host eq "link-admin.lily.lat"` 与 `http.request.uri.path eq "/api/shorten"`：

- 名单内集合仅为 `{103.118.43.47/32 45.77.252.181/32}`，名单外 IPv4 和全部 IPv6 Block。
- 前置互补 Block 与 API Skip 使用相同集合，Block 保持在可能跳过它的 Skip 之前。
- 保留 deny / skip / path guard 的 ID、ref、名称、顺序、Skip action_parameters 与无关规则原对象/相对顺序；历史 restricted checkpoint 不能代替当前表达式读回。
- 普通部署不改写当前名单，不恢复全 IP 放开。Access、Custom Errors 精确例外、业务 Bearer、域名权限、字段校验、POST 和应用限流继续有效。

不关闭全站 Bot Fight、WAF、Access 或 Turnstile 来解决某个入口问题。共享 Turnstile Widget 在切换前读回两个正式 hostname 范围；必要补齐保留其他共享业务域名与原 Site Key / Secret，不轮换共享 Secret。业务 Siteverify 仍精确校验 hostname 与 `action=create`。

## 末次增量与已知豁免

末次扫描必须在旧入口停止新增后开始或续跑。扫描沿原 legacy namespace / migration domain 身份，不能先改主域名导致旧 run 无法恢复；每批最多 10 页，每页最多 100 key。保留租约、cursor、run UUID、计数和有限重试，不制造到期时间、不清有效锁、不扩页、不换数据路径。`partial`、`paused`、`locked`、`not_due` 和绿色工作流都不等于末次扫描完成。

已存在全局映射只比对，不覆盖 URL、管理员状态、到期或确认配置；`deleted_links` 的短码及幂等占用继续阻止复活。原始 `links.domain` 保留创建或导入来源，正式域名共享同一全局短码，不全表改写来源域名。

所有者已接受既有 18 条异常和 2 条未完整读取记录，按末次迁移前保存的观察指纹识别豁免，原始记录、reason 与异常事实继续保留。不能把它们标为 fully_verified，也不能把本次新增错误加入豁免。末次结果须检查实际 run state、cursor、计数、租约释放、新增异常和完整性标记。完成后更新原数据库当前设置，停用自动同步调度，历史 SQL migration 和迁移历史不改写。

## 备份、维护与保留

生产切换需要包含末次增量的新备份，已有全局索引或旧升级备份不能代替它。复用一致性 D1 staging snapshot 与私有 R2 分片上传；实际完成后记录 backup job ID、对象标识、snapshot 与 object digest。`sha256-chunk-manifest-v1` 是有序块摘要 manifest 的 SHA-256，不称为全对象普通 SHA-256。保留 checkpoint 和租约，不删除业务数据或快照来跳过阻挡；本次不要求恢复演练。

Worker 每 10 分钟 Cron 继续推进备份与维护。迁移自动同步关闭不关闭备份，日常后台设置计划并查看状态。统计、审计、备份保留天数 0 为永久；间隔与限流必须大于 0。失败不更新上次成功时间。事件与任务默认完整 Asia/Singapore（UTC+8）；历史访问趋势仍按 UTC 日桶展示并注明，不能伪造重分桶。

## 结果证据与文档

配置/操作读回、代码已提交、工作流绿色和跳过执行是不同证据。交付按实际云端阶段、资源状态、run / cursor / lease 和 backup 对象说明完成与未完成事项；不能把部署代码完成写成切换完成。本轮不额外执行单元、集成、端到端、浏览器、移动端、OTP、业务 API、压力或恢复测试；仓库既有 CI 继续执行，不删测试或降低保护。

当前系统概览见 [README.md](../README.md)，新 API 以 [API_CONTRACT.md](API_CONTRACT.md)、`src/index.ts` 与 `src/core.ts` 的当前实现为准。原 README 完整保存在 [README.v3.md](../archive/legacy-workers/README.v3.md)；三个旧 Worker 同时保留根目录原文件和归档副本。旧 README 归档、旧 Worker、`CODEX_HANDOFF.md` 与 LICENSE 的字节保护继续保留，来源见[归档说明](../archive/legacy-workers/README.md)。历史初始化报告及私有安全快照保留原事实。
