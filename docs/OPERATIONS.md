# 新系统运维

本文件适用于 `shortlink-new`。旧 `short-link`、旧 KV 和现有生产入口继续独立运行。新测试入口是 `https://test.gfw.mom`，管理员和机器入口是 `https://link-admin.lily.lat`；实际 workers.dev 地址由账户子域只读结果生成并在部署摘要给出。

## workflow_dispatch Actions

所有写入流程只接受默认分支上的 `workflow_dispatch`、固定账户/两个 Zone/新 Worker/两个测试入口和对应确认文本。所有者已授权 agent 使用 gh / GitHub API 显式触发本项目初始化、测试部署、精确 Access/WAF 接入、旧 KV 只读迁移至新 D1、备份验证及必要修复重试，无需等待用户点击。CF 写入仍由 Actions 使用 GH 部署 Secret 执行，不从本机执行部署、资源创建、安全配置或真实迁移脚本，不下载部署凭据。CI 可以自动运行，但没有 CF Secrets 或部署步骤。部署 Secret 仅传给最后一个 apply 步骤，依赖安装、本地检查及构建步骤不持有 CF/Turnstile Secret。真实 GitHub 环境审批、登录/MFA 和平台权限阻挡不能绕过；本次补充授权不包含生产发布或域名切换。

| 工作流 | 确认文本 | 作用 |
| --- | --- | --- |
| [Diagnose deployment credential (read only)](https://github.com/jacklilyhello/cloudflare-workers-shortlink/actions/workflows/credential-diagnostic.yml) | `verify shortlink-new deployment credential read only` | 在 Actions 内用部署 Secret 对固定端点逐项 GET；仅输出脱敏结果，不写 CF、不读取旧 KV 值、不执行 SQL。Token 验证失败不阻止其他固定读取诊断，但不成为部署认证通过；资源缺失和读取失败分别记录，读取成功不证明写权限 |
| [Diagnose test runtime (read only)](https://github.com/jacklilyhello/cloudflare-workers-shortlink/actions/workflows/runtime-diagnostic.yml) | `diagnose shortlink-new test runtime read only` | 核验已有资源归属，用固定 SELECT 读取计数及最近迁移的恢复 ID；检查精确机器接口的状态/内容类型，用无效挑战检查现有 Siteverify Secret；可选读取精确后台路径最近 15 分钟的安全事件。不创建业务 Token、不写数据库或 CF 配置 |
| [Initialize new test system](https://github.com/jacklilyhello/cloudflare-workers-shortlink/actions/workflows/bootstrap-test.yml) | `initialize shortlink-new test only` | 首次独立 D1/R2、精确 Access/WAF 接入、数据库迁移、新 Worker 和两个 Custom Domains；可恢复有可靠归属 checkpoint 的未完成步骤 |
| [Deploy new test system](https://github.com/jacklilyhello/cloudflare-workers-shortlink/actions/workflows/deploy-test.yml) | `deploy shortlink-new test only` | 核验已记录的新资源归属、Access 和安全规则，应用新 D1 SQL 迁移并更新新 Worker；不修改 WAF/Access/DNS/Custom Domains |
| [Configure test API security](https://github.com/jacklilyhello/cloudflare-workers-shortlink/actions/workflows/security-test.yml) | `configure shortlink-new test API security` | 在已创建且归属核实的新资源上完成/复核首次安全接入；已存在的本项目规则仅复核，不把管理员收紧的 IP 条件恢复为全放行 |
| [Apply reviewed exact API error exception](https://github.com/jacklilyhello/cloudflare-workers-shortlink/actions/workflows/security-api-errors.yml) | `operation=apply`：`apply reviewed exact shortlink-new API error exception`；`operation=rollback`：`restore reviewed exact shortlink-new API error exception` | 仅调整已审阅的 lily.lat Custom Error 规则，让精确机器入口保留应用错误响应；保存私有原像 checkpoint，支持核对后的恢复或回退，不修改 Access/WAF/IP 策略 |
| [Migrate legacy KV to new test D1](https://github.com/jacklilyhello/cloudflare-workers-shortlink/actions/workflows/migrate-legacy.yml) | `read old KV and migrate owned test D1 only` | 只读已核实的旧 LINKS namespace，写独立新 D1；不改旧 KV、不切流量；`resume_run` 空值启动新全量增量重扫，非空恢复未完成 run；`max_pages` 每页 100 key |
| [Production release gate](https://github.com/jacklilyhello/cloudflare-workers-shortlink/actions/workflows/deploy-production.yml) | `release shortlink-new without production domain cutover` | 默认拒绝：必须另获生产授权并显式设置 `PRODUCTION_RELEASE_AUTHORIZED=true`；还必须存在互补 Block 和真实受限 IP 条件。只更新当前已归属的新 Worker/测试资源，不包含生产域名接入或切换 |

首次通常只需要显式运行初始化流程。触发前先核对当前 main、已有运行记录、固定目标和现场资源归属/冲突；已有进行中的运行先跟踪，不能重复初始化。流程包含首次安全接入，无需预先在面板手工建立规则/IP List/Access 例外。成功后先做无需管理员身份的基础验收，再由真实管理员创建临时业务 Token，继续成功和拒绝路径的完整验收；不通过 Actions 或数据库植入默认业务 Token。工作流相互使用同一 concurrency group，禁止取消进行中的写入；失败后先读取结果和所有权 checkpoint，再对已确认归属的步骤恢复或重试，不能因新授权盲目重发结果不明的写入。

12 个已有 Variables 继续按 `CONFIGURATION.md` 的固定基线核对。需要的 Secrets 是 `CLOUDFLARE_API_TOKEN`（仅 Actions）、`TURNSTILE_SECRET_KEY`（复用共享 Widget）；业务 Token 不存 GH。`CF_ANALYTICS_READ_TOKEN` 保留，本实现统计使用 D1 聚合，不把部署凭据作为统计或业务身份。Secret 名称存在不能证明值/权限：创建、部署、安全配置和迁移工作流在写入前验证 Account Token active、账户/Zone 归属、旧 LINKS 绑定，并检查实际操作结果。两个只读诊断分别按表中限定范围执行；运行时诊断不读取旧 Worker/KV。自身 Token policy 能读取时才审阅；policy GET 的明确权限拒绝会记录未验证，其他错误阻止执行。各资源真实写端点的成功才证明对应操作可用，不故意写旧资源测试权限上限。

遇到权限或认证失败时，先查看固定 `endpoint_category`、HTTP 状态和 CF 数字错误码；诊断不输出路径、真实 KV key、对象内容、URL、Token 或原始错误正文。用独立只读工作流集中检查，区分凭据身份、资源范围、端点权限、产品兼容和新资源尚未创建，避免逐项盲目重试初始化。Account Token [自身 policy GET](https://developers.cloudflare.com/api/resources/accounts/subresources/tokens/methods/get/) 可因未授予 Account API Tokens Read 而不可读，不要求为此增加 Tokens Write；关键 Token verify 和账户/Zone 归属仍必须通过。[Bot Management 配置读取](https://developers.cloudflare.com/api/resources/bot_management/methods/get/) 接受对应 Read 或 Write 权限，[官方 Account Token 兼容表](https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/)中的产品限制也必须结合实际失败核实，不能以权限失败为由跳过安全核对或关闭共享防护。

运行时诊断不携带浏览器 Cookie 或 Access JWT。固定 Siteverify 请求使用无效挑战，仅能确认 Secret 未被服务端拒绝，不能替代真实 Turnstile 成功验收；可选安全事件读取失败会标为未验证，不阻止其他必要检查。输出不含原始响应、URL、旧 KV key、IP、Token 或验证码；迁移恢复 ID 可用于同一未完成 run 的 `resume_run`。

Zone Rulesets 列表还包含可供部署的账户级规则定义；[Zone 详情接口只用于 `kind=zone` 的阶段入口](https://developers.cloudflare.com/ruleset-engine/rulesets-api/view/)。预检与诊断先校验列表元数据，再读取实际 Zone 入口，并核对详情的 ID、kind 和 phase。托管规则定义出现在列表中不代表对应防护已经启用；API Skip 的 phase 取自已部署入口的启用规则及 Bot 配置。实际入口读取失败仍阻止初始化，诊断只输出固定规则类型、阶段和安全错误摘要。

所需能力涉及 Workers Scripts/D1/R2 编辑、Workers Routes/DNS 相关读取、旧 KV 只读、Access Apps and Policies/组织与 IdP 读取，以及 lily.lat Zone WAF 编辑和相关安全设置读取。安全检查还读取账户入口 Rulesets，无法读取或有无法排除影响的账户级防护时会停止，不申请或使用 Global API Key/OAuth，不关闭共享防护。不要为读取 Token 自身 policy 增加管理写权限。

## 所有权与失败恢复

新数据库名称 `shortlink-new-test`、私有备份桶 `shortlink-new-backups`。R2 的 `delivery/ownership.json` 记录仓库、账户、环境、随机 owner UUID、创建返回的 D1 ID、Access/规则/Custom Domain ID 和进度；D1 `delivery_ownership` 与 Worker `RESOURCE_OWNER_ID`、DB/BACKUPS 绑定互证。新资源创建后立即保存 checkpoint。配置只在忽略的 `.local/wrangler.deploy.json` 生成；没有旧 KV 绑定，没有 `gfw.mom` 路由，静态资产必须经过 Worker 的主机/身份边界。

同名资源没有可靠标识、已有域名/DNS/广域路由冲突或 Access 广域覆盖时拒绝覆盖。不能依据“名字一样”“同一个账户”或 Token 范围认领资源。CF 写入网络异常不会自动重发；先读取所有权/进度，再恢复明确归属的步骤。R2 首次创建但所有权对象写入结果不明，或 D1 创建返回 ID 未能可靠留存时，需要人工核对该次 Actions 与 CF 现场，保持停止；不要删桶/删数据库/重建来使检查通过。

安全变更前信息保存在私有 R2 `delivery/<owner UUID>/security-before.json`，本项目结果和无关规则摘要在 `security-after.json`。不上传公开 Actions artifact，不打印原始响应、KV key/目标 URL、Token 或 SQL。若需本地留存，只存忽略的 `.local/`、`exports/` 等路径并限制文件权限。

## Access 与当前测试 IP 策略

后台根应用保护整个 `link-admin.lily.lat`，只允许 `lilyyaloveyou@gmail.com`、`admin@888888.mom`，只使用现有 OTP IdP，不修改共享 IdP。Worker 独立验证 JWT 签名、issuer、真实 AUD、有效期和邮箱，管理员写接口还验证 Origin/CSRF。

机器应用的 domain 是 `link-admin.lily.lat/api/shorten`，唯一 Bypass 策略是 everyone。Access 按路径继承、更具体应用优先，因此另建 `link-admin.lily.lat/api/shorten/*` 管理员保护应用。无星号路径不能单凭配置外观声称完全精确：WAF 再阻断所有以 `/api/shorten` 开头而不完全相等的路径，Worker 只接受精确主机、精确 `/api/shorten` 和 POST。相似路径、子路径、编码/归一化变体需要实测；任何业务 Token 都不能取得管理权限。

WAF 仅在 lily.lat 的 Custom Rules 入口中插入独立规则，不 PUT 整个现有规则列表：

- `shortlink_new_api_path_guard`：精确主机，`starts_with(path,"/api/shorten")` 且 `path != "/api/shorten"`，Block；放在 API Skip 前面。
- `shortlink_new_api_skip`：仅 `(http.host eq "link-admin.lily.lat" and http.request.uri.path eq "/api/shorten")`，测试期暂时允许全部 IPv4/IPv6。跳过该规则之后的 Custom Rules；根据读取的实际启用防护加入 SBFM、Managed WAF、Rate Limiting phases 和必要的产品例外，记录具体 action_parameters，并在普通部署中严格比对。

上述例外不覆盖 `/api/*`、整个后台域、通配子域或 lily.lat 其他服务。原有无关规则对象和相对顺序在变更后再次比对。普通 Bot Fight Mode 无法由 Custom Rules 精确 Skip；如果发现其启用，流程拒绝继续并报告套餐/防护限制，绝不关闭全域 Bot Fight Mode。无法排除广域 Access/账户 Custom Rules 等冲突也先停止。测试全 IP 可达始终保留 Bearer 鉴权、字段校验、域名授权、应用限流和匿名 Turnstile；它不是正式 IP 白名单验收。

## 精确机器 API 错误响应例外

Custom Error 规则可能把应用的 JSON 错误和状态码改成统一 HTML 页面。`security-api-errors.yml` 只允许默认分支上的测试 `workflow_dispatch`，按表中 `operation` 和对应确认文本执行。脚本先证明账户、目的 D1、Worker 绑定及本项目 Access/WAF 归属，再核对固定的 `http_custom_errors` Zone 入口、规则 ID 和已审阅原始指纹；只将该条原表达式整体加括号，并追加 `and not (http.host eq "link-admin.lily.lat" and http.request.uri.path eq "/api/shorten")`。完整 action、asset、状态码、启用状态、ref 和说明保留，不传 position，不替换整组规则，也不修改其他入口或任何防护产品。

首次保存原像或需要 PATCH 规则前，先执行官方 [PATCH dry-run](https://developers.cloudflare.com/api/resources/rulesets/subresources/rules/methods/edit/) 的 `dry_run=true`，要求成功返回 `result: null`，并重新读取确认内容及版本均未变化。此阶段的 `Custom Errors Write` 编辑能力须由固定 dry-run 的实际结果核验，Token active、读取成功或其他 WAF 写入成功均不能代替；权限拒绝或异常结果不会降级成直接 PATCH。首次原像保存于私有 R2 `delivery/<owner UUID>/custom-error-api-checkpoint.json`，以项目归属、完整原始入口和 SHA-256 绑定，读回核验后才登记 `security.custom_error_api` 的 planned 状态。随后再次核验归属和入口指纹，只 PATCH 已审阅规则；写后核对整组内容与顺序，再记录 applied。原始 checkpoint 始终保留，不上传公开 artifact。

网络中断或结果不明时不自动重发。先核对运行摘要、私有 checkpoint 和实际入口，再用同一 operation 显式触发恢复；若目标状态已存在，只补齐记录，不再次 PATCH。`operation=rollback` 使用同一 checkpoint 恢复该条原始表达式并记录 rolled_back；需要实际更改时同样先执行 dry-run，再读回核对。当前入口必须仍与已保存原像或预期状态相符；规则、参数或无关内容发生漂移时停止，不覆盖面板调整，不自动回退。普通测试部署不执行这项 Custom Error PATCH，也不把已应用例外或已回退状态改回；实际机器 JSON 状态与路径隔离仍须部署后验收。

## 以后由所有者维护 CF 白名单

在 CF 面板维护 IP/CIDR，不复制到应用、D1、业务 Token 或 GitHub。可以在账户中创建专用 IP List `shortlink_api_allowlist`，也可以直接在规则中使用受限 IP 集合；测试初始化不依赖该 List。

先准备并核对名单，再在 Skip 之前添加启用的 Block `shortlink_new_api_deny_outside_allowlist`，description 保留 `shortlink-new:<owner UUID>:` 前缀：

```text
(http.host eq "link-admin.lily.lat" and http.request.uri.path eq "/api/shorten") and not (ip.src in $shortlink_api_allowlist)
```

随后把现有 Skip 的 expression 改为下式，保留 ref、用途前缀和原有 Skip action_parameters：

```text
(http.host eq "link-admin.lily.lat" and http.request.uri.path eq "/api/shorten") and (ip.src in $shortlink_api_allowlist)
```

只给 Skip 添加 IP 条件并不能拒绝名单外访问，必须保留前面的互补 Block。管理员浏览器路径不匹配这两条规则，因此不受机器名单限制。生产护栏读取真实 List 的完整内容，拒绝空/未核实列表、`0.0.0.0/0`、`::/0` 和多个 CIDR 拼合覆盖整个地址族；只记录数量/结果，不导出名单。生产确认还要求互补 Block 在 Skip 前、主机/路径均精确及引用相同名单。Block 必须先于任何可能跳过当前自定义规则集或该 Block 的启用 Skip，否则生产门禁拒绝发布，不自动重排无关规则。普通部署与重复首次安全核验都不会自动重置面板的收紧配置。

每次变更后分别从名单内外验证 IPv4/IPv6：名单内无/错 Token 得到程序 JSON 401，有效授权 Token 创建成功；名单外 CF 拒绝。同时验证两个管理员 OTP 登录、管理接口和 lily.lat 其他服务。名单内容/调用原 URL 不要贴到公开 issue/Actions 日志。正式名单、实际规则命中和名单内外双栈结果未完成时，不能宣称生产发布条件满足。

## 使用、统计与备份

匿名创建只有 URL、可选短码、Turnstile；无匿名历史。后台统一管理链接、域名和业务 Token。业务 Token 在后台创建，仅首次显示明文，D1 保存不可逆摘要，可撤销、到期和限制域名；不要把 Actions 部署 Token 用作 Bearer 业务身份。机器仅 `POST https://link-admin.lily.lat/api/shorten`，字段和调用示例见 `API_CONTRACT.md`。

同一个完整 URL 每次正常创建独立映射；链接默认永久。停用/到期保留短码与映射。高级有效期、确认页/文案、目标 query 策略和设置只能管理员修改。签名 URL 的原始 query 编码保持；旧迁移默认 `preserve`，附加 query 不重写目标，后台可按需要改变策略。

访问统计异步写 D1 聚合，趋势、国家、来源主机和设备是近似事件计数，可能包括机器人/重复请求，不能当作独立用户数。默认统计 90 天、审计 365 天、备份间隔 24 小时及备份保留 30 天，可后台调整。Worker 每 10 分钟 Cron 推进备份/维护工作；清理周期仅作用于统计、审计、备份，不清理永久映射。R2 备份使用一致的 D1 staging snapshot 和分片 NDJSON；后台下载仍需 Access 管理身份。没有新增自动 GitHub 部署计划，也不以长 Worker sleep 实现周期任务。

备份推进使用可续租的独占租约，只有当前持有者才能提交 D1 进度、标记完成并清理该任务的快照。已经发往 R2 的请求不能由租约取消；迟到请求可能令分片 ETag 失效，需要重新上传。恢复时先核验已完成对象的版本、快照标识及 UTF-8 大小；未完成的分片会保留原始快照并重新上传，失去租约的旧调用不能重复累计记录或清除快照。不要通过删除备份任务或 staging 数据修复上传中断。

超过保留期的备份从后台列表和下载入口移除，D1 保留不含备份正文的内部清理标记。维护任务按上次检查时间轮转，每次最多检查 20 个已过期的精确对象键，持续删除可能由迟到上传重建的文件；删除失败时保留标记，供后续维护重试。此清理仅限本项目的 `backups/<任务 ID>.ndjson`，不清理正在上传的快照或其他 R2 前缀。

## 旧 KV 迁移

真实迁移仅 Actions 的 `workflow_dispatch`，agent 可按本次授权显式触发。脚本先验证旧 `short-link` 的 `LINKS` 确实指向已登记 namespace，再验证目的 D1 归属和测试域名绑定。它只对源 KV 发 GET，对目的 D1 使用参数化 SQL；不会调用旧后台（旧 GET 管理接口可能删数据），不会迁移旧业务 Token/SYS_CONFIG 设置。

识别短码→完整 HTTP/HTTPS URL；128 位 hex key 只有在值指向另一短码，且该短码的 URL 的 SHA-512 等于 key 时才当反向索引跳过。128 位 key 值本身是真 URL 时保留为映射。危险/保留短码、无法安全解析的 URL、未知记录、索引关系不符均报告待审阅，不假装已完整迁移。安全 ASCII 历史短码可保留至 KV key 上限 512 字节；新建短码仍最多 64 字符。无合法 createdAt 的历史行使用 NULL，不伪造导入时间。

目的库 `UNIQUE(domain,slug)`、INSERT ON CONFLICT DO NOTHING 和 URL 精确读回避免覆盖任何已存在映射。旧 key/值只存不可逆指纹作为迁移检查；链接列表可查看导入短码，迁移页显示最近 run 的状态、结果和原因汇总（包含 unknown/conflicts）；公开日志仅数量和摘要。`legacy_migration_runs/items` 记录 cursor、每个已处理观察、状态和排序后的 SHA-256 摘要；页中断可重播而不重复导入/计数。已存在 URL 相同为 unchanged，URL 不同为 conflict；既存时间原样保留并如实标记。

单条 KV 值的读取上限为 16 KiB，迁移允许符合原有安全校验的 HTTP/HTTPS URL 至 16 KiB，按 UTF-8 字节计数。前台、机器 API 和后台新建仍限制为 8 KiB，请求体仍限制为 16 KiB；短码与路由限制不变。迁移保留原始 URL、query 编码和 fragment，默认 `preserve` 忽略短链附加 query；长历史链接仍可调整启停、到期和确认页，无需重新提交或截短 URL。

跳转中的非 ASCII 字符会按现有逻辑编码成 ASCII `Location`，不重排原 query。Cloudflare 的[响应头总上限为 128 KB，URL 上限为 16 KB](https://developers.cloudflare.com/workers/platform/limits/)；迁移保真不保证所有客户端或目标服务器都接受长 URL，Unicode 编码后可能更长。例如 [Node HTTP 客户端默认响应头预算为 16 KiB](https://nodejs.org/api/http.html#httpmaxheadersize)，边界长度的 `Location` 加上其他头就可能超出该预算。

成功响应超过读取上限时记为 unknown，保留同一 run 的恢复进度；其检查标记与真实内容指纹分开，报告明确列出 `unverified_value_fingerprints`，不能当作值内容已经校验。同一 run 的标记不能识别两次不同的超大值，后续全量重扫必须重新观察；包含这些记录的结果不标为完整迁移。鉴权、限流、网络、协议或错误响应仍终止该次执行，不能转成可忽略的 unknown。直接及反向索引读取都排除 `SYS_CONFIG_` 配置记录。

每次完成后再次启动无 resume_run 的全量增量重扫，捕捉旧系统继续新增或修改的数据。更改分类兼容范围后也需开启新一轮全量扫描，已完成 run 的历史 unknown 与摘要不改写。游标扫描不是一致性快照；摘要验证本轮观察，不证明旧 KV 从此不再变化。出现 conflict/unknown 或达到页数上限时工作流退出 2 并保留 checkpoint/报告，保持旧业务运行；必须处理差异后再次验证，正式冻结/增量截止和生产切换另行授权。

## 部署后的实际验收与回退

Actions 成功只是代码/端点写入证据。还必须在真实浏览器与机器客户端核验：匿名 Turnstile 成功/失败、复制与直接跳转、后台两邮箱 OTP、非允许邮箱拒绝、管理员管理/批量/Token/统计/备份、无/错/撤销 Token API、域名越权、额外管理字段、并发短码冲突/幂等、到期/停用/确认页、完整 URL 和相似/编码路径、公共域及 workers.dev 后台/API拒绝。WAF Skip 与 Access Bypass 分别验证程序请求没有挑战/登录页，其他 lily.lat 服务配置与命中范围保持原样。未实际部署或未登录完成的项目均标未验证；需要用户完成真实 OTP、MFA 或平台审批时集中说明，不能伪造登录与验收结果。

应用回退使用此前已验证 commit，仍只经测试部署 `workflow_dispatch`，agent 可在已授权修复范围内显式触发并保留 D1/R2/旧 KV；不要回滚成绑定旧库/旧 Worker 的配置。不要自动撤销 SQL 或删除永久映射。安全回退仅核对 private before/after 记录和本项目 ID 后逐条恢复本项目变化，保留无关规则原对象/顺序、OTP IdP、共享 Turnstile；禁止覆盖整个规则集或用全站关防护解决故障。当前工具不执行删除/自动回滚，复杂恢复或生产变更先明确范围和授权。

官方依据：[Access 路径继承](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/app-paths/)、[Custom Rules Skip 能力及 BFP 限制](https://developers.cloudflare.com/waf/custom-rules/skip/options/)、[逐条插入规则与位置](https://developers.cloudflare.com/ruleset-engine/rulesets-api/add-rule/)、[Rulesets 游标和 per_page 上限](https://developers.cloudflare.com/api/resources/rulesets/methods/list/)、[D1 创建](https://developers.cloudflare.com/api/resources/d1/subresources/database/methods/create/)、[R2 对象 API](https://developers.cloudflare.com/api/resources/r2/subresources/buckets/subresources/objects/)、[Worker Custom Domain API](https://developers.cloudflare.com/api/resources/workers/subresources/domains/methods/update/)。
