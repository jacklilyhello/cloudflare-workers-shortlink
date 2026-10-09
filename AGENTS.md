# 项目执行边界

## 当前文档与历史归档约定（2026-10-09）

- 根 `README.md` 已转为当前正式系统说明，允许持续维护；原 README 完整保存在 `archive/legacy-workers/README.v3.md`。下文“README 原文冻结”“重写留待后续”属于历史约定，以本节为准。
- 三个根目录 `worker_updated*.js` 原文件继续逐字节保留，并在 `archive/legacy-workers/` 保存相同内容的冻结副本。它们仅供历史查阅，不是当前部署入口。
- 安全检查继续对照原基线校验旧 README 归档、三个旧 JS 的原文件与归档副本，以及原 `CODEX_HANDOFF.md` 和 `LICENSE`；不取消历史原文保护。
- 当前应用入口为 `src/index.ts`，前端为 `ui/`。文档与归档维护不改变应用、数据库、云端资源或部署流程。

## 当前正式环境授权（2026-10-08，优先于下方历史测试阶段）

- 所有者授权本项目代码、生产 Variables、PR/CI/合并与独立手动 Actions 完成正式迁移。Cloudflare 写入只经 Actions；本地和主账号浏览器只读，不读取部署 Secret 值，不绕过平台审批。
- 正式公共域名为 gfw.mom（主）和 gfw.lat，后台为 link-admin.lily.lat。复用原 shortlink-new、D1 shortlink-new-test 原 ID/数据与 R2 shortlink-new-backups。两个 test 域名资源及记录保留，服务永久停用；workers.dev/Preview 关闭。
- 仅接管两个正式域名已核验 ID 的 Web DNS、路由和旧 Custom Domain；邮件/MX/TXT/CAA/其他业务保持。旧 short-link/KV 保留，精确停写保护覆盖它的全部入口，旧跳转读保留。
- 机器 WAF 精确 host/path 仅允许 103.118.43.47/32、45.77.252.181/32，拒绝其他 IPv4 和全部 IPv6。Access 三管理员、ID/AUD、业务 Token/域名权限/限流、Turnstile 保持；生产不接受全 IP 操作。业务 Token 由所有者手动生成。
- 停止旧新增早于末次完整扫描；沿原迁移身份恢复分页/租约，既有 18 异常及 2 未读按原指纹豁免并保留事实，新错误不可豁免。新原子备份包含末次结果后关闭 migration_enabled 与旧同步 schedule；保留迁移历史、日常备份和 Worker 维护。
- 本轮仅代码审阅、编译构建、配置/操作读回；不新增或主动执行额外业务/浏览器/移动端/OTP/压力/恢复测试，不创建短链或业务 Token。现有 CI 正常运行。README 重写后续处理，六个历史文件仍逐字节保留。

当前阶段：2026-10-07 三管理员、独立 Access 策略名称和可控迁移验收接续。所有者已明确授权目标模式、业务实现、测试、修复、提交、推送、PR、CI 和符合 GitHub 规则的合并，并补充授权 agent 使用 gh / GitHub API 自行触发本项目 `workflow_dispatch`，完成初始化、测试部署、精确 Access/WAF 配置、旧 KV 只读迁移至新 D1、备份验证及必要的修复重试。本轮允许精确机器入口临时向全部 IPv4/IPv6 放行以完成测试；该授权取代此前仅允许 87.83.110.180 的测试要求，不构成生产授权。初始化成果继续保留，初始化阶段的停止限制及等待用户点击的限制已结束；CF 写入仅经 Actions，生产保护继续有效。

## 版本与入口

- 现有生产代码为 `worker_updated_v3.js`，旧 Worker 为 `short-link`，KV 绑定为 `LINKS`。
- 保留三个历史 Worker、`README.md`、`CODEX_HANDOFF.md` 原文。它们描述旧系统，旧 API、密码、IP 白名单、全局 URL 去重和兼容性约束不属于新系统需求。
- 新系统确定要求见 `docs/REFACTOR_REQUIREMENTS.md`；当前 API 契约见 `docs/API_CONTRACT.md`；`docs/API_CONTRACT_DRAFT.md` 为历史设计参考；现场证据及未验证项见 `docs/INITIALIZATION_REPORT.md`。
- 新系统计划 Worker：`shortlink-new`；测试前台：`test.gfw.mom`；后台与机器 API：`link-admin.lily.lat`。实际资源以只读核验和后续授权创建结果为准。

## 资源与权限保护

- 已登录的 Cloudflare 主账号浏览器严格只读，仅可查看配置和状态；禁止在面板保存、创建、删除或执行其他写入，禁止扩大主账号 Token 权限或轮换 Token。登录成功不改变此边界。经诊断仍缺少的必要部署权限由用户补足，agent 不得代理修改主账号 Token。
- 本地 Cloudflare 只读；所有者已确认本机现有 `CLOUDFLARE_API_TOKEN` 是本项目可用的只读凭据，不重复询问来源。仅通过明确的进程映射用于固定只读核验，不自动使用部署 Token、Wrangler OAuth、Global API Key，不打印凭据或导出环境变量。Actions 部署 Secret 不下载到本地。
- 保护账户设置、旧生产及与本项目无关的已有域名、DNS、路由、Worker、D1、KV、R2、配置及数据；不得删除、重建、覆盖或修改。尤其不得改变 `gfw.mom` 现有服务指向。
- 不修改共享 Turnstile、无关 Access/身份提供方/WAF/规则/Secret，不清缓存，不执行旧生产写入或压力测试。本项目新入口的精确 WAF / Access 配置只经独立 Actions 的手动 `workflow_dispatch`；本轮临时全 IPv4/IPv6 测试仅匹配 `link-admin.lily.lat` 精确 `/api/shorten`，不得扩大至其他路径或服务。87.83.110.180 仅作为后续受限名单参考，不在本轮验收前自动收紧。IP 策略只由 CF Custom Rules 管理，不引入后台、D1、Token、业务代码或应用 IP 变量；管理员 Access、业务 Bearer、域名授权、字段校验、应用限流及匿名 Turnstile 保持有效。
- 主账号浏览器只读不撤销本仓库持续授权的 `workflow_dispatch`。新系统独立资源可经 Actions 创建、部署、迁移和验证，agent 可使用 gh / GitHub API 触发及按归属 checkpoint 恢复必要步骤；范围仅限已确认实际资源 ID 和本项目归属的新 Worker、D1、R2，以及 `test.gfw.mom`、`link-admin.lily.lat`。遇到已有同名资源需证明本项目归属后才可幂等更新，禁止覆盖其他资源；写入结果不明时先核验归属，不盲目重发。
- 明确允许上述 Actions 为 `link-admin.lily.lat` 精确 `/api/shorten` 添加必要的 Custom Errors 表达式例外。共享规则仅可调整已审阅目标规则的这一必要部分，其他请求的匹配行为、规则对象及相对顺序保持不变；禁止覆盖整套规则。此授权不包含账户设置、共享 Turnstile 或旧生产变更。
- 不通过故意写入验证只读上限。读取成功只证明对应读取可用；Token active 不等于所有权限通过；GH Secret 名称存在不等于值正确或权限有效。
- 预检固定官方 API 主机、预定义只读端点及固定查询；禁止携认证跨域重定向、任意 SQL、修复或自动创建功能。
- 仅直接读取明确的本项目凭据位置；不扫描用户目录寻找密钥。凭据、KV 样本、日志、响应和导出只能保存在忽略的本地路径。

## Git 与后续开发

- 先核实 origin、基线、分支、工作区和适用指令；先读脚本再执行。保护未提交内容，不使用 `reset --hard`、`git clean`、强制 checkout 或自动 stash。
- 开发流程：任务分支 → 编写 → 本地验证 → 自行修复 → 提交 / PR → CI → 符合规则后合并；普通阶段无需再次询问。
- CF 写操作只能通过 GitHub Actions，并校验账户、环境、资源 ID、目标域名和明确授权的新系统资源范围。
- 测试、生产部署必须分别使用独立的 `workflow_dispatch`；禁止 push、合并、定时自动部署。独立旧 KV 自动增量迁移已获授权，可定时执行固定源只读→已归属新 D1 的数据任务，不得触发部署。本次允许 agent 显式触发已授权的新测试环境流程，不包含生产发布或生产域名切换授权。未实际执行的项目仍记录未验证；真实 GitHub 环境审批、登录/MFA 或平台权限阻挡不能绕过，生产发布与切换需单独授权。
- `npm run check` 执行安全检查、类型检查、业务测试和构建；`npm run preflight` 只读。二者没有部署能力。历史六文件的逐字节保护继续有效。

## 本轮产品与变更授权

- 公共短码使用全局命名空间，一条逻辑映射被所有登记、真实绑定核验且启用的公共域名解析；不包含旧生产 gfw.mom、后台或无关域名。保留原始 URL，不做长链接去重。
- 域名由后台登记，管理员本人手动绑定 Worker，再点击刷新；`test.gfw.lat` 已由管理员本人绑定，仍须后台真实刷新核验后按业务状态启用。agent 不替管理员创建、转移或重绑第二域名。独立只读凭据须实际资格核验，GH 部署 Token 不得注入业务 Worker。
- 允许管理员对单条新系统在线映射彻底删除，替代旧永久保留绝对限制；需默认取消确认、Access/CSRF 校验，保留无目标 URL 的短码/幂等占用记录防复活。真实删除验收只使用本轮新建一次性记录，禁止批量删除历史数据。
- 自动一致性备份复用本项目独立私有 R2，保留 checkpoint；日常后台仅设置计划和查看任务。访问聚合、审计、备份保留天数 0 表示永久，间隔/限流仍必须大于 0。
- 允许经独立 Actions 整理已核实本项目 Access/WAF 的显示名称；ID、AUD、策略与相对顺序保持，内部所有权由私有 checkpoint、稳定 ref 和资源 ID 互证。临时全 IP 测试或后续名单收紧分别使用对应独立手动 Actions，不由正常部署改变。普通部署不得恢复 UUID 名称、自行恢复或扩大全 IP 放行、自行收紧当前测试策略，或覆盖所有者未来名单。生产仍需独立授权并通过受限名单和入口隔离门禁。
- 前台真实视口至少 390px，结合 360px/430px/桌面及明暗/自动；后台仅要求桌面验收。事件和任务时间默认 Asia/Singapore（UTC+8）；历史按 UTC 日期聚合的访问趋势必须如实标注，不能伪造重分桶。
- 当前迭代目标在 docs/REFACTOR_REQUIREMENTS.md；旧初始化报告继续作为历史证据。提交中的文档描述产品和运维约定，任务报告、测试结果及 Codex 工作记录只放 PR 或忽略的本地交付文件。


## 2026-10-07 接续调整

- 仅删除 Codex“短链真实定时迁移验收”跟进任务，不创建同类轮询。项目正常24小时自动迁移、GitHub定时工作流、Worker定时维护与R2自动备份继续保留，其他项目任务不动。
- 本轮不再要求等待后续真实schedule完成全程迁移才交付。先核对共享CF执行组无live/pending和实际计划/断点，复用已完成的真实到期扫描，否则通过migrate-legacy-auto.yml的workflow_dispatch执行到期扫描；保留10页上限和100条/页，后续沿同一未完成UUID恢复。旧KV只读，已存在映射和删除占用保护不变。手动重试与schedule退避差异如实验证；不得换数据路径、扩页、制造到期或伪造事件。定时投递稳定性／全程定时接续作为已知限制，不阻塞本轮交付。
- 本项目后台管理员仅为lilyyaloveyou@gmail.com、admin@888888.mom、moshaoli688@gmail.com，三者同权；同步本项目两条管理员Allow、Worker身份校验、部署变量、预检及测试。名单外拒绝，真实验证码由所有者本人在网页输入，不涉及CF账户成员、GH权限或业务Token权限。
- 方案A保留三个Access应用和三条独立应用策略，不合并、不改为可复用策略，Legacy标签可保留。策略可编辑名称为“短链后台管理员”“短链 API 免登录”“短链 API 子路径管理员”；应用现有中文名保留。仅名称与上述管理员邮箱可变，Policy/Application ID、AUD、owner UUID、稳定ref、动作、路径、precedence、会话及其他条件保留。
- 策略归属需由已核验policy ID、所属应用和不可覆盖私有checkpoint互证，不能删除归属检查；普通部署接受保留新中文名。变更只经已授权独立Actions，结果不明先读回核对归属和断点，不盲目重发。
