# 项目执行边界

当前阶段：2026-10-05 多域名、自动任务与管理能力迭代。所有者已明确授权目标模式、业务实现、测试、修复、提交、推送、PR、CI 和符合 GitHub 规则的合并，并补充授权 agent 使用 gh / GitHub API 自行触发本项目 `workflow_dispatch`，完成初始化、测试部署、精确 Access/WAF 配置、旧 KV 只读迁移至新 D1、备份验证及必要的修复重试。初始化成果继续保留，初始化阶段的停止限制及等待用户点击的限制已结束；CF 写入仅经 Actions，生产保护继续有效。

## 版本与入口

- 现有生产代码为 `worker_updated_v3.js`，旧 Worker 为 `short-link`，KV 绑定为 `LINKS`。
- 保留三个历史 Worker、`README.md`、`CODEX_HANDOFF.md` 原文。它们描述旧系统，旧 API、密码、IP 白名单、全局 URL 去重和兼容性约束不属于新系统需求。
- 新系统确定要求见 `docs/REFACTOR_REQUIREMENTS.md`；当前 API 契约见 `docs/API_CONTRACT.md`；`docs/API_CONTRACT_DRAFT.md` 为历史设计参考；现场证据及未验证项见 `docs/INITIALIZATION_REPORT.md`。
- 新系统计划 Worker：`shortlink-new`；测试前台：`test.gfw.mom`；后台与机器 API：`link-admin.lily.lat`。实际资源以只读核验和后续授权创建结果为准。

## 资源与权限保护

- 已登录的 Cloudflare 主账号浏览器严格只读，仅可查看配置和状态；禁止在面板保存、创建、删除或执行其他写入，禁止扩大主账号 Token 权限或轮换 Token。登录成功不改变此边界。经诊断仍缺少的必要部署权限由用户补足，agent 不得代理修改主账号 Token。
- 本地 Cloudflare 只读；所有者已确认本机现有 `CLOUDFLARE_API_TOKEN` 是本项目可用的只读凭据，不重复询问来源。仅通过明确的进程映射用于固定只读核验，不自动使用部署 Token、Wrangler OAuth、Global API Key，不打印凭据或导出环境变量。Actions 部署 Secret 不下载到本地。
- 保护账户设置、旧生产及与本项目无关的已有域名、DNS、路由、Worker、D1、KV、R2、配置及数据；不得删除、重建、覆盖或修改。尤其不得改变 `gfw.mom` 现有服务指向。
- 不修改共享 Turnstile、无关 Access/身份提供方/WAF/规则/Secret，不清缓存，不执行旧生产写入或压力测试。本项目新入口的精确 WAF / Access 配置只经 Actions 的 `workflow_dispatch`；机器 API 的 CF 白名单仅允许 87.83.110.180，范围仅为 link-admin.lily.lat 精确 /api/shorten；先完成必要验收再经 Actions 收紧，不引入应用 IP 变量。
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
- 域名由后台登记，管理员本人手动绑定 Worker，再点击刷新；agent 不替管理员创建第二域名绑定。独立只读凭据须实际资格核验，GH 部署 Token 不得注入业务 Worker。
- 允许管理员对单条新系统在线映射彻底删除，替代旧永久保留绝对限制；需默认取消确认、Access/CSRF 校验，保留无目标 URL 的短码/幂等占用记录防复活。真实删除验收只使用本轮新建一次性记录，禁止批量删除历史数据。
- 自动一致性备份复用本项目独立私有 R2，保留 checkpoint；日常后台仅设置计划和查看任务。访问聚合、审计、备份保留天数 0 表示永久，间隔/限流仍必须大于 0。
- 允许经独立 Actions 整理已核实本项目 Access/WAF 的显示名称；ID、AUD、策略与相对顺序保持，内部所有权由私有 checkpoint、稳定 ref 和资源 ID 互证。普通部署不得恢复 UUID 名称、全 IP 放行或覆盖所有者后续名单。
- 前台真实视口至少 390px，结合 360px/430px/桌面及明暗/自动；后台仅要求桌面验收。事件和任务时间默认 Asia/Singapore（UTC+8）；历史按 UTC 日期聚合的访问趋势必须如实标注，不能伪造重分桶。
- 当前迭代目标在 docs/REFACTOR_REQUIREMENTS.md；旧初始化报告继续作为历史证据。提交中的文档描述产品和运维约定，任务报告、测试结果及 Codex 工作记录只放 PR 或忽略的本地交付文件。
