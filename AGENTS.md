# 项目执行边界

当前阶段：2026-10-04 正式开发与新测试环境验收。所有者已明确授权目标模式、业务实现、测试、修复、提交、推送、PR、CI 和符合 GitHub 规则的合并，并补充授权 agent 使用 gh / GitHub API 自行触发本项目 `workflow_dispatch`，完成初始化、测试部署、精确 Access/WAF 配置、旧 KV 只读迁移至新 D1、备份验证及必要的修复重试。初始化成果继续保留，初始化阶段的停止限制及等待用户点击的限制已结束；CF 写入仅经 Actions，生产保护继续有效。

## 版本与入口

- 现有生产代码为 `worker_updated_v3.js`，旧 Worker 为 `short-link`，KV 绑定为 `LINKS`。
- 保留三个历史 Worker、`README.md`、`CODEX_HANDOFF.md` 原文。它们描述旧系统，旧 API、密码、IP 白名单、全局 URL 去重和兼容性约束不属于新系统需求。
- 新系统确定要求见 `docs/REFACTOR_REQUIREMENTS.md`；当前 API 契约见 `docs/API_CONTRACT.md`；`docs/API_CONTRACT_DRAFT.md` 为历史设计参考；现场证据及未验证项见 `docs/INITIALIZATION_REPORT.md`。
- 新系统计划 Worker：`shortlink-new`；测试前台：`test.gfw.mom`；后台与机器 API：`link-admin.lily.lat`。实际资源以只读核验和后续授权创建结果为准。

## 资源与权限保护

- 本地 Cloudflare 只读；所有者已确认本机现有 `CLOUDFLARE_API_TOKEN` 是本项目可用的只读凭据，不重复询问来源。仅通过明确的进程映射用于固定只读核验，不自动使用部署 Token、Wrangler OAuth、Global API Key，不打印凭据或导出环境变量。Actions 部署 Secret 不下载到本地。
- 保护账户中所有已有域名、DNS、路由、Worker、D1、KV、R2、生产配置及数据；不得删除、重建、覆盖或修改。尤其不得改变 `gfw.mom` 现有服务指向。
- 不修改共享 Turnstile、无关 Access/身份提供方/WAF/规则/Secret，不清缓存，不执行旧生产写入或压力测试。本项目新入口的精确 WAF / Access 配置只经 Actions 的 `workflow_dispatch`；机器 API 测试期全 IP 授权仅限 link-admin.lily.lat 的精确 /api/shorten。
- 新系统独立资源可经已授权的 `workflow_dispatch` 创建、部署、迁移和验证，agent 可使用 gh / GitHub API 触发及按归属 checkpoint 恢复必要步骤。遇到已有同名资源需证明本项目归属后才可幂等更新，禁止覆盖其他资源；写入结果不明时先核验归属，不盲目重发。
- 不通过故意写入验证只读上限。读取成功只证明对应读取可用；Token active 不等于所有权限通过；GH Secret 名称存在不等于值正确或权限有效。
- 预检固定官方 API 主机、预定义只读端点及固定查询；禁止携认证跨域重定向、任意 SQL、修复或自动创建功能。
- 仅直接读取明确的本项目凭据位置；不扫描用户目录寻找密钥。凭据、KV 样本、日志、响应和导出只能保存在忽略的本地路径。

## Git 与后续开发

- 先核实 origin、基线、分支、工作区和适用指令；先读脚本再执行。保护未提交内容，不使用 `reset --hard`、`git clean`、强制 checkout 或自动 stash。
- 开发流程：任务分支 → 编写 → 本地验证 → 自行修复 → 提交 / PR → CI → 符合规则后合并；普通阶段无需再次询问。
- CF 写操作只能通过 GitHub Actions，并校验账户、环境、资源 ID、目标域名和明确授权的新系统资源范围。
- 测试、生产部署必须分别使用独立的 `workflow_dispatch`；禁止 push、合并、定时自动部署。本次允许 agent 显式触发已授权的新测试环境流程，不包含生产发布或生产域名切换授权。未实际执行的项目仍记录未验证；真实 GitHub 环境审批、登录/MFA 或平台权限阻挡不能绕过，生产发布与切换需单独授权。
- `npm run check` 执行安全检查、类型检查、业务测试和构建；`npm run preflight` 只读。二者没有部署能力。历史六文件的逐字节保护继续有效。
