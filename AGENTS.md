# 项目执行边界

当前阶段：2026-10-04 正式开发。所有者已明确授权目标模式、业务实现、测试、修复、提交、推送、PR、CI 和符合 GitHub 规则的合并。初始化成果继续保留，初始化阶段的停止限制已结束。生产保护和用户手动部署边界继续有效。

## 版本与入口

- 现有生产代码为 `worker_updated_v3.js`，旧 Worker 为 `short-link`，KV 绑定为 `LINKS`。
- 保留三个历史 Worker、`README.md`、`CODEX_HANDOFF.md` 原文。它们描述旧系统，旧 API、密码、IP 白名单、全局 URL 去重和兼容性约束不属于新系统需求。
- 新系统确定要求见 `docs/REFACTOR_REQUIREMENTS.md`；当前 API 契约见 `docs/API_CONTRACT.md`；`docs/API_CONTRACT_DRAFT.md` 为历史设计参考；现场证据及未验证项见 `docs/INITIALIZATION_REPORT.md`。
- 新系统计划 Worker：`shortlink-new`；测试前台：`test.gfw.mom`；后台与机器 API：`link-admin.lily.lat`。实际资源以只读核验和后续授权创建结果为准。

## 资源与权限保护

- 本地 Cloudflare 只读；仅使用明确用于本项目的只读凭据。不得自动使用通用部署 Token、Wrangler OAuth、Global API Key，不打印凭据或导出环境变量。
- 保护账户中所有已有域名、DNS、路由、Worker、D1、KV、R2、生产配置及数据；不得删除、重建、覆盖或修改。尤其不得改变 `gfw.mom` 现有服务指向。
- 不修改共享 Turnstile、无关 Access/身份提供方/WAF/规则/Secret，不清缓存，不执行旧生产写入或压力测试。本项目新入口的精确 WAF / Access 配置只经用户手动 Actions；机器 API 测试期全 IP 授权仅限 link-admin.lily.lat 的精确 /api/shorten。
- 新系统独立资源可经用户手动 Actions 创建、部署、迁移；agent 不代替用户触发。遇到已有同名资源需证明本项目归属后才可幂等更新，禁止覆盖其他资源。
- 不通过故意写入验证只读上限。读取成功只证明对应读取可用；Token active 不等于所有权限通过；GH Secret 名称存在不等于值正确或权限有效。
- 预检固定官方 API 主机、预定义只读端点及固定查询；禁止携认证跨域重定向、任意 SQL、修复或自动创建功能。
- 仅直接读取明确的本项目凭据位置；不扫描用户目录寻找密钥。凭据、KV 样本、日志、响应和导出只能保存在忽略的本地路径。

## Git 与后续开发

- 先核实 origin、基线、分支、工作区和适用指令；先读脚本再执行。保护未提交内容，不使用 `reset --hard`、`git clean`、强制 checkout 或自动 stash。
- 开发流程：任务分支 → 编写 → 本地验证 → 自行修复 → 提交 / PR → CI → 符合规则后合并；普通阶段无需再次询问。
- CF 写操作只能通过 GitHub Actions，并校验账户、环境、资源 ID、目标域名和明确授权的新系统资源范围。
- 测试、生产部署必须分别为用户手动触发的 `workflow_dispatch`；禁止 push、合并、定时自动部署。等待手动部署时记录未验证，生产切换需单独授权。
- `npm run check` 执行安全检查、类型检查、业务测试和构建；`npm run preflight` 只读。二者没有部署能力。历史六文件的逐字节保护继续有效。
