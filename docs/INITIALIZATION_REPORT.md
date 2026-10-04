# 初始化交接报告

> 历史快照：下文记录初始化结束时的证据。所有者已于 2026-10-04 明确授权正式开发、提交、PR、CI 和按规则合并，并确认当前 `CLOUDFLARE_API_TOKEN` 是本项目可用的只读凭据。初始化的停止限制已结束；生产保护、只读本地凭据和用户手动 Actions 写入边界继续有效。开发接口见 [API_CONTRACT.md](API_CONTRACT.md)，部署操作见 [OPERATIONS.md](OPERATIONS.md)。当前验证与交付记录放在 PR 中，不把下文旧快照当作新系统验收。

状态：**本地准备完成，以下验证待补**。初始化到此停止；没有启动 Goal 模式或新系统业务开发。

## 本地仓库与成果

- 路径：`/Users/bao/Desktop/codex.nosync/cloudflare-workers-shortlink`。
- 仓库：[jacklilyhello/cloudflare-workers-shortlink](https://github.com/jacklilyhello/cloudflare-workers-shortlink)，origin 使用 HTTPS，公开仓库，默认分支 main，未归档。
- 初始目录确认为空，无适用的祖先 AGENTS.md；安全克隆后工作区干净，无用户修改需要覆盖。
- 本地和最后读取的远端 main 基线均为 `4eb246fb41d5f15fd8262cfda84cbe930fa37b3c`；没有强行回退到提示词基线。
- 实际本地分支：`codex/shortlink-initialization`，从该 commit 新建，HEAD 没有新增提交。
- 原有六个跟踪文件逐字节保持原样：README.md、CODEX_HANDOFF.md、LICENSE 及三个 Worker JS。新增成果仅在本地、未暂存/提交/推送。

新增文件：

| 文件 | 用途 |
| --- | --- |
| `AGENTS.md` | 初始化终点、资源保护、权限和后续入口 |
| `docs/REFACTOR_REQUIREMENTS.md` | 已确定要求、建议、待定事项及旧版本边界 |
| `docs/CONFIGURATION.md` | 12 Variables 实际值、3 Secrets 名称、凭据与官方 API 依据 |
| `docs/API_CONTRACT_DRAFT.md` | 尚未实现的机器 API 与安全/响应/后续验收草案 |
| `docs/INITIALIZATION_REPORT.md` | 本次证据、限制与待补事项 |
| `scripts/preflight-readonly.mjs` | 固定范围只读预检，默认不读取 KV 值 |
| `scripts/preflight-readonly.test.mjs` | 预检有实质风险的安全逻辑验证，不是产品测试 |
| `scripts/check-initialization.mjs` | 语法、安全测试、空白与旧文件完整性检查 |
| `docs/workflows/preflight-readonly.yml.example` | 后续手动只读 Action 草稿，未发布/执行 |
| `package.json` | 仅初始化所需、无依赖/部署入口的 Node 工具配置 |
| `.gitignore` | 排除凭据、本地报告、样本、日志、数据库和模拟器状态 |
| `.env.readonly.example` | 不含真实值的本地只读凭据示例 |

忽略的本地证据：`.local/initialization-preflight.json`，包含 42 项脱敏摘要（21 项 GitHub、21 项 CF 待补），无原始业务值、Secret 或认证头。该文件不应提交，仓库报告保留结论。语法/验证不安装依赖，不改变全局环境；没有创建 Wrangler 配置、业务框架或数据库。

## 证据时间与配置结果

主要 GitHub 可重复脚本证据：2026-10-04 **18:22:13–18:22:16 Asia/Singapore**（10:22:13–10:22:16 UTC）。其后的只读远端 main 查询再次返回相同 SHA。脚本每个检查项单独带 UTC 时间。

| 检查项 | 凭据来源 | 范围 | 实际结果 | 未验证部分 |
| --- | --- | --- | --- | --- |
| GitHub Variables | 本机既有 gh 登录 | 指定仓库，单页 total_count=12 | 12/12 读取成功、非空、无首尾空白/换行；域名、邮箱、环境、Worker 名等符合要求，ID 符合格式；完整值见 CONFIGURATION.md | CF 中对应资源/归属尚未读取 |
| GitHub Secrets | 本机既有 gh 登录 | 指定仓库，total_count=3 | CLOUDFLARE_API_TOKEN、CF_ANALYTICS_READ_TOKEN、TURNSTILE_SECRET_KEY 名称均存在；无额外 Secret | GH API 不返回值；状态、来源、配对、权限、部署能力均未知 |
| Actions 设置 | 本机既有 gh 登录 | 指定仓库 | enabled=true、allowed_actions=all、sha_pinning_required=false；默认 workflow read，不能审批 PR | 未运行任何工作流/部署 |
| 现有工作流 | 本机既有 gh 登录 | 指定仓库 | total_count=0 | 本地草稿不等于可手动运行 |
| 本地 CF 凭据来源 | 相关环境变量存在性、新克隆仓库文件、当前工具目录 | 仅明确相关来源，无用户目录扫描 | 通用 CLOUDFLARE_API_TOKEN 已配置；专用只读变量/文件路径未配置，仓库无凭据位置说明，无可调用 CF 连接器 | 通用变量未标明本项目只读用途，因此不使用；只读凭据安全位置/变量名待确认 |
| Account Token 状态/策略 | 无明确本项目只读来源 | 预期账户 | **未发送请求** | active、写权限上限、自身政策和部署候选 Token 政策全部待补 |
| 两个 Zone 名称/账户 | 同上 | gfw.mom、lily.lat 的 GH Zone ID | **未实测** | 不能确认 ID 对应实际名称/同账户 |
| 旧 Worker/LINKS/KV | 同上 | short-link 与 GH LEGACY_KV_NAMESPACE_ID | **未实测**；只从本地代码看到 LINKS 用法 | 真实绑定、KV key/value 读取能力、数据格式分布未知；无样本导出 |
| Workers 子域名与新 Worker | 同上 | 新 Worker 名与账户子域 | **未实测** | shortlink-new.lilyya.workers.dev 仅用户资料中的候选，未当作已部署地址；新 Worker 是否存在未知 |
| DNS/路由/Custom Domain | 同上 | test.gfw.mom、link-admin.lily.lat | **占用状态未知** | 精确绑定、wildcard/广域、其他产品覆盖均待补；未覆盖任何资源 |
| D1/R2 读取 | 同上 | 受限项目名搜索，未来新资源 | **未实测** | 能力、现有冲突和资源状态未知；没有访问数据库/对象或创建资源 |
| Access 团队/应用/策略/OTP | 同上 | 预期团队和后台域名 | **未实测** | auth_domain、应用是否创建、AUD、两邮箱完整策略、OTP 与应用设置未知；不猜测 AUD |
| Account Analytics | 同上 | 固定新 Worker、15 分钟、limit=1 | **未实测** | 本地读取能力、GH 专用分析 Token、AE 数据集都未知；没有制造统计数据 |
| Turnstile | GH Variables/Secrets 名称、用户提供信息、官方文档 | 已有公开 Site Key 与共享 Widget | 仅确认公开 key 非空及 Secret 名称存在 | 未读取 Widget hostname、Secret 配对或真实浏览器 challenge；无 Siteverify/旧系统创建请求 |

本地 CLOUDFLARE_ACCOUNT_ID 已配置；CF_ZONE_ID_GFW_MOM、CF_ZONE_ID_LILY_LAT、CLOUDFLARE_READONLY_API_TOKEN、CF_READONLY_API_TOKEN、CF_API_TOKEN、CF_ANALYTICS_READ_TOKEN、CLOUDFLARE_READONLY_TOKEN_FILE 未配置。只输出名称和状态，没有展示凭据。

官方 [Account API Token 兼容表](https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/) 当前注明 Turnstile 管理不支持 Account Token，因此不能把管理失败当作缺权限，也不会为初始化申请高权限 User Token。用户提供的 Widget 根域信息与官方 [子域覆盖规则](https://developers.cloudflare.com/turnstile/additional-configuration/hostname-management/) 相容，但不是现场 Widget 读取证据。workers.dev 允许范围偏宽只作为后续可选改进记录，本次未改变。

## 本地验证与观察

- `npm run check`：三个原 Worker 与所有新 mjs 语法通过；15 个预检安全测试通过；`git diff --check` 和新增未跟踪文件空白检查通过；六个原文件与 HEAD 的字节比较通过。
- 工作流草稿：仅 workflow_dispatch，GitHub permissions={}，固定官方 API Account verify/GraphQL 只读请求，认证不跟随重定向，超时与响应上限，无 checkout/部署/迁移/资源创建/artifact 上传；YAML 与内嵌 Node 语法本地核验。未运行草稿网络代码。
- 现场可重复预检退出码 **2**，原因是 21 项 CF 待补，不是测试失败，也没有放宽凭据识别或鉴权使它通过。
- 已验证 .env.readonly、.local 报告、.wrangler/state、数据库和 exports 路径受 Git 忽略。没有本地真实凭据文件或业务样本进入新增成果。
- 代码版本差异：main 上 `/api/v1/link` 直接写旧 KV，旧 README/交接仍说 DWZLA；旧后台 GET 列表可删除缺失项。已在新需求中明确原文属于旧系统，未修复旧代码，未对旧后台发请求。

## 限制、原因与最小下一步

| 项目 | 具体原因/证据 | 最小下一步（本次不执行） |
| --- | --- | --- |
| CF 21 项现场读取 | 没有明确标为本项目只读的凭据来源；通用变量存在不能证明用途 | 仅提供已有只读凭据的安全读取位置/变量名，或明确确认现有变量就是本项目 Account 只读 Token；无需发送明文。之后按脚本固定范围复核 |
| 只读权限上限 | 没有读取策略；即使读取成功也不证明没有写权限 | 若现有权限支持，读取自身 Token policy，审阅权限名称及资源条件；不能通过故意写入测试，不另申请管理写权限 |
| GH Secret 有效性 | Secrets API 无值；名称存在≠有效 | 后续另行授权将只读草稿发布到默认分支，再由用户手动触发。草稿验证状态/统计查询，不证明部署写能力或 Turnstile 配对 |
| Turnstile 端到端 | 无真实浏览器 challenge 与配对 Secret，Account Token 管理不支持 | 新测试系统接入后验证真实成功/失败；保留共享 Widget，不用测试 challenge 判断真实 Secret |
| 广域绑定/Access 策略 | 当前未读 CF；脚本精确域名过滤也有边界 | 获得来源后先有限读取，仍不完整时单独只读审阅相关 wildcard/multi-destination/其他产品证据，不覆盖冲突 |
| 沙箱网络诊断 | 最初 gh auth status 报默认登录失败；yarn 版本查询触发 corepack registry 读取并遇 ENOTFOUND | GH 只读查询在审查后的网络环境成功，不能据初始诊断认定登录失效；不要求重新登录。Yarn 非初始化必需，不安装或改全局工具链 |

现场工具：Git 2.54.0、gh 2.96.0、Node v22.23.1、npm 10.9.8、pnpm 9.15.4；无 Wrangler 可执行文件。仓库原来无 package.json/锁文件/项目脚本，本次沿用 Node/npm，仅最小初始化配置、无外部依赖。Yarn 版本未能独立读取；本次不需要 Yarn/Wrangler。

真正待补配置仅为**本地只读凭据来源的确认**，以及读取后发现的实际配置偏差（当前尚无 CF 证据）。无需现在填写新 D1 ID、R2 桶名、Access AUD、AE 数据集或候选 workers.dev 地址，不能为了通过检查而创建资源。

后续只有收到新的明确开发指令后，才按任务分支→开发→本地验证/修复→PR→CI→按授权合并推进。部署由用户分别手动触发；生产切换仍需独立授权。当前预检完成不启动下一阶段。

## 本次边界执行结果

没有修改/创建/删除任何 CF 资源、域名、DNS、路由、旧 Worker、KV、D1、R2、Turnstile、Access、WAF、安全规则、缓存或 Secret；CF 认证 API 请求数为 **0**。没有部署、迁移、生产写入/压力测试、推送、创建 PR、合并、触发 Actions 或修改远端配置。仅本地克隆、建立初始化分支、新增初始化文档/脚本并读取 GitHub。未启动 Goal 模式，未更改旧生产代码。

**本地准备完成，以下验证待补；以上是初始化阶段的历史结论。当前执行边界以 AGENTS.md 和所有者后续明确授权为准。**
