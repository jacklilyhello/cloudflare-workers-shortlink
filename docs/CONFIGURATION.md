# 初始化配置与只读核验

> 下文是初始化配置快照，其中资源、工具、工作流数量和待补项均描述初始化时点。开发阶段已获授权；所有者已明确确认本机现有 `CLOUDFLARE_API_TOKEN` 是本项目可用的只读凭据，无需重新询问来源。它仅在显式进程映射后用于固定只读预检，不作为部署凭据。所有者另已允许 agent 经 gh / GitHub API 显式触发本项目新测试环境的 `workflow_dispatch`，完成初始化、测试部署、安全接入、旧 KV 只读迁移至新 D1、备份验证及必要修复重试；Actions 中同名 Secret 的实际值与权限仍须在相应运行中核验，不下载到本地。生产发布与域名切换仍需单独授权。当前部署参数见 [OPERATIONS.md](OPERATIONS.md)，新接口见 [API_CONTRACT.md](API_CONTRACT.md)。

2026-10-04 已通过现有 GitHub 登录读取仓库配置；下面是实际保存的非机密 Variables，不是根据截图重建。**没有修改 GitHub 配置。**

| Variable | 实际值 | 本地格式/关系核验 | 仍待 CF 实测 |
| --- | --- | --- | --- |
| `CLOUDFLARE_ACCOUNT_ID` | `9431815bdb8beb2272f6668e06b7d3be` | 32 位十六进制 | 两 Zone、旧 Worker 的账户归属 |
| `CF_ZONE_ID_GFW_MOM` | `c145387704a24150f2e5a897ae947156` | 32 位十六进制 | 名称为 gfw.mom、账户匹配 |
| `CF_ZONE_ID_LILY_LAT` | `9c2a663ae602ff4ac1a73e97a98f2bf1` | 32 位十六进制，和前者不同 | 名称为 lily.lat、账户匹配 |
| `WORKER_NAME` | `shortlink-new` | 与最新决定一致，区别于旧 Worker | 是否存在、归属与部署状态 |
| `LEGACY_WORKER_NAME` | `short-link` | 与保护对象一致 | 元数据和绑定 |
| `LEGACY_KV_NAMESPACE_ID` | `5fad543837b4409898805eab154b5b84` | 32 位十六进制 | 旧 Worker LINKS 绑定、读取权限 |
| `PUBLIC_HOSTNAME` | `test.gfw.mom` | gfw.mom 子域、裸小写 hostname | DNS、路由、Custom Domain、广域绑定 |
| `ADMIN_HOSTNAME` | `link-admin.lily.lat` | lily.lat 子域、区别于前台 | DNS、路由、Access 及广域绑定 |
| `APP_ENV` | `test` | 仅测试，非生产 | 后续部署护栏 |
| `ADMIN_EMAILS` | `lilyyaloveyou@gmail.com,admin@888888.mom` | 两邮箱、无多余空白/重复 | OTP 和 Access 完整策略 |
| `CF_ACCESS_TEAM_DOMAIN` | `lilyya.cloudflareaccess.com` | 无协议、路径和端口 | 组织 auth_domain、JWT issuer |
| `TURNSTILE_SITE_KEY` | `0x4AAAAAACH8Z3i_zCB8ztZd` | 非空公开 key、无空白 | Widget 实际来源、hostname、Secret 配对 |

所有变量均无首尾空白和换行，12/12 与现场基线一致。脚本将这些已观察值作为只读范围固定基线；以后 GitHub 值变化先审阅，再更新核验基线，不静默接受新账户或域名。账户/Zone/KV ID 和 Site Key 是非机密元数据；本文件不含 Token 或 Secret 值。

## Repository Secrets

| 名称 | 本次证据 | 后续用途 | 未实测部分 |
| --- | --- | --- | --- |
| `CLOUDFLARE_API_TOKEN` | 名称存在 | 预期对应名为 github-shortlink-deploy 的 Account API Token，仅 Actions 创建/部署已授权新资源 | GH 无法读取值；来源、状态、写权限和实际部署能力未知 |
| `CF_ANALYTICS_READ_TOKEN` | 名称存在 | 后续后台统计只读；不能用部署 Token 代替 | 实际值、权限、有效性未知 |
| `TURNSTILE_SECRET_KEY` | 名称存在 | 既有 Widget 服务端 Siteverify | 与公开 key 配对、真实成功/失败未知 |

API 返回 total_count=3，无额外名称；Variables total_count=12，无额外配置。不要求 TEST_API_TOKEN、API_ALLOWED_CIDRS、API_ALLOWED_IPS。本次不删除旧配置；旧代码中的 ADMIN_PASS、INTERNAL_API_TOKEN、DWZLA_*、API_ALLOWED_IPS 属于旧系统。

初始化读取时 Actions enabled=true、allowed_actions=all、sha_pinning_required=false；默认 workflow 权限 read，不允许 Actions 审批 PR；当时工作流 total_count=0。这里只记录，不修改设置。

## 本地只读凭据

现场检查仅查看明确相关变量的存在性，无 Token 输出、无全环境导出。CLOUDFLARE_ACCOUNT_ID、CLOUDFLARE_API_TOKEN 已配置；CLOUDFLARE_READONLY_API_TOKEN、CF_READONLY_API_TOKEN、CF_API_TOKEN、CF_ANALYTICS_READ_TOKEN、CLOUDFLARE_READONLY_TOKEN_FILE 及两个 Zone 环境变量未配置。

初始化时新克隆仓库无旧本地配置/凭据说明，也没有可调用 CF 连接器。通用 CLOUDFLARE_API_TOKEN 当时没有只读来源标注，因此**未使用**，也未推定为用户准备的只读 Token。未扫描整个用户目录或其他项目寻找凭据；当前已由所有者确认来源，按顶部说明使用。

脚本接受以下显式来源之一：

- `CLOUDFLARE_READONLY_API_TOKEN`：仅由本项目安全读取方式提供给进程，不用通用 CLOUDFLARE_API_TOKEN 回退。
- `CLOUDFLARE_READONLY_TOKEN_FILE`：用户指定只含 Token 的已知安全文件；大小最多 4096 字节，仅当前用户可读写（0600/0400），不打印路径或内容。两个来源不能同时设置。

原来已有的安全来源可以保留，在命令的进程环境中映射到上述变量即可；这是本地约定，**不是必须新增的 GH Secret**。仅在用户明确说明通用变量是本项目只读凭据时，才通过原有方式映射给检查进程。禁止 fallback 到 OAuth、Global API Key 或部署 Token。

`.env.readonly.example` 只含空值；可复制为被忽略的 `.env.readonly` 并设 0600。Node 22 可显式 `node --env-file=.env.readonly scripts/preflight-readonly.mjs`；脚本不自动加载其他文件。

## 可重复预检

先阅读脚本，然后可运行：

```bash
npm run check
npm run preflight:github
# 当前本机来源已由所有者确认，显式映射后运行：
npm run preflight
# 若迁移结构理解确有必要，显式允许最多两条 KV 值结构读取：
node scripts/preflight-readonly.mjs --sample-kv
```

`--offline` 完全不请求 GitHub/CF；`--github-only` 不请求 CF。没有凭据或完整配置时，本地工作继续，CF 各项为 PENDING。退出码 0 表示本轮被实现的检查无待补；2 表示待补/异常，不应当作部署状态。预检没有上线验收功能，策略审阅、Secret 值和真实浏览器验证不会因脚本完成而自动通过。

输出每项包含检查项、凭据来源、范围、实际结果、UTC 证据时间、未验证部分。只输出白名单摘要，不打印 headers/认证/错误正文/其他 Worker bindings/KV key 或完整目标 URL。若留存输出，仅重定向到 `.local/`；默认不写文件或上传 artifacts。

安全实现：认证主机固定 api.cloudflare.com，redirect=error；只支持固定 GET 和固定 GraphQL 查询 POST，无任意路径/SQL/方法参数。每请求 12 秒，最多 2 次（短暂网络/5xx/429 才重试），响应上限 2 MiB；列表每端点最多一页，至多三个精确 Access 应用策略、最多两条 KV 值。超限/分页不完整为 PARTIAL，不能证明无冲突。依赖失败停止后续资源请求，不放宽鉴权。路由/IdP 无适用服务端过滤时只在内存中过滤/计数，不保存整个资产清单。

范围局限：DNS 精确 hostname 查询不能证明无 wildcard DNS，Access 域名过滤不覆盖其他主域的多目的地应用/广域 wildcard；发现占用只记录，不修复。D1/R2 搜索按 Worker 名限制，只测相关读取能力，空结果不证明资源最终命名/已创建状态；R2 只覆盖默认 jurisdiction。Token policy 只摘要权限名称，未执行写入，资源条件和权限上限需人工核验。预检不读取其他数据库、桶内容或统计原始日志。

## 官方接口与权限依据

核阅日期 2026-10-04。只列读取所需权限；写操作的未来最小权限必须结合真实策略与授权另审，**本次未实测部署写权限**。

| 检查 | 官方文档 | 读取权限/限制 |
| --- | --- | --- |
| Account Token 状态/策略 | [Account verify](https://developers.cloudflare.com/api/resources/accounts/subresources/tokens/methods/verify/)、[Account Tokens](https://developers.cloudflare.com/api/resources/accounts/subresources/tokens/) | 使用 accounts/{id}/tokens/verify；不混用 User Token 路径，active 仅状态 |
| Zone 归属 | [Zone details](https://developers.cloudflare.com/api/resources/zones/methods/get/) | Zone Read |
| Worker 元数据/绑定 | [Script Settings](https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/settings/methods/get/) | Workers Scripts Read；只摘取 LINKS |
| workers.dev 子域 | [Workers Subdomain](https://developers.cloudflare.com/api/resources/workers/subresources/subdomains/methods/get/) | Workers Scripts Read；地址仍为候选 |
| KV 小样本 | [List keys](https://developers.cloudflare.com/api/resources/kv/subresources/namespaces/subresources/keys/methods/list/) | Workers KV Storage Read；key limit=10，值默认关闭 |
| DNS/路由/Custom Domains | [DNS list](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/)、[Routes](https://developers.cloudflare.com/api/resources/workers/subresources/routes/)、[Domains](https://developers.cloudflare.com/api/resources/workers/subresources/domains/methods/list/) | DNS Read、Workers Routes Read、Workers Scripts Read（以端点权限说明为准） |
| D1/R2 | [D1 list](https://developers.cloudflare.com/api/resources/d1/subresources/database/methods/list/)、[R2 list](https://developers.cloudflare.com/api/resources/r2/subresources/buckets/methods/list/) | D1 Read、Workers R2 Storage Read；name/name_contains 过滤 |
| Access | [Applications](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/methods/list/)、[Organization](https://developers.cloudflare.com/api/resources/zero_trust/subresources/organizations/methods/list/)、[Identity Providers](https://developers.cloudflare.com/api/resources/zero_trust/subresources/identity_providers/) | Access: Apps and Policies Read；组织/IdP 的合并权限名为 Access: Organizations, Identity Providers, and Groups Read |
| 统计 | [Workers GraphQL 示例](https://developers.cloudflare.com/analytics/graphql-api/tutorials/querying-workers-metrics/) | Account Analytics Read；固定 Worker、15 分钟、limit=1，无 AE 数据集证明 |
| Account Token 产品支持 | [官方兼容表](https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/) | Turnstile 管理当前不支持 Account API Token，不误判为缺权限，不申请新高权限 User Token |

Turnstile 公共 hostname 规则见 [Hostname management](https://developers.cloudflare.com/turnstile/additional-configuration/hostname-management/)。用户提供的信息称现有 Widget 允许 gfw.mom、lily.lat、旧 Worker 域名和 workers.dev；根域可覆盖子域，故 gfw.mom 规则可覆盖 test.gfw.mom。这是文档规则加用户信息，**不是读取 Widget 的现场证据**。workers.dev 范围较宽仅记为以后可选收紧，不修改共享 Widget。管理 API 凭据与 Siteverify Secret 不同；本次没有真实 challenge，不调用旧系统创建流程或用测试 challenge 判断真实 Secret。

## 当前运行与历史草稿

新资源 ID、Access App ID/AUD 和实际 workers.dev URL 仍不得猜填；在已授权的初始化 Actions 返回后记录真实值，再只读核验归属。新资源目标和现有 workflow 以 [OPERATIONS.md](OPERATIONS.md) 为准，不能依据上文旧快照将已确认的只读凭据来源或测试 Actions 触发重新作为待授权事项。

只读 Action 草稿位于 `docs/workflows/preflight-readonly.yml.example`；初始化时它未进入 `.github/workflows`，未发布/运行。它只能验证 Account Token 状态及固定统计查询，不声称验证写权限/Turnstile Secret 配对。当前 agent 已获准通过 gh / GitHub API 触发默认分支上的本项目测试 `workflow_dispatch`；本地或任务分支存在草稿不等于可运行，真实环境审批仍须遵守，不由本次授权绕过。

## 当前迭代配置

上述初始化表格是历史快照。已有Worker/D1/R2与域名不重建；部署从私有ownership manifest读取真实ID。新增运行时plain配置`CLOUDFLARE_ACCOUNT_ID/WORKER_NAME/D1_DATABASE_ID/RESOURCE_OWNER_ID`，均由已核验manifest生成，用于域名刷新交叉核对，不是用户可提交的管理字段。

独立域名只读Secret优先`CF_DOMAIN_READ_TOKEN`，其次现有`CF_ANALYTICS_READ_TOKEN`。Actions在官方固定两个GET上实际读取Custom Domains与Worker settings，并审阅凭据自身只读policy/范围后才作为Worker secret `DOMAIN_BINDING_READ_TOKEN`注入。部署Token无兜底、不进入Worker，Secret值不打印、不下载。资格不足将部署标为domain verification unavailable，后台刷新明确失败，不凭名称推定权限。只读能力为项目账户的Workers Scripts Read；自身policy审阅需现有可读能力，agent不扩权。`domain-read-credential.yml`仅资格诊断，无资源写入。

后台D1设置新增`backup_enabled/migration_enabled`（0或1）、`migration_interval_hours`（1..720）；默认自动开启、24小时。备份间隔同样1..720小时，三项保留天数0..3650，0永久。设置保存在本项目DB，不改变CF基础设施。IP名单仅由CF Custom Rules维护，当前指定87.83.110.180，不新增应用IP配置。
