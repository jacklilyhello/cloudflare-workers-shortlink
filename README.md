<h1 align="center">🔗 Cloudflare Workers Shortlink</h1>

<p align="center">
  <strong>长链接，轻一点。</strong><br>
  免登录生成 · 多域名通用 · 独立管理后台 · Cloudflare 原生部署
</p>

<p align="center">
  <a href="https://developers.cloudflare.com/workers/"><img src="https://img.shields.io/badge/Cloudflare-Workers-F38020?logo=cloudflare&logoColor=white" alt="Cloudflare Workers"></a>
  <a href="https://developers.cloudflare.com/d1/"><img src="https://img.shields.io/badge/Storage-D1%20%2B%20R2-F38020" alt="Cloudflare D1 and R2"></a>
  <a href="https://www.typescriptlang.org/"><img src="https://img.shields.io/badge/TypeScript-3178C6?logo=typescript&logoColor=white" alt="TypeScript"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-2E8B57" alt="MIT license"></a>
  <a href="https://github.com/jacklilyhello/cloudflare-workers-shortlink/actions/workflows/ci.yml"><img src="https://github.com/jacklilyhello/cloudflare-workers-shortlink/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/jacklilyhello/cloudflare-workers-shortlink/stargazers"><img src="https://img.shields.io/github/stars/jacklilyhello/cloudflare-workers-shortlink?style=flat" alt="GitHub stars"></a>
</p>

<p align="center">
  <a href="https://gfw.mom/">在线使用</a> ·
  <a href="https://gfw.lat/">备用域名</a> ·
  <a href="#部署与配置">部署说明</a> ·
  <a href="docs/API_CONTRACT.md">API 文档</a> ·
  <a href="archive/legacy-workers/README.md">历史版本</a> ·
  <a href="https://github.com/jacklilyhello/cloudflare-workers-shortlink/issues">问题反馈</a>
</p>

Cloudflare Workers Shortlink 是一个基于 **TypeScript、Cloudflare Workers、D1 与私有 R2** 的短链接系统。用户无需注册即可创建、复制和分享短链；管理员通过独立域名管理链接、域名、业务 Token、访问统计和自动备份。

当前应用入口为 [`src/index.ts`](src/index.ts)，前端位于 [`ui/`](ui/)。正式系统使用 D1 保存业务数据，旧 KV 保留用于历史迁移来源，不再作为新系统的在线短链数据库。

> [!IMPORTANT]
> **根目录的三个 `worker_updated*.js` 均为历史版本，不是当前部署入口。** 它们已原样归档，原文件也继续保留。旧版 API、密码验证、长链接去重和单文件部署说明仅供查阅，详见[历史版本归档](#历史版本归档)。

<details>
<summary><strong>目录</strong></summary>

- [在线入口](#在线入口)
- [功能特性](#功能特性)
- [使用方式](#使用方式)
- [系统架构](#系统架构)
- [机器 API](#机器-api)
- [部署与配置](#部署与配置)
- [本地开发](#本地开发)
- [备份与迁移](#备份与迁移)
- [历史版本归档](#历史版本归档)
- [常见问题](#常见问题)
- [文档与贡献](#文档与贡献)
- [许可证](#许可证)

</details>

## 在线入口

| 入口 | 用途 |
| --- | --- |
| **[gfw.mom](https://gfw.mom/)** | 正式主域名，匿名创建与短链跳转 |
| **[gfw.lat](https://gfw.lat/)** | 同一系统的另一个正式公共域名 |
| [link-admin.lily.lat/admin](https://link-admin.lily.lat/admin) | 管理后台，需要通过 Cloudflare Access |
| `POST https://link-admin.lily.lat/api/shorten` | 服务器、脚本和机器人的创建接口 |

同一个短码可以通过所有已登记、已核验且启用的公共域名访问，并指向同一条逻辑映射。例如，`gfw.mom/your-code` 与 `gfw.lat/your-code` 共享目标和生命周期设置；这里的地址仅为格式示例。

历史测试域名 `test.gfw.mom`、`test.gfw.lat` 的资源和记录保留，业务入口已停用；`workers.dev` 与 Preview 入口关闭。

## 功能特性

| | 当前能力 |
| --- | --- |
| 🔗 匿名创建 | 无需登录，支持随机短码和自定义短码，创建必须通过 Turnstile 验证 |
| 🌐 多域名共享 | 全局短码命名空间，一条映射对应多个有效公共域名前缀，前台逐条展示并支持复制 |
| 🎨 用户界面 | 雾白蓝与液态玻璃风格、紧凑桌面布局、移动端适配、浅色 / 深色 / 跟随系统 |
| 🗂️ 链接管理 | 搜索、分页、创建、编辑、批量启停与到期设置、导出，以及确认后单条删除 |
| ⏳ 生命周期 | 默认永久有效；可设置到期、停用、跳转确认页、说明文字及查询参数策略 |
| 🔑 业务 API | Bearer Token、按域名授权、限流、可选幂等键；业务 Token 仅有创建能力 |
| 📊 访问统计 | 按日期、来源、地区与设备展示访问聚合 |
| 🛡️ 独立鉴权 | 公共入口使用 Turnstile；后台使用 Access JWT；机器入口使用精确 WAF 白名单和业务 Token |
| 💾 数据保护 | D1 一致性快照、私有 R2 备份、维护计划、审计日志和迁移状态 |
| ⚙️ 交付流程 | GitHub Actions 运行 CI；通过独立手动工作流执行生产部署与受控维护 |

匿名用户不保留个人历史列表，生成后应及时复制保存。相同长链接每次正常创建都会产生独立短链；机器客户端只有使用相同幂等键重试同一请求时才复用结果。

## 使用方式

1. 打开 [gfw.mom](https://gfw.mom/) 或 [gfw.lat](https://gfw.lat/)，粘贴完整的 HTTP / HTTPS 长链接。
2. 按需填写自定义短码；留空时自动生成。
3. 完成安全验证后点击“生成短链接”，从结果中选择一个公共域名地址复制分享。

自定义短码区分大小写，支持 1–64 个字母、数字、下划线或连字符。保留路径及已经占用的短码不可使用。

管理后台提供链接管理、访问统计、域名配置、业务 Token、自动备份、审计日志、迁移记录和系统设置。管理员通过已配置的 Access 身份登录；项目没有公开注册或匿名管理入口。

## 系统架构

| 组件 | 作用 |
| --- | --- |
| TypeScript + Vite | 构建公共页面与管理后台的静态资源 |
| Cloudflare Workers | 主机与路由隔离、创建与跳转、管理员接口、鉴权及定时维护 |
| Workers Static Assets | 与应用同源提供页面、样式和脚本 |
| Cloudflare D1 | 链接、域名、Token 摘要、幂等记录、统计、设置、审计和任务状态 |
| 私有 Cloudflare R2 | 一致性备份对象与运维归属 / 断点记录 |
| Cloudflare Access / Turnstile / WAF | 分别保护管理员入口、匿名创建和机器 API |
| GitHub Actions | CI、受控发布、迁移与维护工作流 |

应用运行在一个 Worker 上，无需 VPS、常驻 Node 服务或独立 Cloudflare Pages 项目。Node.js 用于本地开发与 CI。旧 Worker 与 KV 作为保留资源存在，不承担新系统的数据写入。

| 目录 / 文件 | 内容 |
| --- | --- |
| [`src/index.ts`](src/index.ts) | 当前 Worker 入口与主机 / 路由边界 |
| [`src/core.ts`](src/core.ts) | 创建、短码、Token、参数处理与跳转 |
| [`src/admin.ts`](src/admin.ts)、[`src/auth.ts`](src/auth.ts) | 后台接口与 Access JWT 校验 |
| [`src/maintenance.ts`](src/maintenance.ts) | 备份与定时维护 |
| [`ui/`](ui/) | 用户页面、管理后台和公共页面独立样式 |
| [`migrations/`](migrations/) | D1 版本化数据库迁移 |
| [`scripts/`](scripts/) | 预检、部署、安全维护与旧数据迁移工具 |
| [`.github/workflows/`](.github/workflows/) | CI 与独立手动工作流 |
| [`docs/`](docs/) | 接口契约、运行配置和运维说明 |
| [`archive/legacy-workers/`](archive/legacy-workers/) | 三个旧版 JS 与旧 README 的只读归档 |

## 机器 API

唯一机器创建入口：

```http
POST https://link-admin.lily.lat/api/shorten
Authorization: Bearer <业务 Token>
Content-Type: application/json
```

`url` 与 `domain` 必填，`slug` 可省略。接口只接受这三个业务字段，公共网页使用的是另一组匿名接口。

```bash
# 从安全运行环境提供 SHORTLINK_BUSINESS_TOKEN；不要把真实值写入代码。
curl --request POST 'https://link-admin.lily.lat/api/shorten' \
  --header "Authorization: Bearer $SHORTLINK_BUSINESS_TOKEN" \
  --header 'Content-Type: application/json' \
  --header 'Idempotency-Key: unique-request-001' \
  --data '{"url":"https://example.com/a?x=1#section","domain":"gfw.mom"}'
```

首次成功返回 `201 Created`，响应格式示例：

```json
{
  "ok": true,
  "data": {
    "slug": "Ab9xQ2mR",
    "domain": "gfw.mom",
    "short_url": "https://gfw.mom/Ab9xQ2mR"
  },
  "request_id": "opaque-id"
}
```

- 业务 Token 由管理员在后台手动生成，明文仅首次显示；数据库保存其摘要。
- `domain` 必须已启用、完成绑定核验，并在当前 Token 的授权范围内。机器响应只返回所选域名地址。
- 每次新的业务请求使用新的幂等键；网络重试同一请求时复用原键。相同键和内容返回原结果，不同内容返回冲突。
- 当前上游实例的机器 WAF 仅允许 `103.118.43.47/32` 与 `45.77.252.181/32`；其他 IPv4 和全部 IPv6 被拒绝。这不限制普通用户访问公共网站。
- 机器 API 不需要交互式 Access 登录或 Turnstile，但始终要求业务 Token；它不提供查询、管理或删除权限。

> [!NOTE]
> 旧 `POST /api/v1/link`、旧 Token 和旧响应格式不兼容。Cloudflare 部署 Token 也不能用作业务 Token。边缘 WAF 在 Worker 执行前拒绝的响应，不属于应用 JSON 错误契约。

完整字段限制、错误码、幂等语义、签名 URL 与查询参数处理见 **[API_CONTRACT.md](docs/API_CONTRACT.md)**。

## 部署与配置

### 当前正式实例

| 项目 | 配置 |
| --- | --- |
| Worker | `shortlink-new` |
| 环境 | `APP_ENV=production` |
| 主公共域名 | `gfw.mom` |
| 其他正式公共域名 | `gfw.lat` |
| 后台域名 | `link-admin.lily.lat` |
| D1 | 继续使用原 `shortlink-new-test` 数据库和数据 |
| 私有 R2 | `shortlink-new-backups` |
| 维护 Cron | `*/10 * * * *` |
| 测试域名 / workers.dev / Preview | 测试业务停用；workers.dev 与 Preview 关闭 |

数据库名称中的 `test` 是历史命名，不代表仍在测试环境，也不是重建、清空或更换数据库的理由。

### GitHub 配置

生产流程使用 **`shortlink-production` Environment**，在仓库的 Settings → Secrets and variables → Actions / Environments 中维护相应配置。以下为配置分组，准确值与作用以工作流及运行文档为准。

| 类型 | 名称 | 用途 |
| --- | --- | --- |
| Secret | `CLOUDFLARE_API_TOKEN` | 仅在 Actions 中使用的部署 / 维护凭据 |
| Secret | `TURNSTILE_SECRET_KEY` | 匿名创建的服务端验证 |
| Secret | `CF_DOMAIN_READ_TOKEN` | 优先使用的独立域名只读核验凭据 |
| Secret | `CF_ANALYTICS_READ_TOKEN` | 现有候选读取凭据；只有实际通过资格核验才可用于域名读取 |
| Variables | `CLOUDFLARE_ACCOUNT_ID`、`CF_ZONE_ID_GFW_MOM`、`CF_ZONE_ID_GFW_LAT`、`CF_ZONE_ID_LILY_LAT` | 账户与三个 Zone 范围 |
| Variables | `WORKER_NAME`、`LEGACY_WORKER_NAME`、`LEGACY_KV_NAMESPACE_ID` | 当前 Worker 与保留旧资源的标识 |
| Variables | `PUBLIC_HOSTNAME`、`ADMIN_HOSTNAME`、`APP_ENV` | 生产主机与环境 |
| Variables | `ADMIN_EMAILS`、`CF_ACCESS_TEAM_DOMAIN`、`TURNSTILE_SITE_KEY` | 管理员名单、Access 团队域和公开 Site Key |
| Variable | `PRODUCTION_RELEASE_AUTHORIZED` | 已审阅生产流程的执行门禁，不替代 GitHub 审批 |

实际 D1 ID、Access AUD、资源归属等由已核验的绑定与私有 manifest 解析。独立域名只读凭据需要通过真实权限及归属核验后，才能注入为 Worker 的 `DOMAIN_BINDING_READ_TOKEN`；不能用部署凭据兜底。

### 更新现有实例

代码通过任务分支与 PR 交付，现有 CI 通过后按仓库规则合并。**Push 和合并只触发 CI，不会自动部署生产。**

生产更新使用 [部署及切换工作流](https://github.com/jacklilyhello/cloudflare-workers-shortlink/actions/workflows/deploy-production.yml)，仅允许从 `main` 手动运行。普通代码发布使用已完成切换后的 `cutover` 阶段，由部署脚本复用原资源并核验已保存的迁移、备份和归属条件；其余阶段用于受控切换与诊断，不应为每次更新重新执行整套迁移。

此部署路径会执行受控 D1 migration ledger 检查与应用，不能将它理解为纯静态文件上传。具体确认文本、阶段说明、安全维护和诊断入口见 [OPERATIONS.md](docs/OPERATIONS.md)。

### 部署自己的实例

> [!IMPORTANT]
> 本仓库包含上游项目专用的仓库、账户、域名、资源和迁移保护。**Fork 后仅填写 Secrets 不足以部署新站。**

新实例需要自己的 Worker、D1、私有 R2、公共与后台域名、Turnstile 和 Access 配置，并在 Fork 中协调调整运行时主机校验、部署与安全脚本中的固定范围。现有生产工作流依赖上游资源归属及切换记录，历史测试初始化入口已停用；应为新实例单独设计和审阅初始化流程，不能借用或覆盖上游资源。

[CONFIGURATION.md](docs/CONFIGURATION.md) 顶部描述当前正式配置，后续标注的初始化快照用于历史查阅。不要把旧测试域名、旧权限或旧变量示例直接当作当前配置。

## 本地开发

使用 **Node.js 22.12 或更高版本**，CI 当前使用 Node.js 22。

```bash
git clone https://github.com/jacklilyhello/cloudflare-workers-shortlink.git
cd cloudflare-workers-shortlink
npm ci
npm run dev
```

`npm run dev` 启动 Vite 前端开发服务，**不会自动提供本地 Worker API、D1、Access 或 Turnstile 后端**。完整交互需要另行准备隔离的本地运行环境或模拟响应，不能将前端启动成功等同于业务可用。

| 命令 | 用途 |
| --- | --- |
| `npm run build` | 构建前端，输出到 `dist/` |
| `npm run typecheck` | 检查 Worker 与前端 TypeScript |
| `npm run check:safety` | 开发安全检查及历史文件原文保护 |
| `npm run check` | 安全、格式、类型、既有测试与构建检查 |
| `npm run preflight:github` | GitHub 配置的只读预检 |
| `npm run preflight` | 固定范围的只读预检，需要明确的只读凭据 |

普通构建和 CI 不需要生产业务 Token。Cloudflare 写操作由 Actions 执行，部署凭据不下载到本地。开发与自动化协作约定见 [AGENTS.md](AGENTS.md)。

## 备份与迁移

- **日常备份**：从 D1 创建一致性快照，分片写入私有 R2；后台配置计划并查看状态，Worker 定时推进任务。
- **保留策略**：统计、审计和备份保留天数设为 `0` 表示永久保留；计划间隔必须大于零。
- **旧数据迁移**：旧 KV 自动同步在末次增量和备份核验后停用，迁移历史、旧 Worker 与 KV 继续保留；日常备份和维护 Cron 不因此停用。
- **历史来源**：保留原始 `links.domain`，展示与复制使用当前有效公共域名，不通过批量改写来源域名完成切换。
- **完整性说明**：迁移记录中的既有异常和未完整读取项保留真实状态，不能把任务完成写成所有历史记录均已完整核验。

事件与任务时间默认按 Asia/Singapore（UTC+8）展示；历史访问趋势的日桶按 UTC 统计。访问事件不是独立访客人数。恢复与迁移操作应遵循 [运维说明](docs/OPERATIONS.md)，不能以恢复为由覆盖正在使用的数据。

## 历史版本归档

三个单文件 Worker 已作为**冻结的历史源码**保存到 [`archive/legacy-workers/`](archive/legacy-workers/)，根目录原文件也保留，内容不变、不删除。

| 历史版本 | 归档副本 | 保留的原文件 |
| --- | --- | --- |
| v1 | [worker_updated.js](archive/legacy-workers/worker_updated.js) | [根目录原文件](worker_updated.js) |
| v2 | [worker_updated_v2.js](archive/legacy-workers/worker_updated_v2.js) | [根目录原文件](worker_updated_v2.js) |
| v3，迁移前版本 | [worker_updated_v3.js](archive/legacy-workers/worker_updated_v3.js) | [根目录原文件](worker_updated_v3.js) |
| 旧版说明 | [README.v3.md](archive/legacy-workers/README.v3.md) | 原 README 的完整归档 |

保留它们用于版本比较、历史行为追溯和迁移参考。当前发布流程从 `src/index.ts` 与 `ui/` 构建，不部署这些旧文件。源码归档也不等于删除云端旧 Worker / KV，或恢复旧入口写入。

旧说明中“最新正式版”“推荐部署”等表述只代表归档时的历史语境。**当前用法以本 README、现行 API 契约及运行代码为准。** 归档来源、文件摘要与保护规则见 [归档说明](archive/legacy-workers/README.md)。

## 常见问题

| 问题 | 说明 |
| --- | --- |
| 应该部署哪个 JS？ | 当前系统使用 `src/index.ts` 与构建后的前端；三个根目录 JS 都是历史文件 |
| 为什么同一个长链接生成不同短链？ | 新系统不按长链接去重；机器重试可使用幂等键 |
| 两个域名生成的短码可以互通吗？ | 同一映射可由所有有效公共域名前缀解析，停用某个域名不等于删除映射 |
| API 返回 403？ | 区分边缘 WAF、错误入口、Token 域名权限等原因，先检查响应与调用出口 IP |
| 旧 `/api/v1/link` 还能继续用吗？ | 新系统不兼容旧接口，请改用 `/api/shorten` 和新业务 Token |
| 测试域名无法创建或跳转？ | 测试业务已停用，请使用两个正式公共域名 |
| D1 名称为什么仍带 `test`？ | 保留原数据库与数据的历史名称，运行环境由正式配置决定 |
| 域名登记后为什么还不可用？ | 需要真实绑定、独立只读凭据核验及启用；后台登记不会自动创建 DNS 或绑定 |
| `npm run dev` 后验证码 / API 不可用？ | Vite 仅提供前端，完整后端依赖不由该命令启动 |
| PR 合并后页面为什么没更新？ | 生产发布是单独的手动 Actions，合并成功不等于部署完成 |

## 文档与贡献

| 文档 | 阅读内容 |
| --- | --- |
| [API 契约](docs/API_CONTRACT.md) | 新业务 API、匿名接口、管理员接口与错误码 |
| [正式环境运维](docs/OPERATIONS.md) | 发布、入口安全、备份和迁移流程 |
| [配置说明](docs/CONFIGURATION.md) | 当前正式配置及明确标注的历史初始化快照 |
| [产品需求与演进记录](docs/REFACTOR_REQUIREMENTS.md) | 需求背景与各阶段约定 |
| [历史版本归档](archive/legacy-workers/README.md) | 旧源码、旧文档和原文保护 |
| [协作约定](AGENTS.md) | 变更范围、Git 流程与资源保护 |

欢迎通过 [Issues](https://github.com/jacklilyhello/cloudflare-workers-shortlink/issues) 提交问题与建议。反馈时附上复现步骤、浏览器环境和脱敏后的错误信息，不提交 Token、原始访问日志或私有备份。

提交修改前阅读协作约定，通过任务分支与 PR 交付，并保留现有安全边界与 CI。若项目对你有帮助，欢迎点一个 Star。

## 许可证

项目代码与原创仓库文档采用 **[MIT License](LICENSE)**。第三方依赖、品牌和服务名称遵循各自的许可与权利约定。
