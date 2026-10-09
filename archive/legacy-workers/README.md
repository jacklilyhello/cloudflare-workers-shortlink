# 历史 Worker 归档

本目录保存迁移前的三个单文件 Worker 及旧版 README。它们是历史参考，不是当前生产部署入口；当前系统请阅读[仓库首页](../../README.md)与[新 API 契约](../../docs/API_CONTRACT.md)。

## 保留范围

| 文件 | 用途 | 保留方式 |
| --- | --- | --- |
| [worker_updated.js](worker_updated.js) | v1 历史源码 | 本目录副本与[根目录原文件](../../worker_updated.js)逐字节一致 |
| [worker_updated_v2.js](worker_updated_v2.js) | v2 历史源码 | 本目录副本与[根目录原文件](../../worker_updated_v2.js)逐字节一致 |
| [worker_updated_v3.js](worker_updated_v3.js) | 迁移前 v3 源码 | 本目录副本与[根目录原文件](../../worker_updated_v3.js)逐字节一致 |
| [README.v3.md](README.v3.md) | 重写前 README 原文 | 完整保留旧说明，不修改其历史表述 |

根目录三个 JS 不移动、不删除、不改写。本目录不参与当前 Worker 的构建和部署，也不用于存放数据库导出、业务 Token 或备份对象。云端旧 Worker `short-link` 与 `LINKS` KV 的保留是独立的运维安排，源码归档不会更改这些资源。

## 来源与完整性

归档取自重写前的 main 提交 [`5029e601e61ff1fce74a7416766fc3bc6ce069e9`](https://github.com/jacklilyhello/cloudflare-workers-shortlink/commit/5029e601e61ff1fce74a7416766fc3bc6ce069e9)，归档副本直接复用相同 Git blob。

以下为 **Git blob 对象 ID（SHA-1）**，不是文件内容的普通 SHA-1 或 SHA-256：

| 文件 | Git blob ID |
| --- | --- |
| `worker_updated.js` | `cf9a0b9f58babeec66437ed71bed7836db38c9c1` |
| `worker_updated_v2.js` | `e3423558d68b3e9825d47a11e96230614fde76cf` |
| `worker_updated_v3.js` | `8185edad2240dcc562db9abaebb0671023c699fa` |
| `README.v3.md` | `93ea7c8324538880d66f6c478a597b887ef30b73` |

[`scripts/check-initialization.mjs`](../../scripts/check-initialization.mjs) 继续使用原始基线 `4eb246fb41d5f15fd8262cfda84cbe930fa37b3c` 比较根目录三个 JS、三个归档副本、旧 README 归档、原 `CODEX_HANDOFF.md` 和 `LICENSE` 的字节。新的根 README 可以维护，历史原文保护继续保留。

## 阅读旧文档时

旧 README 中的“最新正式版”“推荐部署”、KV 去重、密码验证、`/api/v1/link` 及旧配置均描述当时版本，不能当作新系统的部署或 API 指南。

归档源码是历史仓库快照，不等同于正式切换时加装只读入口保护后的云端旧 Worker。不要直接重新部署这些文件来恢复旧入口写入。当前运行入口是 `src/index.ts`，数据位于 D1，详细说明见[正式环境运维](../../docs/OPERATIONS.md)。
