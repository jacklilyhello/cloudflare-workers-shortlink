#!/usr/bin/env node
// A generic local token may be examined only at Account verify and its own policy.
// This never authorizes or issues resource reads, writes, OAuth fallback, or token discovery.
import { pathToFileURL } from 'node:url';
import { EXPECTED, SafeError, createClient } from './preflight-readonly.mjs';

export function qualifyPolicy(policy) {
  const projectName =
    typeof policy?.name === 'string' &&
    /shortlink|short-link/i.test(policy.name) &&
    /read[ _-]?only/i.test(policy.name);
  const allowed = Array.isArray(policy?.policies)
    ? policy.policies.filter((p) => p.effect === 'allow')
    : [];
  const permissions = allowed.flatMap((p) => (p.permission_groups || []).map((g) => g.name));
  const writes = permissions.filter(
    (n) => typeof n === 'string' && /\b(write|edit|delete|purge|revoke|manage|create)\b/i.test(n),
  );
  const unclassified = permissions.filter((n) => typeof n !== 'string' || !/\bread\b/i.test(n));
  const allRead =
    permissions.length > 0 &&
    permissions.every((n) => typeof n === 'string' && /\bread\b/i.test(n)) &&
    writes.length === 0;
  const scopeKeys = allowed.flatMap((p) => Object.keys(p.resources || {}));
  const known = new Set([
    `com.cloudflare.api.account.${EXPECTED.CLOUDFLARE_ACCOUNT_ID}`,
    `com.cloudflare.api.account.zone.${EXPECTED.CF_ZONE_ID_GFW_MOM}`,
    `com.cloudflare.api.account.zone.${EXPECTED.CF_ZONE_ID_GFW_LAT}`,
    `com.cloudflare.api.account.zone.${EXPECTED.CF_ZONE_ID_LILY_LAT}`,
  ]);
  const scopeProven =
    scopeKeys.length > 0 &&
    scopeKeys.every((k) => known.has(k)) &&
    allowed.every((p) => Object.values(p.resources || {}).every((v) => v === '*'));
  return {
    result: projectName && allRead && scopeProven ? 'READONLY_QUALIFIED' : 'PENDING',
    project_readonly_name: projectName,
    read_only_permissions: allRead,
    fixed_project_scope: scopeProven,
    allow_permission_count: permissions.length,
    write_permission_names: writes,
    unclassified_permission_names: unclassified.map((n) => (typeof n === 'string' ? n : 'unknown')),
    detail:
      projectName && allRead && scopeProven
        ? 'Account Token 自身名称、只读权限及资源范围符合本项目；本脚本未读取项目资源。'
        : '来源或权限证明不足；请仅确认安全来源/用途，无需发送明文。未读取项目资源。',
  };
}

export async function main(env = process.env, fetcher = fetch) {
  const token = env.CLOUDFLARE_API_TOKEN;
  if (!token)
    return {
      result: 'PENDING',
      source: 'env:CLOUDFLARE_API_TOKEN',
      detail: '变量未配置；未请求 Cloudflare。',
    };
  if (env.CLOUDFLARE_ACCOUNT_ID && env.CLOUDFLARE_ACCOUNT_ID !== EXPECTED.CLOUDFLARE_ACCOUNT_ID)
    throw new SafeError('CONFIG_MISMATCH');
  if (/\s/.test(token) || token.length > 4096) throw new SafeError('INVALID_CREDENTIAL_FORMAT');
  const call = createClient(EXPECTED, token, fetcher);
  const verified = await call('verify');
  if (verified.result?.status !== 'active')
    return { result: 'AUTH_FAILED', detail: 'Token 不处于 active 状态；未读取项目资源。' };
  const policy = await call('policy', verified.result.id);
  return {
    source: 'env:CLOUDFLARE_API_TOKEN (self verification only)',
    time: new Date().toISOString(),
    ...qualifyPolicy(policy.result),
    requests: ['Account Token verify GET', 'verified Token own policy GET'],
    unverified: 'GH 部署 Secret 的值和权限、项目资源读取能力及写权限均未实测。',
  };
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const result = await main();
    console.log(JSON.stringify(result, null, 2));
    process.exitCode = result.result === 'READONLY_QUALIFIED' ? 0 : 2;
  } catch (error) {
    console.error(
      JSON.stringify({
        result: error instanceof SafeError ? error.kind : 'INTERNAL_ERROR',
        http_status: error instanceof SafeError ? error.status : null,
        detail: '原始异常/响应/凭据已隐藏；未访问项目资源。',
      }),
    );
    process.exitCode = 2;
  }
}
