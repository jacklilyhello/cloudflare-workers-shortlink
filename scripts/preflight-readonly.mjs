#!/usr/bin/env node
// Initialization only. No SDK, OAuth fallback, writes, dynamic endpoints or arbitrary queries.
import { execFileSync } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

export const REPOSITORY = 'jacklilyhello/cloudflare-workers-shortlink';
// Non-secret, fixed project scope and authorized administrator set. Drift requires review.
export const EXPECTED = Object.freeze({
  CLOUDFLARE_ACCOUNT_ID: '9431815bdb8beb2272f6668e06b7d3be',
  CF_ZONE_ID_GFW_MOM: 'c145387704a24150f2e5a897ae947156',
  CF_ZONE_ID_LILY_LAT: '9c2a663ae602ff4ac1a73e97a98f2bf1',
  WORKER_NAME: 'shortlink-new',
  LEGACY_WORKER_NAME: 'short-link',
  LEGACY_KV_NAMESPACE_ID: '5fad543837b4409898805eab154b5b84',
  PUBLIC_HOSTNAME: 'test.gfw.mom',
  ADMIN_HOSTNAME: 'link-admin.lily.lat',
  APP_ENV: 'test',
  ADMIN_EMAILS: 'lilyyaloveyou@gmail.com,admin@888888.mom,moshaoli688@gmail.com',
  CF_ACCESS_TEAM_DOMAIN: 'lilyya.cloudflareaccess.com',
  TURNSTILE_SITE_KEY: '0x4AAAAAACH8Z3i_zCB8ztZd',
});
export const SECRET_NAMES = Object.freeze([
  'CLOUDFLARE_API_TOKEN',
  'CF_ANALYTICS_READ_TOKEN',
  'TURNSTILE_SECRET_KEY',
]);
const API = 'https://api.cloudflare.com/client/v4';
const MAX_RESPONSE = 2 * 1024 * 1024;
const MAX_PAGES = 3;
const MAX_ATTEMPTS = 2;
const TIMEOUT_MS = 12000;
const CF_ITEMS = [
  'token.verify',
  'token.policy',
  'zone.gfw.mom',
  'zone.lily.lat',
  'worker.legacy',
  'kv.read',
  'workers.subdomain',
  'worker.new',
  'dns.public',
  'dns.admin',
  'routes.public',
  'routes.admin',
  'domains.public',
  'domains.admin',
  'd1.read',
  'r2.read',
  'access.organization',
  'access.applications',
  'access.policies',
  'access.otp',
  'analytics.read',
];

export class SafeError extends Error {
  constructor(kind, status = null, codes = []) {
    super(kind);
    this.kind = kind;
    this.status = status;
    this.codes = codes;
  }
}
const entry = (item, credential, scope, result, detail, unverified = '', extra = {}) => ({
  item,
  credential,
  scope,
  result,
  detail,
  time: new Date().toISOString(),
  unverified,
  ...extra,
});
const safeFailure = (item, credential, scope, error) =>
  entry(
    item,
    credential,
    scope,
    error instanceof SafeError ? error.kind : 'INTERNAL_ERROR',
    '未输出原始错误/响应；请根据分类复核。',
    '该项未通过实测',
    {
      http_status: error instanceof SafeError ? error.status : null,
      cf_error_codes: error instanceof SafeError ? error.codes : [],
    },
  );

export function validateVariables(values) {
  return Object.entries(EXPECTED).map(([name, expected]) => {
    const value = values[name];
    let reason = '';
    if (typeof value !== 'string' || value.length === 0) reason = '变量缺失或为空';
    else if (value !== value.trim() || /[\r\n\0]/.test(value))
      reason = '含首尾空白、换行或控制字符';
    else if (value !== expected) reason = '与已核验项目范围/预期不一致，先审阅，不自动覆盖';
    return {
      name,
      ok: !reason,
      reason: reason || '与现场基线相符；CF 资源归属/Secret 配对另行核验',
    };
  });
}

// Reads only an explicit project readonly source. Generic CF tokens are never consumed.
export function loadCredential(env = process.env) {
  const value = env.CLOUDFLARE_READONLY_API_TOKEN;
  const file = env.CLOUDFLARE_READONLY_TOKEN_FILE;
  if (value && file) throw new SafeError('AMBIGUOUS_CREDENTIAL_SOURCE');
  let token = value;
  let source = 'env:CLOUDFLARE_READONLY_API_TOKEN';
  if (file) {
    try {
      const info = statSync(file);
      if (!info.isFile() || info.size > 4096 || (info.mode & 0o077) !== 0)
        throw new SafeError('UNSAFE_CREDENTIAL_FILE');
      token = readFileSync(file, 'utf8').trim();
      source = 'file:CLOUDFLARE_READONLY_TOKEN_FILE (path withheld)';
    } catch (error) {
      if (error instanceof SafeError) throw error;
      throw new SafeError('CREDENTIAL_FILE_UNREADABLE');
    }
  }
  if (!token) return null;
  if (token !== token.trim() || /\s/.test(token) || token.length > 4096)
    throw new SafeError('INVALID_CREDENTIAL_FORMAT');
  return { token, source };
}

function gh(path) {
  // No shell, fixed repository and hostname. Never run `gh auth token` or print stderr.
  try {
    return JSON.parse(
      execFileSync('gh', ['api', '--hostname', 'github.com', `repos/${REPOSITORY}/${path}`], {
        encoding: 'utf8',
        timeout: 20000,
        maxBuffer: MAX_RESPONSE,
        stdio: ['ignore', 'pipe', 'pipe'],
      }),
    );
  } catch (error) {
    const stderr = String(error.stderr || '');
    if (error.code === 'ENOENT') throw new SafeError('GH_TOOL_MISSING');
    if (/401|Bad credentials/.test(stderr)) throw new SafeError('AUTH_FAILED', 401);
    if (/403|Resource not accessible/.test(stderr)) throw new SafeError('PERMISSION_DENIED', 403);
    if (/429|rate limit/i.test(stderr)) throw new SafeError('RATE_LIMITED', 429);
    if (/404/.test(stderr)) throw new SafeError('GH_ACCESS_OR_NOT_FOUND', 404);
    if (/connect|lookup|network|timeout/i.test(stderr) || error.code === 'ETIMEDOUT')
      throw new SafeError('NETWORK');
    throw new SafeError('GH_QUERY_FAILED');
  }
}
export function checkGitHub(query = gh) {
  const rows = [];
  let variables = {};
  for (const [type, arrayName] of [
    ['variables', 'variables'],
    ['secrets', 'secrets'],
  ]) {
    try {
      const response = query(`actions/${type}?per_page=100&page=1`);
      if (!Array.isArray(response[arrayName]) || !Number.isInteger(response.total_count))
        throw new SafeError('INVALID_RESPONSE');
      const complete = response[arrayName].length === response.total_count;
      if (type === 'variables') {
        variables = Object.fromEntries(response.variables.map((v) => [v.name, v.value]));
        rows.push(
          entry(
            'github.variables.list',
            'existing gh login',
            REPOSITORY,
            complete ? 'PASS' : 'PARTIAL',
            `读取 ${response.variables.length} 个变量；只请求一页，上限 100`,
            complete ? '' : '分页未完成，不能判断缺失',
          ),
        );
        for (const check of validateVariables(variables))
          rows.push(
            entry(
              `github.variable.${check.name}`,
              'existing gh login',
              REPOSITORY,
              check.ok ? 'PASS' : complete ? 'CONFIG_MISMATCH' : 'PARTIAL',
              check.reason,
            ),
          );
        rows.push(
          entry(
            'github.variables.extra',
            'existing gh login',
            REPOSITORY,
            'INFO',
            `额外名称：${
              Object.keys(variables)
                .filter((n) => !(n in EXPECTED))
                .join(', ') || '无'
            }；不修改或删除`,
          ),
        );
      } else {
        const names = response.secrets.map((s) => s.name);
        for (const name of SECRET_NAMES)
          rows.push(
            entry(
              `github.secret.${name}`,
              'existing gh login',
              REPOSITORY,
              names.includes(name) ? 'EXISTS_NAME_ONLY' : complete ? 'ABSENT_NAME' : 'PARTIAL',
              names.includes(name)
                ? '仅确认名称存在'
                : complete
                  ? '列表成功，未找到此名称'
                  : '列表不完整',
              '值、配对、有效性和权限均未实测',
            ),
          );
        rows.push(
          entry(
            'github.secrets.extra',
            'existing gh login',
            REPOSITORY,
            'INFO',
            `额外名称：${names.filter((n) => !SECRET_NAMES.includes(n)).join(', ') || '无'}；不修改或删除`,
          ),
        );
      }
    } catch (error) {
      rows.push(safeFailure(`github.${type}`, 'existing gh login', REPOSITORY, error));
    }
  }
  for (const [item, endpoint, summarize] of [
    [
      'permissions',
      'actions/permissions',
      (x) => ({
        enabled: x.enabled,
        allowed_actions: x.allowed_actions,
        sha_pinning_required: x.sha_pinning_required,
      }),
    ],
    [
      'workflow_permissions',
      'actions/permissions/workflow',
      (x) => ({
        default_workflow_permissions: x.default_workflow_permissions,
        can_approve_pull_request_reviews: x.can_approve_pull_request_reviews,
      }),
    ],
    [
      'workflows',
      'actions/workflows?per_page=100&page=1',
      (x) => ({ total_count: x.total_count, retrieved: x.workflows?.length }),
    ],
  ]) {
    try {
      rows.push(
        entry(
          `github.${item}`,
          'existing gh login',
          REPOSITORY,
          'PASS',
          JSON.stringify(summarize(query(endpoint))),
        ),
      );
    } catch (error) {
      rows.push(safeFailure(`github.${item}`, 'existing gh login', REPOSITORY, error));
    }
  }
  return { variables, rows };
}

// Only these constructors can produce authenticated requests; no CLI endpoint parameter.
export function buildRequest(kind, c, arg = '') {
  if (validateVariables(c).some((x) => !x.ok)) throw new SafeError('CONFIG_MISMATCH');
  const a = `/accounts/${c.CLOUDFLARE_ACCOUNT_ID}`;
  const z = (id) => `/zones/${id}`;
  const hostname = (which) => (which === 'public' ? c.PUBLIC_HOSTNAME : c.ADMIN_HOSTNAME);
  const zone = (which) => (which === 'public' ? c.CF_ZONE_ID_GFW_MOM : c.CF_ZONE_ID_LILY_LAT);
  let path;
  let params = {};
  let body;
  switch (kind) {
    case 'verify':
      path = `${a}/tokens/verify`;
      break;
    case 'policy':
      if (!/^[a-f0-9]{32}$/i.test(arg)) throw new SafeError('INVALID_RESOURCE_ID');
      path = `${a}/tokens/${arg}`;
      break;
    case 'zone-public':
      path = z(c.CF_ZONE_ID_GFW_MOM);
      break;
    case 'zone-admin':
      path = z(c.CF_ZONE_ID_LILY_LAT);
      break;
    case 'legacy':
      path = `${a}/workers/scripts/${c.LEGACY_WORKER_NAME}/settings`;
      break;
    case 'new':
      path = `${a}/workers/scripts/${c.WORKER_NAME}/settings`;
      break;
    case 'subdomain':
      path = `${a}/workers/subdomain`;
      break;
    case 'keys':
      path = `${a}/storage/kv/namespaces/${c.LEGACY_KV_NAMESPACE_ID}/keys`;
      params = { limit: 10 };
      break;
    case 'value':
      // arg must be one key returned by the bounded keys request, checked by caller.
      if (
        typeof arg !== 'string' ||
        !arg ||
        ['.', '..'].includes(arg) ||
        new TextEncoder().encode(arg).length > 512 ||
        /[\r\n\0]/.test(arg)
      )
        throw new SafeError('INVALID_KV_KEY');
      path = `${a}/storage/kv/namespaces/${c.LEGACY_KV_NAMESPACE_ID}/values/${encodeURIComponent(arg).replace(/\./g, '%2E')}`;
      break;
    case 'dns-public':
    case 'dns-admin': {
      const which = kind.slice(4);
      path = `${z(zone(which))}/dns_records`;
      params = { name: hostname(which), per_page: 10, page: 1 };
      break;
    }
    case 'routes-public':
    case 'routes-admin':
      path = `${z(zone(kind.slice(7)))}/workers/routes`;
      break;
    case 'domains-public':
    case 'domains-admin':
      path = `${a}/workers/domains`;
      params = { hostname: hostname(kind.slice(8)) };
      break;
    case 'd1':
      path = `${a}/d1/database`;
      params = { name: c.WORKER_NAME, per_page: 10, page: 1 };
      break;
    case 'r2':
      path = `${a}/r2/buckets`;
      params = { name_contains: c.WORKER_NAME, per_page: 10 };
      break;
    case 'organization':
      path = `${a}/access/organizations`;
      break;
    case 'apps':
      path = `${a}/access/apps`;
      params = { domain: c.ADMIN_HOSTNAME, exact: false, per_page: 20, page: 1 };
      break;
    case 'policies':
      if (!/^[a-f0-9-]{32,36}$/i.test(arg)) throw new SafeError('INVALID_RESOURCE_ID');
      path = `${a}/access/apps/${arg}/policies`;
      params = { per_page: 20, page: 1 };
      break;
    case 'idps':
      path = `${a}/access/identity_providers`;
      break;
    case 'analytics': {
      path = '/graphql';
      const end = new Date();
      const start = new Date(end.getTime() - 15 * 60 * 1000);
      body = JSON.stringify({
        query: `query InitReadonly($accountTag: string, $scriptName: string, $start: string, $end: string) {
        viewer { accounts(filter: {accountTag: $accountTag}) {
          workersInvocationsAdaptive(limit: 1, filter: {scriptName: $scriptName, datetime_geq: $start, datetime_leq: $end}) { sum { requests } }
        } }
      }`,
        variables: {
          accountTag: c.CLOUDFLARE_ACCOUNT_ID,
          scriptName: c.WORKER_NAME,
          start: start.toISOString(),
          end: end.toISOString(),
        },
      });
      break;
    }
    default:
      throw new SafeError('ENDPOINT_NOT_ALLOWED');
  }
  const url = new URL(`${API}${path}`);
  for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
  if (url.origin !== 'https://api.cloudflare.com' || !url.pathname.startsWith('/client/v4/'))
    throw new SafeError('ENDPOINT_NOT_ALLOWED');
  return { url: url.href, method: body ? 'POST' : 'GET', body, kind };
}
async function boundedBody(response) {
  if (Number(response.headers.get('content-length')) > MAX_RESPONSE)
    throw new SafeError('RESPONSE_TOO_LARGE');
  if (!response.body) throw new SafeError('INVALID_RESPONSE');
  const reader = response.body.getReader();
  const chunks = [];
  let bytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > MAX_RESPONSE) throw new SafeError('RESPONSE_TOO_LARGE');
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  return Buffer.concat(chunks).toString('utf8');
}
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
export function createClient(config, token, fetcher = fetch, sleeper = delay) {
  return async (kind, arg = '') => {
    const request = buildRequest(kind, config, arg);
    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
      let response;
      let raw;
      try {
        response = await fetcher(request.url, {
          method: request.method,
          redirect: 'error',
          headers: {
            Authorization: `Bearer ${token}`,
            Accept: 'application/json',
            ...(request.body ? { 'Content-Type': 'application/json' } : {}),
          },
          ...(request.body ? { body: request.body } : {}),
          signal: AbortSignal.timeout(TIMEOUT_MS),
        });
        if (response.headers.get('cf-mitigated') === 'challenge') {
          await response.body?.cancel();
          throw new SafeError('CLOUDFLARE_CHALLENGE', response.status);
        }
        // Retry only transient statuses, once, at most two seconds; never auth/permission errors.
        if ((response.status === 429 || response.status >= 500) && attempt + 1 < MAX_ATTEMPTS) {
          await response.body?.cancel();
          await sleeper(1000);
          continue;
        }
        raw = await boundedBody(response);
      } catch (error) {
        if (error instanceof SafeError) throw error;
        // fetch uses redirect:error; never forwards authentication to the redirect location.
        if (attempt + 1 < MAX_ATTEMPTS) {
          await sleeper(1000);
          continue;
        }
        throw new SafeError('NETWORK_OR_REDIRECT_BLOCKED');
      }
      if (response.status >= 300 && response.status < 400)
        throw new SafeError('REDIRECT_BLOCKED', response.status);
      let payload;
      if (kind === 'value' && response.ok) return raw; // kept only in memory, summarized by caller
      try {
        payload = JSON.parse(raw);
      } catch {
        const kind =
          response.status === 401
            ? 'AUTH_FAILED'
            : response.status === 403
              ? 'PERMISSION_DENIED'
              : response.status === 429
                ? 'RATE_LIMITED'
                : 'NON_JSON_RESPONSE';
        throw new SafeError(kind, response.status);
      }
      const codes = (Array.isArray(payload.errors) ? payload.errors : [])
        .map((e) => e.code)
        .filter(Number.isInteger)
        .slice(0, 5);
      if (!response.ok || payload.success === false) {
        const status = response.status;
        const result =
          status === 401
            ? 'AUTH_FAILED'
            : status === 403
              ? 'PERMISSION_DENIED'
              : status === 404
                ? 'NOT_FOUND_UNCONFIRMED'
                : status === 429
                  ? 'RATE_LIMITED'
                  : codes.includes(10000)
                    ? 'AUTH_OR_SCOPE_DENIED'
                    : 'REMOTE_ERROR';
        throw new SafeError(result, status, codes);
      }
      if (kind === 'analytics') {
        if (payload.errors?.length)
          throw new SafeError('GRAPHQL_QUERY_DENIED_OR_UNSUPPORTED', response.status);
        if (
          !Array.isArray(payload.data?.viewer?.accounts) ||
          !payload.data.viewer.accounts.length ||
          !Array.isArray(payload.data.viewer.accounts[0].workersInvocationsAdaptive)
        )
          throw new SafeError('INVALID_RESPONSE');
      } else if (payload.success !== true || !Object.hasOwn(payload, 'result'))
        throw new SafeError('INVALID_RESPONSE');
      return payload;
    }
    throw new SafeError('INTERNAL_ERROR');
  };
}

export function summarizeKeys(keys) {
  if (!Array.isArray(keys)) throw new SafeError('INVALID_RESPONSE');
  return {
    sampled_keys: keys.length,
    hash_index_candidates: keys.filter((k) => /^[a-f0-9]{128}$/i.test(k.name || '')).length,
    system_keys: keys.filter((k) => String(k.name).startsWith('SYS_CONFIG_')).length,
    other_keys: keys.filter(
      (k) => !/^[a-f0-9]{128}$/i.test(k.name || '') && !String(k.name).startsWith('SYS_CONFIG_'),
    ).length,
    with_createdAt_metadata: keys.filter(
      (k) => k.metadata && Object.hasOwn(k.metadata, 'createdAt'),
    ).length,
    with_expiration: keys.filter((k) => k.expiration !== undefined).length,
  };
}
export function summarizeValue(value) {
  let kind = 'other';
  try {
    const parsed = new URL(value);
    if (['http:', 'https:'].includes(parsed.protocol)) kind = 'http_url_string';
  } catch {
    /* classify without printing */
  }
  if (kind === 'other' && /^[A-Za-z0-9_-]+$/.test(value)) kind = 'slug_candidate_string';
  return { kind, bytes: new TextEncoder().encode(value).length };
}
export function summarizePolicy(policy) {
  if (!Array.isArray(policy.policies)) return { reviewed: false };
  const names = policy.policies
    .filter((p) => p.effect === 'allow')
    .flatMap((p) => (p.permission_groups || []).map((g) => g.name || 'unknown'));
  const write = names.filter((n) =>
    /\b(?:write|edit|delete|revoke|purge|manage|create)\b/i.test(n),
  );
  const unknown = names.filter((n) => !/read/i.test(n) && !write.includes(n));
  return {
    reviewed: true,
    allow_permission_names: names,
    write_permission_names: write,
    unclassified_permission_names: unknown,
    resource_scope_reviewed: false,
  };
}
function routeMatches(pattern, host) {
  const withoutScheme = String(pattern).replace(/^https?:\/\//, '');
  const routeHost = withoutScheme.split('/')[0];
  const escaped = routeHost.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`, 'i').test(host);
}
function listResult(payload) {
  if (!Array.isArray(payload.result)) throw new SafeError('INVALID_RESPONSE');
  return payload.result;
}
function truncated(payload, count) {
  const info = payload.result_info || {};
  return Boolean(info.cursor || info.total_pages > 1 || info.total_count > count);
}

export async function checkCloudflare(config, credential, { sampleKV = false, request } = {}) {
  const rows = [];
  const source = credential?.source || '未找到明确的本项目只读凭据';
  if (!credential || validateVariables(config).some((x) => !x.ok)) {
    const reason = !credential
      ? '未发出 CF 请求；通用 Token 没有自动回退'
      : 'GH 配置不完整或漂移，未发出 CF 请求';
    return CF_ITEMS.map((item) => entry(item, source, REPOSITORY, 'PENDING', reason, '未实测'));
  }
  const call = request || createClient(config, credential.token);
  const scope = `account:${config.CLOUDFLARE_ACCOUNT_ID}`;
  const run = async (item, kind, summarize, arg = '') => {
    try {
      const response = await call(kind, arg);
      const summary = summarize(response);
      rows.push(
        entry(
          item,
          source,
          scope,
          summary.result || 'PASS',
          summary.detail,
          summary.unverified || '',
        ),
      );
      return response;
    } catch (error) {
      rows.push(safeFailure(item, source, scope, error));
      return null;
    }
  };
  const verified = await run('token.verify', 'verify', (x) => ({
    result: x.result?.status === 'active' ? 'PASS' : 'AUTH_FAILED',
    detail: `Account Token 状态：${x.result?.status === 'active' ? 'active' : '非 active/未知'}`,
    unverified: 'active 只证明活跃，不证明全部权限',
  }));
  if (!verified || verified.result?.status !== 'active') {
    for (const item of CF_ITEMS.slice(1))
      rows.push(entry(item, source, scope, 'PENDING', 'Token 验证未通过，停止后续请求', '未实测'));
    return rows;
  }
  await run(
    'token.policy',
    'policy',
    (x) => {
      const s = summarizePolicy(x.result);
      return {
        result:
          !s.reviewed || s.unclassified_permission_names.length
            ? 'PARTIAL'
            : s.write_permission_names.length
              ? 'WRITE_PERMISSION_OBSERVED'
              : 'READ_NAMES_ONLY',
        detail: JSON.stringify(s),
        unverified: '未执行任何写入；策略资源条件/权限上限仍需人工审阅；不证明部署 Secret 来源',
      };
    },
    verified.result.id,
  );
  let zonesMatch = true;
  for (const [which, name] of [
    ['public', 'gfw.mom'],
    ['admin', 'lily.lat'],
  ]) {
    const p = await run(`zone.${name}`, `zone-${which}`, (x) => {
      const match =
        x.result?.name === name && x.result?.account?.id === config.CLOUDFLARE_ACCOUNT_ID;
      if (!match) zonesMatch = false;
      return {
        result: match ? 'PASS' : 'CONFIG_MISMATCH',
        detail: match ? `${name} 名称和账户匹配` : '名称或账户不匹配；停止该账户资源核验',
      };
    });
    if (!p) zonesMatch = false;
  }
  if (!zonesMatch) {
    for (const item of CF_ITEMS.slice(4))
      rows.push(
        entry(item, source, scope, 'PENDING', '两 Zone 归属未通过，停止后续资源请求', '未实测'),
      );
    return rows;
  }
  const legacy = await run('worker.legacy', 'legacy', (x) => {
    const binding = x.result?.bindings?.find(
      (b) => b.name === 'LINKS' && b.type === 'kv_namespace',
    );
    return {
      result: binding?.namespace_id === config.LEGACY_KV_NAMESPACE_ID ? 'PASS' : 'CONFIG_MISMATCH',
      detail: `只检查 LINKS/KV 类型及 namespace_id 是否匹配；不输出其他绑定或变量`,
    };
  });
  const bindingMatches = legacy?.result?.bindings?.some(
    (b) =>
      b.name === 'LINKS' &&
      b.type === 'kv_namespace' &&
      b.namespace_id === config.LEGACY_KV_NAMESPACE_ID,
  );
  let keys;
  if (bindingMatches) {
    keys = await run('kv.read', 'keys', (x) => ({
      detail: JSON.stringify(summarizeKeys(x.result)),
      unverified: '一页最多 10 个 key；非全量数据、一致性快照或值读取证明',
    }));
    if (sampleKV && keys) {
      for (const key of listResult(keys)
        .filter((k) => !String(k.name).startsWith('SYS_CONFIG_'))
        .slice(0, 2)) {
        await run(
          'kv.sample.structure',
          'value',
          (value) => ({
            detail: JSON.stringify(summarizeValue(value)),
            unverified: '仅结构分类；不保存 key/URL/原始值，不证明全部格式',
          }),
          key.name,
        );
      }
    } else
      rows.push(
        entry(
          'kv.value.read',
          source,
          scope,
          'PENDING',
          '未启用 --sample-kv；默认不读取业务值',
          '值读取权限未实测',
        ),
      );
  } else
    rows.push(
      entry(
        'kv.read',
        source,
        scope,
        'PENDING',
        'LINKS 绑定未核实，不读取猜测的 namespace',
        '未实测',
      ),
    );
  await run('workers.subdomain', 'subdomain', (x) => {
    if (!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(x.result?.subdomain || ''))
      throw new SafeError('INVALID_RESPONSE');
    return {
      detail: `候选 https://${config.WORKER_NAME}.${x.result.subdomain}.workers.dev`,
      unverified: '账户子域名已读取，候选不等于已部署地址',
    };
  });
  await run('worker.new', 'new', (x) => ({
    result: 'EXISTS_REVIEW_REQUIRED',
    detail: '新 Worker 名称已有资源；不覆盖，仅核验是否属于本项目',
    unverified: '未证明可部署或资源归属',
  }));
  for (const which of ['public', 'admin']) {
    const host = which === 'public' ? config.PUBLIC_HOSTNAME : config.ADMIN_HOSTNAME;
    await run(`dns.${which}`, `dns-${which}`, (x) => {
      const records = listResult(x).filter((r) => r.name === host);
      return {
        result: records.length
          ? 'OCCUPIED_REVIEW_REQUIRED'
          : truncated(x, listResult(x).length)
            ? 'PARTIAL'
            : 'ABSENT',
        detail: `${host} 精确匹配 DNS 数量 ${records.length}；不输出内容或其他记录`,
        unverified: '不能据此证明无 wildcard DNS 或其他产品绑定',
      };
    });
    await run(`routes.${which}`, `routes-${which}`, (x) => {
      const matches = listResult(x).filter((r) => routeMatches(r.pattern, host));
      return {
        result: matches.length
          ? 'OCCUPIED_REVIEW_REQUIRED'
          : truncated(x, listResult(x).length)
            ? 'PARTIAL'
            : 'ABSENT',
        detail: `${host} 的匹配路由数量 ${matches.length}（包括 wildcard host，保守按全部路径）`,
        unverified: '单次 Zone 列表；不保存其他路由；未覆盖产品外绑定',
      };
    });
    await run(`domains.${which}`, `domains-${which}`, (x) => ({
      result: listResult(x).some((d) => d.hostname === host)
        ? 'OCCUPIED_REVIEW_REQUIRED'
        : truncated(x, listResult(x).length)
          ? 'PARTIAL'
          : 'ABSENT',
      detail: `${host} 的 Workers Custom Domain 绑定已按 hostname 过滤查询`,
      unverified: '不证明 Pages/其他产品或 wildcard 绑定不存在',
    }));
  }
  await run('d1.read', 'd1', (x) => ({
    result: truncated(x, listResult(x).length) ? 'PARTIAL' : 'PASS',
    detail: `D1 项目名搜索可读取；匹配数 ${listResult(x).filter((d) => d.name?.includes(config.WORKER_NAME)).length}`,
    unverified:
      '只证明列表读取；新 D1 最终名称/ID 未定，空结果不证明数据库已规划或缺失；未执行 SQL',
  }));
  await run('r2.read', 'r2', (x) => {
    if (!Array.isArray(x.result?.buckets)) throw new SafeError('INVALID_RESPONSE');
    return {
      result: truncated(x, x.result.buckets.length) ? 'PARTIAL' : 'PASS',
      detail: `R2 默认 jurisdiction 项目名过滤可读取；匹配数 ${x.result.buckets.filter((b) => b.name?.includes(config.WORKER_NAME)).length}`,
      unverified: '新桶名称未定；不读取其他桶或对象；其他 jurisdiction 未验证',
    };
  });
  await run('access.organization', 'organization', (x) => ({
    result: x.result?.auth_domain === config.CF_ACCESS_TEAM_DOMAIN ? 'PASS' : 'CONFIG_MISMATCH',
    detail: '只对比团队 auth_domain，不输出其他组织配置',
  }));
  const apps = await run('access.applications', 'apps', (x) => ({
    result: listResult(x).length
      ? 'EXISTS_REVIEW_REQUIRED'
      : truncated(x, 0)
        ? 'PARTIAL'
        : 'ABSENT',
    detail: `按后台域名过滤的应用数 ${listResult(x).length}`,
    unverified:
      '过滤查询未覆盖宽域名 wildcard/其他主域的多目的地应用，不能证明后台未被其他应用覆盖',
  }));
  if (apps) {
    const exactApps = listResult(apps)
      .filter((app) => app.domain === config.ADMIN_HOSTNAME)
      .slice(0, MAX_PAGES);
    for (const app of exactApps) {
      rows.push(
        entry(
          'access.aud',
          source,
          config.ADMIN_HOSTNAME,
          typeof app.aud === 'string' && app.aud ? 'OBSERVED' : 'PENDING',
          typeof app.aud === 'string' && app.aud ? `实际 AUD: ${app.aud}` : '应用未提供 AUD',
          '未验证浏览器登录/JWT 流程',
        ),
      );
      await run(
        'access.policies',
        'policies',
        (x) => {
          const policies = listResult(x);
          const emails = policies
            .filter((p) => p.decision === 'allow')
            .flatMap((p) => (p.include || []).map((r) => r.email?.email).filter(Boolean));
          const expected = config.ADMIN_EMAILS.split(',');
          const directMatch =
            expected.every((e) => emails.includes(e)) && emails.every((e) => expected.includes(e));
          return {
            result: 'POLICY_REVIEW_REQUIRED',
            detail: `直接邮箱 allow 条目与三管理员集合相符：${directMatch}；策略数 ${policies.length}`,
            unverified:
              '必须人工复核 bypass/service_auth、everyone/邮箱域、groups、exclude、require 和优先级；简单邮箱比较不证明整体安全',
          };
        },
        app.id,
      );
    }
    if (!exactApps.length)
      rows.push(
        entry(
          'access.policies',
          source,
          config.ADMIN_HOSTNAME,
          'PENDING',
          '没有精确主域匹配应用，未猜测 AUD/策略',
          '应用创建状态和广域覆盖须复核',
        ),
      );
  }
  await run('access.otp', 'idps', (x) => {
    const providers = listResult(x);
    const otp = providers.filter((p) => p.type === 'onetimepin');
    return {
      result: otp.length ? 'OBSERVED' : 'PARTIAL',
      detail: `只统计邮件 OTP 类型 onetimepin；数量 ${otp.length}；不保存 provider config`,
      unverified:
        '未发送 OTP；仍需核验应用 allowed_idps/allow_authenticate_via_warp 等设置，只发现 provider 不等于后台已启用',
    };
  });
  await run('analytics.read', 'analytics', (x) => ({
    detail: `固定新 Worker、最近 15 分钟、limit=1 的 GraphQL 查询通过；返回组数 ${x.data.viewer.accounts[0].workersInvocationsAdaptive.length}`,
    unverified:
      '只证明本地只读凭据对该查询的能力；不验证 GH CF_ANALYTICS_READ_TOKEN 或 Analytics Engine 数据集，不制造数据',
  }));
  rows.push(
    entry(
      'turnstile.management',
      source,
      scope,
      'UNSUPPORTED_ACCOUNT_TOKEN',
      '官方兼容表显示 Account API Token 暂不支持 Turnstile 管理；未尝试或申请 User Token',
      '真实 Widget hostname/Secret 配对与浏览器端到端仍待验证',
    ),
  );
  return rows;
}

export async function main(args = process.argv.slice(2), env = process.env) {
  if (args.some((a) => !['--github-only', '--offline', '--sample-kv'].includes(a)))
    throw new SafeError('UNKNOWN_ARGUMENT');
  if (
    args.includes('--sample-kv') &&
    (args.includes('--offline') || args.includes('--github-only'))
  )
    throw new SafeError('INCOMPATIBLE_ARGUMENTS');
  const report = {
    schema_version: 1,
    repository: REPOSITORY,
    time: new Date().toISOString(),
    limits: {
      attempts: MAX_ATTEMPTS,
      timeout_ms: TIMEOUT_MS,
      cf_list_pages: 1,
      github_list_pages: 1,
      max_policy_apps: MAX_PAGES,
      max_kv_values: 2,
      max_response_bytes: MAX_RESPONSE,
    },
    checks: [],
    conclusion: '本地准备完成，以下验证待补',
  };
  let variables = {};
  if (args.includes('--offline'))
    report.checks.push(
      entry('github', 'none', REPOSITORY, 'PENDING', '离线模式，未查询 GitHub', '未核验现场配置'),
    );
  else {
    const ghResult = checkGitHub();
    variables = ghResult.variables;
    report.checks.push(...ghResult.rows);
  }
  let credential;
  if (!args.includes('--offline') && !args.includes('--github-only')) {
    try {
      credential = loadCredential(env);
    } catch (error) {
      report.checks.push(
        safeFailure('credential.source', 'explicit readonly only', REPOSITORY, error),
      );
    }
  }
  if (env.CLOUDFLARE_ACCOUNT_ID && env.CLOUDFLARE_ACCOUNT_ID !== EXPECTED.CLOUDFLARE_ACCOUNT_ID) {
    report.checks.push(
      entry(
        'credential.account',
        'local environment',
        REPOSITORY,
        'CONFIG_MISMATCH',
        '环境中的账户与项目范围不符，CF 查询停止',
      ),
    );
    credential = null;
  }
  if (args.includes('--offline') || args.includes('--github-only')) credential = null;
  report.checks.push(
    ...(await checkCloudflare(variables, credential, { sampleKV: args.includes('--sample-kv') })),
  );
  // Only fixed summaries above reach stdout. No raw JSON, request headers, Token or business data.
  console.log(JSON.stringify(report, null, 2));
  return report.checks.some(
    (c) => !['PASS', 'INFO', 'EXISTS_NAME_ONLY', 'ABSENT', 'OBSERVED'].includes(c.result),
  )
    ? 2
    : 0;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    process.exitCode = await main();
  } catch (error) {
    console.error(
      JSON.stringify({
        result: error instanceof SafeError ? error.kind : 'INTERNAL_ERROR',
        detail: '已隐藏原始异常与凭据',
      }),
    );
    process.exitCode = 2;
  }
}
