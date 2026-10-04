import { EXPECTED, REPOSITORY } from './preflight-readonly.mjs';

export { EXPECTED, REPOSITORY };
export const ACCOUNT = `/accounts/${EXPECTED.CLOUDFLARE_ACCOUNT_ID}`;
export const ADMIN_ZONE = `/zones/${EXPECTED.CF_ZONE_ID_LILY_LAT}`;
export const PUBLIC_ZONE = `/zones/${EXPECTED.CF_ZONE_ID_GFW_MOM}`;
export const BUCKET = 'shortlink-new-backups';
export const DATABASE = 'shortlink-new-test';
export const OWNER_KEY = 'delivery/ownership.json';
const ENDPOINT_CATEGORIES = new Set([
  'ACCOUNT_TOKEN_VERIFY',
  'ACCOUNT_TOKEN_POLICY',
  'PUBLIC_ZONE_DETAILS',
  'ADMIN_ZONE_DETAILS',
  'LEGACY_WORKER_SETTINGS',
  'NEW_WORKER_SETTINGS',
  'NEW_WORKER_SECRETS',
  'WORKERS_SUBDOMAIN',
  'WORKERS_CUSTOM_DOMAINS',
  'ACCESS_ORGANIZATION',
  'ACCESS_IDENTITY_PROVIDERS',
  'ACCESS_APPLICATIONS',
  'ACCESS_POLICIES',
  'ZONE_BOT_MANAGEMENT',
  'ZONE_SETTINGS',
  'ZONE_RULESETS',
  'ACCOUNT_RULESETS',
  'ZONE_DNS_RECORDS',
  'ZONE_WORKER_ROUTES',
  'D1_DATABASE',
  'D1_QUERY',
  'R2_BUCKETS',
  'R2_OWNERSHIP_MANIFEST',
  'R2_OBJECT',
  'LEGACY_KV_KEYS',
  'LEGACY_KV_VALUE',
  'ACCOUNT_IP_LISTS',
  'CF_API_OTHER',
]);
function endpointCategory(path) {
  // Return only fixed labels. Paths, object keys, IDs and query values never become diagnostic output.
  const relative = typeof path === 'string' ? path.split('?')[0] : '';
  const exact = new Map([
    [`${ACCOUNT}/tokens/verify`, 'ACCOUNT_TOKEN_VERIFY'],
    [PUBLIC_ZONE, 'PUBLIC_ZONE_DETAILS'],
    [ADMIN_ZONE, 'ADMIN_ZONE_DETAILS'],
    [
      `${ACCOUNT}/workers/scripts/${EXPECTED.LEGACY_WORKER_NAME}/settings`,
      'LEGACY_WORKER_SETTINGS',
    ],
    [`${ACCOUNT}/workers/scripts/${EXPECTED.WORKER_NAME}/settings`, 'NEW_WORKER_SETTINGS'],
    [`${ACCOUNT}/workers/scripts/${EXPECTED.WORKER_NAME}/secrets`, 'NEW_WORKER_SECRETS'],
    [`${ACCOUNT}/workers/subdomain`, 'WORKERS_SUBDOMAIN'],
    [`${ACCOUNT}/workers/domains`, 'WORKERS_CUSTOM_DOMAINS'],
    [`${ACCOUNT}/access/organizations`, 'ACCESS_ORGANIZATION'],
    [`${ACCOUNT}/access/identity_providers`, 'ACCESS_IDENTITY_PROVIDERS'],
    [`${ADMIN_ZONE}/bot_management`, 'ZONE_BOT_MANAGEMENT'],
    [`${ADMIN_ZONE}/settings`, 'ZONE_SETTINGS'],
    [`${ACCOUNT}/r2/buckets/${BUCKET}/objects/${OWNER_KEY}`, 'R2_OWNERSHIP_MANIFEST'],
    [`${ACCOUNT}/storage/kv/namespaces/${EXPECTED.LEGACY_KV_NAMESPACE_ID}/keys`, 'LEGACY_KV_KEYS'],
  ]);
  if (exact.has(relative)) return exact.get(relative);
  if (relative.startsWith(`${ACCOUNT}/tokens/`)) return 'ACCOUNT_TOKEN_POLICY';
  if (relative.startsWith(`${ACCOUNT}/access/apps`))
    return relative.endsWith('/policies') ? 'ACCESS_POLICIES' : 'ACCESS_APPLICATIONS';
  if (relative.startsWith(`${ACCOUNT}/rulesets`)) return 'ACCOUNT_RULESETS';
  if (relative.startsWith(`${ACCOUNT}/rules/lists`)) return 'ACCOUNT_IP_LISTS';
  if (relative.startsWith(`${ACCOUNT}/d1/database`))
    return relative.endsWith('/query') ? 'D1_QUERY' : 'D1_DATABASE';
  if (relative.startsWith(`${ACCOUNT}/r2/buckets`))
    return relative.includes('/objects/') ? 'R2_OBJECT' : 'R2_BUCKETS';
  if (
    relative.startsWith(
      `${ACCOUNT}/storage/kv/namespaces/${EXPECTED.LEGACY_KV_NAMESPACE_ID}/values/`,
    )
  )
    return 'LEGACY_KV_VALUE';
  for (const zone of [PUBLIC_ZONE, ADMIN_ZONE]) {
    if (relative.startsWith(`${zone}/rulesets`)) return 'ZONE_RULESETS';
    if (relative.startsWith(`${zone}/dns_records`)) return 'ZONE_DNS_RECORDS';
    if (relative.startsWith(`${zone}/workers/routes`)) return 'ZONE_WORKER_ROUTES';
  }
  return 'CF_API_OTHER';
}
export class DeliveryError extends Error {
  constructor(code, status = null, cfCodes = [], endpoint = null) {
    super(code);
    this.code = code;
    this.status = status;
    this.cfCodes = cfCodes;
    this.endpointCategory = ENDPOINT_CATEGORIES.has(endpoint) ? endpoint : null;
    this.requestMethod = null;
  }
}
export const fail = (code) => {
  throw new DeliveryError(code);
};
export const ensure = (condition, code) => {
  if (!condition) fail(code);
};
export function requireAction(env, confirmation) {
  ensure(
    env.GITHUB_ACTIONS === 'true' &&
      env.GITHUB_EVENT_NAME === 'workflow_dispatch' &&
      env.GITHUB_REPOSITORY === REPOSITORY &&
      env.GITHUB_REF === 'refs/heads/main',
    'MANUAL_MAIN_ACTION_REQUIRED',
  );
  ensure(env.CONFIRM_TARGET === confirmation, 'TARGET_CONFIRMATION_REQUIRED');
  for (const [key, value] of Object.entries(EXPECTED))
    ensure(env[key] === value, 'FIXED_TARGET_MISMATCH');
  ensure(
    typeof env.CLOUDFLARE_API_TOKEN === 'string' &&
      env.CLOUDFLARE_API_TOKEN.length > 0 &&
      !/\s/.test(env.CLOUDFLARE_API_TOKEN),
    'DEPLOY_CREDENTIAL_MISSING',
  );
}
async function readBounded(response, max = 8 * 1024 * 1024) {
  ensure(Number(response.headers.get('content-length') || 0) <= max, 'RESPONSE_TOO_LARGE');
  ensure(response.body, 'RESPONSE_BODY_MISSING');
  const reader = response.body.getReader();
  const chunks = [];
  let bytes = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      ensure(bytes <= max, 'RESPONSE_TOO_LARGE');
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  return Buffer.concat(chunks).toString('utf8');
}
// The only authenticated origin; no arbitrary endpoint option exists in any CLI.
export function createCFClient(token, { fetcher = fetch, allowWrites = false } = {}) {
  const request = async (path, options = {}) => {
    ensure(
      typeof path === 'string' && path.startsWith('/') && !/[\r\n\\]/.test(path),
      'INVALID_API_PATH',
    );
    const url = new URL(`https://api.cloudflare.com/client/v4${path}`);
    ensure(
      url.origin === 'https://api.cloudflare.com' && url.pathname.startsWith('/client/v4/'),
      'INVALID_API_ORIGIN',
    );
    const method = options.method || 'GET';
    ensure(['GET', 'POST', 'PUT', 'PATCH'].includes(method), 'METHOD_FORBIDDEN');
    const relative = url.pathname.slice('/client/v4'.length);
    ensure(
      relative.startsWith(`${ACCOUNT}/`) ||
        relative === ACCOUNT ||
        relative.startsWith(`${ADMIN_ZONE}/`) ||
        relative === ADMIN_ZONE ||
        relative.startsWith(`${PUBLIC_ZONE}/`) ||
        relative === PUBLIC_ZONE,
      'FOREIGN_RESOURCE_FORBIDDEN',
    );
    if (method !== 'GET') {
      ensure(allowWrites, 'LOCAL_CLOUDFLARE_WRITE_FORBIDDEN');
      ensure(
        !relative.includes(`/scripts/${EXPECTED.LEGACY_WORKER_NAME}/`) &&
          !relative.endsWith(`/scripts/${EXPECTED.LEGACY_WORKER_NAME}`) &&
          !relative.includes('/storage/kv/') &&
          !relative.includes('/dns_records'),
        'PROTECTED_RESOURCE_WRITE_FORBIDDEN',
      );
    }
    let response;
    try {
      response = await fetcher(url.href, {
        method,
        redirect: 'error',
        signal: AbortSignal.timeout(30000),
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: 'application/json',
          ...(options.json !== undefined ? { 'Content-Type': 'application/json' } : {}),
          ...(options.contentType ? { 'Content-Type': options.contentType } : {}),
        },
        ...(options.json !== undefined
          ? { body: JSON.stringify(options.json) }
          : options.body !== undefined
            ? { body: options.body }
            : {}),
      });
    } catch {
      throw new DeliveryError(
        method === 'GET'
          ? 'NETWORK_OR_REDIRECT_BLOCKED'
          : 'WRITE_RESULT_UNKNOWN_RECONCILE_REQUIRED',
      );
    }
    ensure(response.status < 300 || response.status >= 400, 'AUTHENTICATED_REDIRECT_BLOCKED');
    if (response.headers.get('cf-mitigated') === 'challenge') {
      await response.body?.cancel();
      throw new DeliveryError('CF_API_CHALLENGE', response.status);
    }
    const raw = await readBounded(response, options.maxBytes);
    let payload;
    if (options.raw && response.ok) return raw;
    try {
      payload = JSON.parse(raw);
    } catch {
      throw new DeliveryError(
        response.status === 401
          ? 'AUTH_FAILED'
          : response.status === 403
            ? 'PERMISSION_DENIED'
            : 'NON_JSON_RESPONSE',
        response.status,
      );
    }
    const codes = (payload.errors || [])
      .map((e) => e.code)
      .filter(Number.isInteger)
      .slice(0, 8);
    if (!response.ok || payload.success === false)
      throw new DeliveryError(
        response.status === 401
          ? 'AUTH_FAILED'
          : response.status === 403
            ? 'PERMISSION_DENIED'
            : response.status === 404
              ? 'NOT_FOUND'
              : response.status === 429
                ? 'RATE_LIMITED'
                : 'CF_API_ERROR',
        response.status,
        codes,
      );
    ensure(payload.success === true && Object.hasOwn(payload, 'result'), 'INVALID_CF_RESPONSE');
    return payload;
  };
  const diagnosticRequest = async (path, options) => {
    try {
      return await request(path, options);
    } catch (error) {
      if (error instanceof DeliveryError) {
        error.endpointCategory = endpointCategory(path);
        const method = options?.method || 'GET';
        error.requestMethod = ['GET', 'POST', 'PUT', 'PATCH'].includes(method) ? method : null;
      }
      throw error;
    }
  };
  return {
    request: diagnosticRequest,
    async optional(path, opts) {
      try {
        return await diagnosticRequest(path, opts);
      } catch (e) {
        if (e instanceof DeliveryError && e.code === 'NOT_FOUND') return null;
        throw e;
      }
    },
  };
}
export async function listAll(
  client,
  path,
  { select = (p) => p.result, pageSize = 100, maxPages = 100 } = {},
) {
  const items = [];
  const cursors = new Set();
  let cursor = '';
  let page = 1;
  const rulesets = /\/rulesets(?:\?|$)/.test(path);
  const cursorOnly = rulesets || /\/r2\/buckets(?:\?|$)/.test(path) || /\/rules\/lists/.test(path);
  if (rulesets) pageSize = Math.min(pageSize, 50);
  for (; page <= maxPages; page++) {
    const url = new URL(`https://api.cloudflare.com/client/v4${path}`);
    url.searchParams.set('per_page', String(pageSize));
    if (cursor) url.searchParams.set('cursor', cursor);
    else if (!cursorOnly) url.searchParams.set('page', String(page));
    const payload = await client.request(
      url.href.slice('https://api.cloudflare.com/client/v4'.length),
    );
    const batch = select(payload);
    ensure(Array.isArray(batch), 'INVALID_LIST_RESPONSE');
    items.push(...batch);
    const info = payload.result_info || {};
    const next = info.cursors?.after || info.cursor || payload.result?.cursor || '';
    if (next) {
      ensure(!cursors.has(next), 'PAGINATION_CURSOR_REPEATED');
      cursors.add(next);
      cursor = next;
      continue;
    }
    if (info.total_pages && page < info.total_pages) continue;
    if (Number.isInteger(info.total_count)) {
      ensure(items.length >= info.total_count, 'INCOMPLETE_PAGINATION');
      return items;
    }
    if (cursorOnly) return items;
    // APIs without pagination metadata must not be assumed complete at a full page.
    if (batch.length < pageSize) return items;
  }
  fail('PAGINATION_LIMIT_REVIEW_REQUIRED');
}
export async function verifyAccount(client) {
  const verified = await client.request(`${ACCOUNT}/tokens/verify`);
  ensure(
    verified.result.status === 'active' && /^[a-f\d]{32}$/i.test(verified.result.id),
    'DEPLOY_TOKEN_INACTIVE',
  );
  let policy = null;
  try {
    policy = await client.request(`${ACCOUNT}/tokens/${verified.result.id}`);
  } catch (error) {
    if (!(error instanceof DeliveryError && error.code === 'PERMISSION_DENIED')) throw error;
  }
  if (policy) ensure(Array.isArray(policy.result.policies), 'TOKEN_POLICY_UNVERIFIED');
  // Counts are safe evidence; actual write endpoint results remain the capability proof.
  const names = (policy?.result.policies || [])
    .filter((p) => p.effect === 'allow')
    .flatMap((p) => (p.permission_groups || []).map((g) => g.name || ''));
  for (const required of policy ? ['Workers Scripts', 'D1', 'Workers R2 Storage'] : [])
    ensure(
      names.some((n) =>
        required === 'Workers R2 Storage'
          ? n === 'Workers R2 Storage Write'
          : n.includes(required) && /Write|Edit/i.test(n),
      ),
      'DEPLOY_TOKEN_POLICY_MISSING_CAPABILITY',
    );
  for (const [path, name] of [
    [PUBLIC_ZONE, 'gfw.mom'],
    [ADMIN_ZONE, 'lily.lat'],
  ]) {
    const z = await client.request(path);
    ensure(
      z.result.name === name && z.result.account?.id === EXPECTED.CLOUDFLARE_ACCOUNT_ID,
      'ZONE_ACCOUNT_MISMATCH',
    );
  }
  const legacy = await client.request(
    `${ACCOUNT}/workers/scripts/${EXPECTED.LEGACY_WORKER_NAME}/settings`,
  );
  ensure(
    legacy.result.bindings?.some(
      (b) =>
        b.name === 'LINKS' &&
        b.type === 'kv_namespace' &&
        b.namespace_id === EXPECTED.LEGACY_KV_NAMESPACE_ID,
    ),
    'LEGACY_KV_BINDING_MISMATCH',
  );
  return {
    active: true,
    policy_read: policy ? 'reviewed' : 'permission_unavailable',
    allow_permission_count: policy ? names.length : null,
    write_permissions_unverified_until_endpoint_success: true,
  };
}
export function safeError(error) {
  return {
    code: error instanceof DeliveryError ? error.code : 'INTERNAL_ERROR',
    http_status: error instanceof DeliveryError ? error.status : null,
    cf_error_codes: error instanceof DeliveryError ? error.cfCodes : [],
    endpoint_category:
      error instanceof DeliveryError && ENDPOINT_CATEGORIES.has(error.endpointCategory)
        ? error.endpointCategory
        : null,
    request_method:
      error instanceof DeliveryError &&
      ['GET', 'POST', 'PUT', 'PATCH'].includes(error.requestMethod)
        ? error.requestMethod
        : null,
    detail: 'Raw responses, credentials and business data are withheld.',
  };
}
