#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import {
  ACCOUNT,
  EXPECTED,
  OWNER_KEY,
  DeliveryError,
  ensure,
  requireAction,
  createCFClient,
} from './cf-client.mjs';
import { objectPath, readManifest, query, verifyD1Owner } from './deploy-resources.mjs';

export const CONFIRMATION = 'diagnose shortlink-new test runtime read only';
const SITEVERIFY = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
const GRAPHQL = 'https://api.cloudflare.com/client/v4/graphql';
const INVALID_RESPONSE = 'invalid-shortlink-runtime-diagnostic';
const UUID = /^[a-f\d]{8}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{12}$/i;
const OWNER_SQL =
  'SELECT project, owner_id, account_id, worker FROM delivery_ownership WHERE singleton = 1';
const COUNTS_SQL =
  'SELECT (SELECT COUNT(*) FROM links) AS links, (SELECT COUNT(*) FROM domains WHERE bound = 1 AND enabled = 1) AS active_domains, (SELECT COUNT(*) FROM legacy_migration_runs) AS migration_runs, (SELECT COUNT(*) FROM legacy_migration_items) AS migration_observations';
const RUN_SQL =
  "SELECT id, state, processed, imported, unchanged, skipped, conflicts, unknown, CASE WHEN cursor <> '' THEN 1 ELSE 0 END AS cursor_present FROM legacy_migration_runs ORDER BY started_at DESC, id DESC LIMIT 1";
const SQL = new Set([OWNER_SQL, COUNTS_SQL, RUN_SQL]);
const ERROR_CODES = new Set([
  'missing-input-secret',
  'invalid-input-secret',
  'missing-input-response',
  'invalid-input-response',
  'bad-request',
  'timeout-or-duplicate',
  'internal-error',
]);
const SAFE_FAILURES = new Set([
  'MANUAL_MAIN_ACTION_REQUIRED',
  'TARGET_CONFIRMATION_REQUIRED',
  'FIXED_TARGET_MISMATCH',
  'DEPLOY_CREDENTIAL_MISSING',
  'DIAGNOSTIC_ARGUMENTS_FORBIDDEN',
  'RESOURCE_OWNERSHIP_UNPROVEN',
  'OWNERSHIP_MANIFEST_INVALID',
  'D1_OWNERSHIP_UNPROVEN',
  'D1_RESOURCE_DRIFT',
  'BOOTSTRAP_REQUIRED',
  'D1_QUERY_FAILED',
  'AUTH_FAILED',
  'PERMISSION_DENIED',
  'NOT_FOUND',
  'RATE_LIMITED',
  'CF_API_ERROR',
  'NON_JSON_RESPONSE',
  'CF_API_CHALLENGE',
  'RESPONSE_TOO_LARGE',
  'RESPONSE_LENGTH_INVALID',
  'RESPONSE_BODY_MISSING',
  'AUTHENTICATED_REDIRECT_BLOCKED',
  'NETWORK_OR_REDIRECT_BLOCKED',
  'READ_SCOPE_FORBIDDEN',
  'READ_RESPONSE_INVALID',
  'TURNSTILE_SECRET_MISSING',
]);
const HTTP_CODES = new Set([
  'TOKEN_REQUIRED',
  'TOKEN_INVALID',
  'METHOD_NOT_ALLOWED',
  'ADMIN_REQUIRED',
  'ADMIN_INVALID',
  'ADMIN_FORBIDDEN',
  'ADMIN_NOT_CONFIGURED',
  'HOST_FORBIDDEN',
  'TEMPORARILY_UNAVAILABLE',
]);
const PATHS = [
  '/api/shorten',
  '/api/admin/session',
  '/admin',
  '/api/shorten/',
  '/api/shorten-extra',
];
const REFS = [
  'shortlink_new_api_path_guard',
  'shortlink_new_api_skip',
  'shortlink_new_api_deny_outside_allowlist',
];
const contentType = (response) => {
  const type = (response.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
  return ['application/json', 'text/html', 'text/plain'].includes(type)
    ? type
    : type
      ? 'other'
      : 'missing';
};
const rayId = (value) =>
  typeof value === 'string' && /^[a-f\d]{16,32}(?:-[A-Z]{3})?$/i.test(value) ? value : null;
const count = (value) => {
  ensure(Number.isSafeInteger(value) && value >= 0, 'READ_RESPONSE_INVALID');
  return value;
};
function failure(check, error) {
  return {
    check,
    result: 'failed',
    code: SAFE_FAILURES.has(error?.code) ? error.code : 'READ_FAILED',
    http_status:
      Number.isInteger(error?.status) && error.status >= 100 && error.status < 600
        ? error.status
        : null,
  };
}
async function boundedJSON(response, max = 8192) {
  const reject = async (code) => {
    await response.body?.cancel().catch(() => {});
    throw new DeliveryError(code);
  };
  if (contentType(response) !== 'application/json') await reject('NON_JSON_RESPONSE');
  const length = response.headers.get('content-length');
  if (length !== null) {
    if (!/^\d+$/.test(length) || !Number.isSafeInteger(Number(length)))
      await reject('RESPONSE_LENGTH_INVALID');
    if (Number(length) > max) await reject('RESPONSE_TOO_LARGE');
  }
  ensure(response.body, 'RESPONSE_BODY_MISSING');
  const reader = response.body.getReader(),
    chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      ensure(size <= max, 'RESPONSE_TOO_LARGE');
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new DeliveryError('READ_RESPONSE_INVALID');
  }
}

// The underlying client supports writes for other workflows. This wrapper admits
// only the ownership GETs and three exact SELECT statements, never arbitrary SQL.
function readClient(token, fetcher) {
  const base = createCFClient(token, { fetcher, allowWrites: true });
  let id = null;
  const request = async (path, options = {}) => {
    const method = options.method || 'GET';
    const manifest = path === objectPath(OWNER_KEY) && method === 'GET';
    const metadata = id && path === `${ACCOUNT}/d1/database/${id}` && method === 'GET';
    const select =
      id &&
      path === `${ACCOUNT}/d1/database/${id}/query` &&
      method === 'POST' &&
      SQL.has(options.json?.sql) &&
      Array.isArray(options.json?.params) &&
      options.json.params.length === 0 &&
      Object.keys(options.json).length === 2;
    ensure(manifest || metadata || select, 'READ_SCOPE_FORBIDDEN');
    return base.request(path, { ...options, maxBytes: manifest ? 256 * 1024 : 8192 });
  };
  return {
    request,
    async optional(path, options) {
      try {
        return await request(path, options);
      } catch (error) {
        if (error instanceof DeliveryError && error.code === 'NOT_FOUND') return null;
        throw error;
      }
    },
    bindD1(value) {
      ensure(UUID.test(value), 'D1_OWNERSHIP_UNPROVEN');
      id = value;
    },
  };
}
async function databaseStatus(client, manifest) {
  const counts = (await query(client, manifest.d1.id, COUNTS_SQL))[0].results?.[0];
  ensure(counts && typeof counts === 'object', 'READ_RESPONSE_INVALID');
  const items = (await query(client, manifest.d1.id, RUN_SQL))[0].results;
  ensure(Array.isArray(items) && items.length <= 1, 'READ_RESPONSE_INVALID');
  let run = null;
  if (items.length) {
    const item = items[0];
    ensure(
      UUID.test(item.id) &&
        ['running', 'complete', 'failed'].includes(item.state) &&
        [0, 1].includes(item.cursor_present),
      'READ_RESPONSE_INVALID',
    );
    run = { id: item.id, state: item.state, cursor_present: item.cursor_present === 1 };
    for (const key of ['processed', 'imported', 'unchanged', 'skipped', 'conflicts', 'unknown'])
      run[key] = count(item[key]);
  }
  return {
    check: 'owned-d1-status',
    result: 'read_success',
    counts: Object.fromEntries(
      ['links', 'active_domains', 'migration_runs', 'migration_observations'].map((key) => [
        key,
        count(counts[key]),
      ]),
    ),
    migration_run: run,
  };
}
async function siteverify(secret, fetcher) {
  ensure(
    typeof secret === 'string' && secret.length > 0 && !/\s/.test(secret),
    'TURNSTILE_SECRET_MISSING',
  );
  const response = await fetcher(SITEVERIFY, {
    method: 'POST',
    redirect: 'error',
    signal: AbortSignal.timeout(8000),
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ secret, response: INVALID_RESPONSE }),
  });
  const result = {
    check: 'siteverify-invalid-probe',
    result: 'failed',
    http_status: response.status,
    content_type: contentType(response),
    validated_false: false,
    error_codes: [],
    unknown_error_code_count: 0,
  };
  try {
    const body = await boundedJSON(response);
    ensure(
      body &&
        typeof body === 'object' &&
        !Array.isArray(body) &&
        Array.isArray(body['error-codes']) &&
        body['error-codes'].length <= 16,
      'READ_RESPONSE_INVALID',
    );
    result.validated_false = body.success === false;
    result.error_codes = [...new Set(body['error-codes'].filter((code) => ERROR_CODES.has(code)))];
    result.unknown_error_code_count = body['error-codes'].filter(
      (code) => !ERROR_CODES.has(code),
    ).length;
    if (
      response.ok &&
      result.validated_false &&
      result.error_codes.length === 1 &&
      result.error_codes[0] === 'invalid-input-response' &&
      !result.unknown_error_code_count
    )
      result.result = 'expected_invalid_rejection';
  } catch (error) {
    result.code = failure('', error).code;
  }
  return result;
}
async function httpProbe(path, method, fetcher) {
  const response = await fetcher(`https://${EXPECTED.ADMIN_HOSTNAME}${path}`, {
    method,
    redirect: 'manual',
    signal: AbortSignal.timeout(8000),
    headers: {
      Accept: 'application/json',
      ...(method === 'POST' ? { 'Content-Type': 'application/json' } : {}),
    },
    ...(method === 'POST'
      ? { body: JSON.stringify({ url: 'https://example.com', domain: EXPECTED.PUBLIC_HOSTNAME }) }
      : {}),
  });
  const result = {
    check: `admin-${method.toLowerCase()}-${path === '/api/shorten' ? 'machine' : 'session'}`,
    result: 'failed',
    http_status: response.status,
    content_type: contentType(response),
    error_code: null,
    cf_mitigated: response.headers.get('cf-mitigated') === 'challenge' ? 'challenge' : null,
    ray: rayId(response.headers.get('cf-ray')),
    csp_present: response.headers.has('content-security-policy'),
    allow_post: response.headers.get('allow') === 'POST',
  };
  if (result.content_type === 'application/json') {
    try {
      const body = await boundedJSON(response);
      result.error_code = HTTP_CODES.has(body?.error?.code) ? body.error.code : null;
    } catch (error) {
      result.code = failure('', error).code;
    }
  } else await response.body?.cancel();
  const expected =
    path === '/api/admin/session'
      ? [302, 401, 403].includes(response.status)
      : method === 'GET'
        ? response.status === 405 && result.error_code === 'METHOD_NOT_ALLOWED' && result.allow_post
        : response.status === 401 && result.error_code === 'TOKEN_REQUIRED';
  if (expected) result.result = 'expected_rejection';
  return result;
}
async function analytics(env, manifest, fetcher, now) {
  if (!env.CF_ANALYTICS_READ_TOKEN)
    return { result: 'optional_unverified', code: 'ANALYTICS_CREDENTIAL_NOT_CONFIGURED' };
  try {
    ensure(
      typeof env.CF_ANALYTICS_READ_TOKEN === 'string' && !/\s/.test(env.CF_ANALYTICS_READ_TOKEN),
      'READ_RESPONSE_INVALID',
    );
    const end = now().toISOString(),
      start = new Date(Date.parse(end) - 15 * 60000).toISOString();
    // Only fixed project constants and generated ISO times become GraphQL literals.
    const queryText = `query RuntimeEvents { viewer { zones(filter: {zoneTag: ${JSON.stringify(EXPECTED.CF_ZONE_ID_LILY_LAT)}}) { firewallEventsAdaptive(filter: {datetime_geq: ${JSON.stringify(start)}, datetime_leq: ${JSON.stringify(end)}, clientRequestHTTPHost: ${JSON.stringify(EXPECTED.ADMIN_HOSTNAME)}, clientRequestPath_in: ${JSON.stringify(PATHS)}}, limit: 20, orderBy: [datetime_DESC]) { datetime action source ruleId rayName clientRequestPath } } } }`;
    const response = await fetcher(GRAPHQL, {
      method: 'POST',
      redirect: 'error',
      signal: AbortSignal.timeout(8000),
      headers: {
        Authorization: `Bearer ${env.CF_ANALYTICS_READ_TOKEN}`,
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({
        query: queryText,
      }),
    });
    const body = await boundedJSON(response, 256 * 1024);
    ensure(
      response.ok && !body.errors?.length && body.data?.viewer?.zones?.length === 1,
      'READ_RESPONSE_INVALID',
    );
    const events = body.data.viewer.zones[0].firewallEventsAdaptive;
    ensure(Array.isArray(events) && events.length <= 20, 'READ_RESPONSE_INVALID');
    const safeEvents = events.map((event) => {
      ensure(
        PATHS.includes(event.clientRequestPath) &&
          typeof event.datetime === 'string' &&
          Number.isFinite(Date.parse(event.datetime)) &&
          Date.parse(event.datetime) >= Date.parse(start) &&
          Date.parse(event.datetime) <= Date.parse(end),
        'READ_RESPONSE_INVALID',
      );
      const rule =
        typeof event.ruleId === 'string' && /^[a-f\d-]{1,64}$/i.test(event.ruleId)
          ? event.ruleId
          : null;
      const ref = REFS.find((key) => rule && manifest.security?.rules?.[key] === rule);
      return {
        datetime: new Date(event.datetime).toISOString(),
        action: [
          'allow',
          'block',
          'challenge',
          'jschallenge',
          'managed_challenge',
          'skip',
          'log',
          'bypass',
        ].includes(event.action)
          ? event.action
          : 'other',
        source: [
          'waf',
          'firewallrules',
          'firewallManaged',
          'firewallCustom',
          'bic',
          'hot',
          'uaBlock',
          'securitylevel',
          'ratelimit',
          'l7ddos',
          'botfight',
          'botManagement',
          'validation',
          'access',
        ].includes(event.source)
          ? event.source
          : 'other',
        rule_category: ref || 'unrelated_or_unknown',
        rule_hash: rule ? createHash('sha256').update(rule).digest('hex') : null,
        ray: rayId(event.rayName),
        path: event.clientRequestPath,
      };
    });
    return { result: 'read_success', sampled: true, window_minutes: 15, events: safeEvents };
  } catch {
    return { result: 'optional_unverified', code: 'ANALYTICS_READ_UNVERIFIED' };
  }
}
export async function main(
  args = process.argv.slice(2),
  env = process.env,
  { fetcher = fetch, now = () => new Date() } = {},
) {
  ensure(args.length === 0, 'DIAGNOSTIC_ARGUMENTS_FORBIDDEN');
  requireAction(env, CONFIRMATION);
  const checks = [];
  const client = readClient(env.CLOUDFLARE_API_TOKEN, fetcher);
  let manifest;
  try {
    manifest = await readManifest(client);
    ensure(manifest?.d1, 'BOOTSTRAP_REQUIRED');
    client.bindD1(manifest.d1.id);
    await verifyD1Owner(client, manifest);
    checks.push({ check: 'resource-ownership', result: 'read_success' });
  } catch (error) {
    return {
      checks: [failure('resource-ownership', error)],
      analytics: { result: 'optional_unverified', code: 'OWNERSHIP_REQUIRED' },
      exit_code: 2,
    };
  }
  for (const [label, inspect] of [
    ['owned-d1-status', () => databaseStatus(client, manifest)],
    ['siteverify-invalid-probe', () => siteverify(env.TURNSTILE_SECRET_KEY, fetcher)],
    ['admin-post-machine', () => httpProbe('/api/shorten', 'POST', fetcher)],
    ['admin-get-machine', () => httpProbe('/api/shorten', 'GET', fetcher)],
    ['admin-get-session', () => httpProbe('/api/admin/session', 'GET', fetcher)],
  ]) {
    try {
      checks.push(await inspect());
    } catch (error) {
      checks.push(failure(label, error));
    }
  }
  return {
    checks,
    analytics: await analytics(env, manifest, fetcher, now),
    exit_code: checks.some((check) => check.result === 'failed') ? 2 : 0,
  };
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const report = await main();
    console.log(JSON.stringify(report));
    process.exitCode = report.exit_code;
  } catch (error) {
    console.error(JSON.stringify(failure('workflow-scope', error)));
    process.exitCode = 2;
  }
}
