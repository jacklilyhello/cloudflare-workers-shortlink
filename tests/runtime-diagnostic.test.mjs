import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import {
  ACCOUNT,
  EXPECTED,
  DATABASE,
  BUCKET,
  OWNER_KEY,
  REPOSITORY,
} from '../scripts/cf-client.mjs';
import { objectPath } from '../scripts/deploy-resources.mjs';
import { CONFIRMATION, main } from '../scripts/runtime-diagnostic.mjs';

const sensitive = 'private-response-business-data';
const deploySecret = 'fixture-deploy-credential';
const widgetSecret = 'fixture-widget-secret';
const analyticsSecret = 'fixture-analytics-credential';
const owner = '00000000-0000-4000-8000-000000000001';
const db = '00000000-0000-4000-8000-000000000002';
const run = '00000000-0000-4000-8000-000000000003';
const ownRule = '1'.repeat(32),
  unrelatedRule = '2'.repeat(32);
const now = () => new Date('2026-10-05T00:00:00Z');
const manifest = () => ({
  schema: 1,
  project: REPOSITORY,
  account: EXPECTED.CLOUDFLARE_ACCOUNT_ID,
  worker: EXPECTED.WORKER_NAME,
  environment: 'test',
  bucket: BUCKET,
  owner_id: owner,
  d1: { name: DATABASE, id: db },
  domains: {},
  security: { rules: { shortlink_new_api_path_guard: ownRule } },
  private: sensitive,
});
const env = () => ({
  ...EXPECTED,
  GITHUB_ACTIONS: 'true',
  GITHUB_EVENT_NAME: 'workflow_dispatch',
  GITHUB_REPOSITORY: REPOSITORY,
  GITHUB_REF: 'refs/heads/main',
  CONFIRM_TARGET: CONFIRMATION,
  CLOUDFLARE_API_TOKEN: deploySecret,
  TURNSTILE_SECRET_KEY: widgetSecret,
});
const json = (value, status = 200, headers = {}) =>
  new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
const cf = (value) => json({ success: true, result: value });
const d1 = (value) => cf([{ success: true, results: value }]);
function fixture(url, options) {
  const u = new URL(url);
  if (u.href === 'https://api.cloudflare.com/client/v4/graphql')
    return json({
      data: {
        viewer: {
          zones: [
            {
              firewallEventsAdaptive: [ownRule, unrelatedRule].map((ruleId) => ({
                datetime: '2026-10-04T23:58:00Z',
                action: 'block',
                source: 'firewallrules',
                ruleId,
                rayName: 'abcdef0123456789',
                clientRequestPath: '/api/shorten',
                clientIP: sensitive,
                private: sensitive,
              })),
            },
          ],
        },
      },
    });
  if (u.hostname === 'api.cloudflare.com') {
    const path = u.pathname.slice('/client/v4'.length);
    if (path === objectPath(OWNER_KEY)) return json(manifest());
    if (path === `${ACCOUNT}/d1/database/${db}`)
      return cf({ name: DATABASE, uuid: db, private: sensitive });
    if (path === `${ACCOUNT}/d1/database/${db}/query`) {
      const { sql } = JSON.parse(options.body);
      if (sql.includes('delivery_ownership'))
        return d1([
          {
            project: REPOSITORY,
            owner_id: owner,
            account_id: EXPECTED.CLOUDFLARE_ACCOUNT_ID,
            worker: EXPECTED.WORKER_NAME,
          },
        ]);
      if (sql.startsWith('SELECT (SELECT COUNT'))
        return d1([
          {
            links: 3,
            active_domains: 1,
            migration_runs: 1,
            migration_observations: 3,
            private: sensitive,
          },
        ]);
      return d1([
        {
          id: run,
          state: 'running',
          processed: 3,
          imported: 2,
          unchanged: 0,
          skipped: 0,
          conflicts: 0,
          unknown: 1,
          cursor_present: 1,
          cursor: sensitive,
          url: sensitive,
        },
      ]);
    }
  }
  if (u.href === 'https://challenges.cloudflare.com/turnstile/v0/siteverify')
    return json({ success: false, 'error-codes': ['invalid-input-response'], private: sensitive });
  if (u.hostname === EXPECTED.ADMIN_HOSTNAME) {
    const code =
      u.pathname === '/api/admin/session'
        ? 'ADMIN_REQUIRED'
        : options.method === 'POST'
          ? 'TOKEN_REQUIRED'
          : 'METHOD_NOT_ALLOWED';
    return json(
      { ok: false, error: { code, message: sensitive }, private: sensitive },
      options.method === 'GET' && u.pathname === '/api/shorten' ? 405 : 401,
      { Allow: 'POST', 'cf-ray': 'abcdef0123456789-LHR', 'set-cookie': sensitive },
    );
  }
  throw new Error(sensitive);
}
const noLeak = (report) =>
  assert.doesNotMatch(
    JSON.stringify(report),
    new RegExp(
      [
        sensitive,
        deploySecret,
        widgetSecret,
        analyticsSecret,
        unrelatedRule,
        'owner_id',
        'clientIP',
        'rawcursor',
        'Set-Cookie',
      ].join('|'),
    ),
  );

test('fixed owned SELECTs, Siteverify JSON and no-token HTTP probes are bounded and do not leak data', async () => {
  const calls = [];
  const report = await main([], env(), {
    now,
    fetcher: async (url, options) => {
      calls.push({ url, options });
      return fixture(url, options);
    },
  });
  assert.equal(report.exit_code, 0);
  assert.equal(report.checks.length, 6);
  assert.deepEqual(report.checks[1].migration_run, {
    id: run,
    state: 'running',
    cursor_present: true,
    processed: 3,
    imported: 2,
    unchanged: 0,
    skipped: 0,
    conflicts: 0,
    unknown: 1,
  });
  assert.equal(report.analytics.result, 'optional_unverified');
  assert.equal(calls.length, 9);
  const selects = calls.filter((call) => new URL(call.url).pathname.endsWith('/query'));
  assert.equal(selects.length, 3);
  for (const { url, options } of selects) {
    assert.equal(url, `https://api.cloudflare.com/client/v4${ACCOUNT}/d1/database/${db}/query`);
    assert.equal(options.method, 'POST');
    assert.equal(options.redirect, 'error');
    assert.match(JSON.parse(options.body).sql, /^SELECT /);
    assert.doesNotMatch(
      JSON.parse(options.body).sql,
      /INSERT|UPDATE|DELETE|DROP|CREATE|url|digest|namespace_id|key_hash/i,
    );
    assert.deepEqual(JSON.parse(options.body).params, []);
  }
  for (const { url, options } of calls) {
    assert.ok(
      ['api.cloudflare.com', 'challenges.cloudflare.com', EXPECTED.ADMIN_HOSTNAME].includes(
        new URL(url).hostname,
      ),
    );
    assert.equal(options.headers.Cookie, undefined);
    assert.equal(options.headers['Cf-Access-Jwt-Assertion'], undefined);
    if (new URL(url).hostname === EXPECTED.ADMIN_HOSTNAME) {
      assert.equal(options.headers.Authorization, undefined);
      assert.equal(options.redirect, 'manual');
      assert.equal(new URL(url).search, '');
    } else assert.equal(options.redirect, 'error');
  }
  const verify = calls.find((call) => new URL(call.url).hostname === 'challenges.cloudflare.com');
  assert.deepEqual(JSON.parse(verify.options.body), {
    secret: widgetSecret,
    response: 'invalid-shortlink-runtime-diagnostic',
  });
  assert.equal(verify.options.headers.Authorization, undefined);
  const post = calls.find(
    (call) =>
      new URL(call.url).hostname === EXPECTED.ADMIN_HOSTNAME && call.options.method === 'POST',
  );
  assert.deepEqual(JSON.parse(post.options.body), {
    url: 'https://example.com',
    domain: 'test.gfw.mom',
  });
  noLeak(report);
});
test('scope and extra arguments are rejected before all network access', async () => {
  let calls = 0;
  const options = {
    fetcher: async () => {
      calls++;
      throw new Error(sensitive);
    },
  };
  for (const changed of [
    { GITHUB_EVENT_NAME: 'push' },
    { GITHUB_REF: 'refs/heads/other' },
    { GITHUB_ACTIONS: 'false' },
    { CONFIRM_TARGET: '' },
    { PUBLIC_HOSTNAME: 'gfw.mom' },
    { CLOUDFLARE_API_TOKEN: '' },
  ])
    await assert.rejects(main([], { ...env(), ...changed }, options));
  await assert.rejects(main(['SELECT * FROM links'], env(), options), {
    code: 'DIAGNOSTIC_ARGUMENTS_FORBIDDEN',
  });
  assert.equal(calls, 0);
});
test('owner proof failure stops all runtime, analytics and business-data reads', async () => {
  const calls = [];
  const report = await main(
    [],
    { ...env(), CF_ANALYTICS_READ_TOKEN: analyticsSecret },
    {
      fetcher: async (url, options) => {
        calls.push(url);
        if (url.endsWith('/query')) return d1([{ project: sensitive }]);
        return fixture(url, options);
      },
    },
  );
  assert.equal(report.exit_code, 2);
  assert.equal(report.checks[0].code, 'D1_OWNERSHIP_UNPROVEN');
  assert.equal(calls.length, 3);
  assert.ok(calls.every((url) => new URL(url).hostname === 'api.cloudflare.com'));
  noLeak(report);
});
test('foreign manifest and missing manifest stop before D1 or Siteverify', async () => {
  for (const response of [
    json({ ...manifest(), account: 'f'.repeat(32) }),
    json({ success: false, errors: [{ code: 10000, message: sensitive }] }, 404),
  ]) {
    let calls = 0;
    const report = await main([], env(), {
      fetcher: async () => {
        calls++;
        return response;
      },
    });
    assert.equal(report.exit_code, 2);
    assert.equal(calls, 1);
    noLeak(report);
  }
});
test('Siteverify unknown codes, oversized responses, HTML, redirects and exceptions remain safe failures', async () => {
  const samples = [
    () => json({ success: false, 'error-codes': ['invalid-input-response', sensitive] }),
    () => json({ success: false, 'error-codes': ['invalid-input-secret'] }),
    () => json({ success: true, 'error-codes': [], private: sensitive }),
    () =>
      json({
        success: false,
        'error-codes': ['invalid-input-response'],
        private: sensitive.repeat(1000),
      }),
    () =>
      new Response(sensitive, {
        status: 403,
        headers: { 'Content-Type': 'text/html', 'set-cookie': sensitive },
      }),
    () =>
      json({ success: false, 'error-codes': ['invalid-input-response'] }, 302, {
        Location: `https://example.com/?secret=${sensitive}`,
      }),
    () => {
      throw new Error(sensitive);
    },
  ];
  for (const sample of samples) {
    const report = await main([], env(), {
      fetcher: async (url, options) =>
        url.includes('/siteverify') ? sample() : fixture(url, options),
    });
    assert.equal(report.exit_code, 2);
    assert.equal(
      report.checks.find((check) => check.check === 'siteverify-invalid-probe').result,
      'failed',
    );
    noLeak(report);
  }
});
test('HTTP custom HTML denial remains an actual failure and arbitrary header/error text is suppressed', async () => {
  const report = await main([], env(), {
    fetcher: async (url, options) =>
      new URL(url).hostname === EXPECTED.ADMIN_HOSTNAME
        ? new Response(sensitive, {
            status: 403,
            headers: {
              'Content-Type': `${sensitive}; secret=${sensitive}`,
              'cf-ray': sensitive,
              'cf-mitigated': sensitive,
              'set-cookie': sensitive,
            },
          })
        : fixture(url, options),
  });
  assert.equal(report.exit_code, 2);
  const post = report.checks.find((check) => check.check === 'admin-post-machine');
  assert.equal(post.http_status, 403);
  assert.equal(post.content_type, 'other');
  assert.equal(post.ray, null);
  noLeak(report);
});
test('Siteverify cancels bodies before rejecting non-JSON or invalid and oversized declared lengths', async () => {
  for (const [headers, code] of [
    [{ 'Content-Type': 'text/html' }, 'NON_JSON_RESPONSE'],
    [
      { 'Content-Type': 'application/json', 'Content-Length': sensitive },
      'RESPONSE_LENGTH_INVALID',
    ],
    [{ 'Content-Type': 'application/json', 'Content-Length': '-1' }, 'RESPONSE_LENGTH_INVALID'],
    [
      { 'Content-Type': 'application/json', 'Content-Length': '9007199254740993' },
      'RESPONSE_LENGTH_INVALID',
    ],
    [{ 'Content-Type': 'application/json', 'Content-Length': '8193' }, 'RESPONSE_TOO_LARGE'],
  ]) {
    let cancelled = false;
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(sensitive));
      },
      cancel() {
        cancelled = true;
      },
    });
    const report = await main([], env(), {
      fetcher: async (url, options) =>
        url.includes('/siteverify') ? new Response(stream, { headers }) : fixture(url, options),
    });
    assert.equal(cancelled, true);
    assert.equal(report.exit_code, 2);
    assert.equal(
      report.checks.find((check) => check.check === 'siteverify-invalid-probe').code,
      code,
    );
    noLeak(report);
  }
});
test('malformed migration counts, UUID or cursor presence fail safely without revealing cursor data', async () => {
  const report = await main([], env(), {
    fetcher: async (url, options) => {
      if (url.endsWith('/query') && JSON.parse(options.body).sql.startsWith('SELECT id, state'))
        return d1([
          {
            id: run,
            state: 'running',
            processed: -1,
            cursor_present: sensitive,
            cursor: sensitive,
          },
        ]);
      return fixture(url, options);
    },
  });
  assert.equal(report.exit_code, 2);
  assert.equal(report.checks[1].code, 'READ_RESPONSE_INVALID');
  noLeak(report);
});
test('optional analytics is read only, host/path/time/field bounded and hashes unrelated rule IDs', async () => {
  const calls = [];
  const report = await main(
    [],
    { ...env(), CF_ANALYTICS_READ_TOKEN: analyticsSecret },
    {
      now,
      fetcher: async (url, options) => {
        calls.push({ url, options });
        return fixture(url, options);
      },
    },
  );
  assert.equal(report.exit_code, 0);
  assert.equal(report.analytics.result, 'read_success');
  assert.equal(report.analytics.events[0].rule_category, 'shortlink_new_api_path_guard');
  assert.equal(report.analytics.events[1].rule_category, 'unrelated_or_unknown');
  assert.equal(
    report.analytics.events[1].rule_hash,
    createHash('sha256').update(unrelatedRule).digest('hex'),
  );
  const call = calls.find((call) => call.url.endsWith('/graphql'));
  assert.equal(call.url, 'https://api.cloudflare.com/client/v4/graphql');
  assert.equal(call.options.method, 'POST');
  assert.equal(call.options.redirect, 'error');
  assert.equal(call.options.headers.Authorization, `Bearer ${analyticsSecret}`);
  const request = JSON.parse(call.options.body);
  assert.deepEqual(Object.keys(request), ['query']);
  assert.match(request.query, /limit: 20/);
  assert.doesNotMatch(
    request.query,
    /mutation|clientIP|clientAsn|clientRequestQuery|userAgent|headers|\$|InputObject/,
  );
  const literal = (key) => JSON.parse(request.query.match(new RegExp(`${key}: ("[^"]+")`))[1]);
  assert.equal(literal('zoneTag'), EXPECTED.CF_ZONE_ID_LILY_LAT);
  assert.equal(literal('clientRequestHTTPHost'), EXPECTED.ADMIN_HOSTNAME);
  assert.equal(
    Date.parse(literal('datetime_leq')) - Date.parse(literal('datetime_geq')),
    15 * 60000,
  );
  assert.equal(literal('datetime_leq'), now().toISOString());
  assert.deepEqual(JSON.parse(request.query.match(/clientRequestPath_in: (\[[^\]]+\])/)[1]), [
    '/api/shorten',
    '/api/admin/session',
    '/admin',
    '/api/shorten/',
    '/api/shorten-extra',
  ]);
  noLeak(report);
});
test('analytics errors, foreign paths and oversized event counts are optional without private details', async () => {
  for (const body of [
    { errors: [{ message: sensitive }] },
    {
      data: {
        viewer: {
          zones: [
            {
              firewallEventsAdaptive: Array.from({ length: 21 }, () => ({
                clientRequestPath: sensitive,
              })),
            },
          ],
        },
      },
    },
  ]) {
    const report = await main(
      [],
      { ...env(), CF_ANALYTICS_READ_TOKEN: analyticsSecret },
      {
        now,
        fetcher: async (url, options) =>
          url.endsWith('/graphql') ? json(body) : fixture(url, options),
      },
    );
    assert.equal(report.exit_code, 0);
    assert.equal(report.analytics.result, 'optional_unverified');
    noLeak(report);
  }
});
test('workflow secrets are supplied only after local checks and dispatch is main-only', () => {
  const text = readFileSync(
    new URL('../.github/workflows/runtime-diagnostic.yml', import.meta.url),
    'utf8',
  );
  assert.match(text, /workflow_dispatch:/);
  assert.doesNotMatch(
    text,
    /\bpush:|\bpull_request:|\bschedule:|actions\/upload-artifact|wrangler|checkout.*@v\d/,
  );
  assert.match(text, /github\.ref == 'refs\/heads\/main'/);
  assert.match(text, /timeout-minutes: 20/);
  assert.match(text, /environment: shortlink-test/);
  assert.match(text, /group: shortlink-new-cloudflare/);
  assert.match(text, /contents: read/);
  assert.match(text, /actions\/checkout@11bd71901bbe5b1630ceea73d27597364c9af683/);
  assert.match(text, /actions\/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020/);
  assert.ok(text.indexOf('npm run check') < text.indexOf('secrets.CLOUDFLARE_API_TOKEN'));
  for (const name of ['CLOUDFLARE_API_TOKEN', 'TURNSTILE_SECRET_KEY', 'CF_ANALYTICS_READ_TOKEN'])
    assert.match(text, new RegExp(`secrets\\.${name}`));
});
