// Tests are only for safety of the readonly preflight, never product behavior or remote writes.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  EXPECTED,
  SafeError,
  buildRequest,
  checkCloudflare,
  checkGitHub,
  createClient,
  loadCredential,
  summarizeKeys,
  summarizePolicy,
  summarizeValue,
  validateVariables,
} from './preflight-readonly.mjs';
const config = { ...EXPECTED };
const token = 'mock-readonly-secret';
const credential = { token, source: 'mock only' };
const envelope = (result) => ({ success: true, result });
const json = (body, status = 200, headers = {}) =>
  new Response(JSON.stringify(body), { status, headers });

test('configuration drift and whitespace cannot change the permitted account/host', () => {
  assert.ok(validateVariables(config).every((c) => c.ok));
  for (const name of Object.keys(config)) {
    const bad = { ...config, [name]: `${config[name]} ` };
    assert.equal(validateVariables(bad).find((c) => c.name === name).ok, false);
    assert.throws(() => buildRequest('verify', bad), { kind: 'CONFIG_MISMATCH' });
  }
  assert.throws(
    () => buildRequest('verify', { ...config, CLOUDFLARE_ACCOUNT_ID: 'a'.repeat(32) }),
    { kind: 'CONFIG_MISMATCH' },
  );
});
test('configuration requires the three exact administrators and preserves both existing emails', () => {
  const emails = ['lilyyaloveyou@gmail.com', 'admin@888888.mom', 'moshaoli688@gmail.com'];
  assert.deepEqual(EXPECTED.ADMIN_EMAILS.split(','), emails);
  for (const value of [
    ...emails.map((removed) => emails.filter((email) => email !== removed).join(',')),
    `${EXPECTED.ADMIN_EMAILS},intruder@example.com`,
    `${EXPECTED.ADMIN_EMAILS},moshaoli688@gmail.com`,
  ]) {
    const changed = { ...config, ADMIN_EMAILS: value };
    assert.equal(validateVariables(changed).find((row) => row.name === 'ADMIN_EMAILS').ok, false);
    assert.throws(() => buildRequest('verify', changed), { kind: 'CONFIG_MISMATCH' });
  }
});
test('generic/deployment tokens are never used as a fallback', () => {
  assert.equal(loadCredential({ CLOUDFLARE_API_TOKEN: token, CF_API_TOKEN: token }), null);
  assert.equal(
    loadCredential({ CLOUDFLARE_READONLY_API_TOKEN: token }).source,
    'env:CLOUDFLARE_READONLY_API_TOKEN',
  );
  assert.throws(
    () =>
      loadCredential({
        CLOUDFLARE_READONLY_API_TOKEN: token,
        CLOUDFLARE_READONLY_TOKEN_FILE: '/not-read',
      }),
    { kind: 'AMBIGUOUS_CREDENTIAL_SOURCE' },
  );
});
test('no credential means no CF requests; every required CF check stays pending', async () => {
  let calls = 0;
  const rows = await checkCloudflare(config, null, {
    request: () => {
      calls++;
    },
  });
  assert.equal(calls, 0);
  assert.ok(rows.length >= 20);
  assert.ok(rows.every((r) => r.result === 'PENDING'));
});
test('only defined GET requests and the fixed GraphQL query POST are possible', () => {
  for (const kind of [
    'verify',
    'zone-public',
    'zone-secondary',
    'zone-admin',
    'legacy',
    'new',
    'subdomain',
    'keys',
    'dns-public',
    'dns-secondary',
    'dns-admin',
    'routes-public',
    'routes-secondary',
    'routes-admin',
    'domains-public',
    'domains-secondary',
    'domains-admin',
    'd1',
    'r2',
    'organization',
    'apps',
    'idps',
  ]) {
    const request = buildRequest(kind, config);
    assert.equal(new URL(request.url).hostname, 'api.cloudflare.com');
    assert.equal(request.method, 'GET');
    assert.equal(request.body, undefined);
  }
  const request = buildRequest('analytics', config, 'mutation { destroy }');
  assert.equal(request.method, 'POST');
  assert.equal(new URL(request.url).pathname, '/client/v4/graphql');
  const body = JSON.parse(request.body);
  assert.match(body.query, /^query /);
  assert.doesNotMatch(body.query, /mutation|destroy/i);
  assert.match(body.query, /limit: 1/);
  assert.equal(body.variables.scriptName, 'shortlink-new');
  for (const kind of ['PUT', 'DELETE', 'https://evil.test', 'deploy', 'sql'])
    assert.throws(() => buildRequest(kind, config), { kind: 'ENDPOINT_NOT_ALLOWED' });
  assert.throws(() => buildRequest('policy', config, '../secrets'), {
    kind: 'INVALID_RESOURCE_ID',
  });
  assert.throws(() => buildRequest('value', config, '..'), { kind: 'INVALID_KV_KEY' });
  assert.throws(() => buildRequest('value', config, '.'), { kind: 'INVALID_KV_KEY' });
});
test('authentication cannot follow even a same-host redirect', async () => {
  let calls = 0;
  const client = createClient(
    config,
    token,
    async (url, options) => {
      calls++;
      assert.equal(options.redirect, 'error');
      assert.equal(new URL(url).origin, 'https://api.cloudflare.com');
      return new Response('', { status: 302, headers: { location: 'https://evil.test' } });
    },
    async () => {},
  );
  await assert.rejects(client('verify'), { kind: 'REDIRECT_BLOCKED' });
  assert.equal(calls, 1);
});
test('401/403 HTML responses keep authentication/permission classification and are not retried', async () => {
  for (const [status, kind] of [
    [401, 'AUTH_FAILED'],
    [403, 'PERMISSION_DENIED'],
  ]) {
    let calls = 0;
    const client = createClient(
      config,
      token,
      async () => {
        calls++;
        return new Response(`<html>${token}</html>`, { status });
      },
      async () => {},
    );
    await assert.rejects(client('verify'), (e) => e.kind === kind && !e.message.includes(token));
    assert.equal(calls, 1);
  }
});
test('Cloudflare challenge is distinct from a JSON success or a missing permission', async () => {
  const client = createClient(
    config,
    token,
    async () =>
      new Response('challenge', { status: 403, headers: { 'cf-mitigated': 'challenge' } }),
  );
  await assert.rejects(client('verify'), { kind: 'CLOUDFLARE_CHALLENGE' });
});
test('limited transient retry and rate-limit classification', async () => {
  for (const status of [429, 503]) {
    let calls = 0;
    let waits = 0;
    const client = createClient(
      config,
      token,
      async () => {
        calls++;
        return json({ success: false }, status);
      },
      async (ms) => {
        waits++;
        assert.ok(ms <= 2000);
      },
    );
    await assert.rejects(client('verify'), {
      kind: status === 429 ? 'RATE_LIMITED' : 'REMOTE_ERROR',
    });
    assert.equal(calls, 2);
    assert.equal(waits, 1);
  }
});
test('failed fetch exposes neither error message nor credential; bounded attempts', async () => {
  let calls = 0;
  const client = createClient(
    config,
    token,
    async () => {
      calls++;
      throw new Error(`request failed ${token}`);
    },
    async () => {},
  );
  await assert.rejects(
    client('verify'),
    (e) => e.kind === 'NETWORK_OR_REDIRECT_BLOCKED' && !e.message.includes(token),
  );
  assert.equal(calls, 2);
});
test('oversized response, malformed JSON and GraphQL HTTP-200 errors cannot pass', async () => {
  await assert.rejects(
    createClient(
      config,
      token,
      async () => new Response('x', { headers: { 'content-length': '9999999' } }),
    )('verify'),
    { kind: 'RESPONSE_TOO_LARGE' },
  );
  await assert.rejects(
    createClient(config, token, async () => new Response('x'.repeat(2097153)))('verify'),
    { kind: 'RESPONSE_TOO_LARGE' },
  );
  await assert.rejects(createClient(config, token, async () => new Response('<html>'))('verify'), {
    kind: 'NON_JSON_RESPONSE',
  });
  await assert.rejects(
    createClient(config, token, async () => json({ errors: [{ message: token }] }))('analytics'),
    { kind: 'GRAPHQL_QUERY_DENIED_OR_UNSUPPORTED' },
  );
});
test('Secret listing refusal is not interpreted as missing, raw errors are hidden', () => {
  const { rows } = checkGitHub((path) => {
    if (path.startsWith('actions/secrets')) throw new SafeError('PERMISSION_DENIED', 403);
    if (path.startsWith('actions/variables'))
      return {
        variables: Object.entries(config).map(([name, value]) => ({ name, value })),
        total_count: 12,
      };
    return {};
  });
  assert.ok(rows.some((r) => r.item === 'github.secrets' && r.result === 'PERMISSION_DENIED'));
  assert.ok(!rows.some((r) => r.result === 'ABSENT_NAME'));
});
test('KV summaries retain only structure; no URL, slug, key or metadata values', () => {
  const url = 'https://private.example/path?secret=hidden#fragment';
  const keys = [
    { name: 'a'.repeat(128), metadata: { url } },
    { name: 'private-slug', metadata: { createdAt: 123 } },
    { name: 'SYS_CONFIG_PRIVATE' },
  ];
  const summary = JSON.stringify({ ...summarizeKeys(keys), value: summarizeValue(url) });
  assert.ok(!summary.includes(url));
  assert.ok(!summary.includes('private-slug'));
  assert.ok(!summary.includes('SYS_CONFIG_PRIVATE'));
  assert.equal(summarizeKeys(keys).hash_index_candidates, 1);
  assert.equal(summarizeValue(url).kind, 'http_url_string');
});
test('write or unknown policy permissions remain explicitly unresolved', () => {
  const result = summarizePolicy({
    policies: [
      {
        effect: 'allow',
        permission_groups: [
          { name: 'Workers Scripts Write' },
          { name: 'D1 Read' },
          { name: 'Unknown' },
        ],
      },
    ],
  });
  assert.deepEqual(result.write_permission_names, ['Workers Scripts Write']);
  assert.deepEqual(result.unclassified_permission_names, ['Unknown']);
  assert.equal(result.resource_scope_reviewed, false);
});
test('dependent CF checks stop after token or Zone failure', async () => {
  let calls = [];
  let rows = await checkCloudflare(config, credential, {
    request: async (kind) => {
      calls.push(kind);
      throw new SafeError('AUTH_FAILED', 401);
    },
  });
  assert.deepEqual(calls, ['verify']);
  assert.ok(rows.some((r) => r.item === 'worker.legacy' && r.result === 'PENDING'));
  calls = [];
  rows = await checkCloudflare(config, credential, {
    request: async (kind) => {
      calls.push(kind);
      if (kind === 'verify') return envelope({ status: 'active', id: 'a'.repeat(32) });
      if (kind === 'policy') throw new SafeError('PERMISSION_DENIED', 403);
      return envelope({ name: 'wrong-zone', account: { id: config.CLOUDFLARE_ACCOUNT_ID } });
    },
  });
  assert.deepEqual(calls, ['verify', 'policy', 'zone-public', 'zone-secondary', 'zone-admin']);
  assert.ok(rows.some((r) => r.item === 'kv.read' && r.result === 'PENDING'));
});
test('CF summaries filter other account assets and wildcard routes are conservatively occupied', async () => {
  const calls = [];
  const rows = await checkCloudflare(config, credential, {
    sampleKV: true,
    request: async (kind, arg) => {
      calls.push([kind, arg]);
      if (kind === 'verify') return envelope({ status: 'active', id: 'a'.repeat(32) });
      if (kind === 'policy') throw new SafeError('PERMISSION_DENIED', 403);
      if (kind.startsWith('zone-'))
        return envelope({
          name:
            kind === 'zone-public' ? 'gfw.mom' : kind === 'zone-secondary' ? 'gfw.lat' : 'lily.lat',
          account: { id: config.CLOUDFLARE_ACCOUNT_ID },
        });
      if (kind === 'legacy')
        return envelope({
          bindings: [
            { name: 'LINKS', type: 'kv_namespace', namespace_id: config.LEGACY_KV_NAMESPACE_ID },
            { name: 'SECRET', text: token },
          ],
        });
      if (kind === 'keys')
        return envelope(Array.from({ length: 10 }, (_, i) => ({ name: `code${i}` })));
      if (kind === 'value') return 'https://private.example/?secret=hidden';
      if (kind === 'subdomain') return envelope({ subdomain: 'observed-subdomain' });
      if (kind === 'new') throw new SafeError('NOT_FOUND_UNCONFIRMED', 404);
      if (kind.startsWith('routes-'))
        return envelope([
          { pattern: '*.gfw.mom/*' },
          { pattern: 'unrelated.example/*', script: 'private-worker' },
        ]);
      if (kind === 'r2') return envelope({ buckets: [] });
      if (kind === 'organization') return envelope({ auth_domain: config.CF_ACCESS_TEAM_DOMAIN });
      if (kind === 'idps') return envelope([{ type: 'onetimepin', config: { secret: token } }]);
      if (kind === 'analytics')
        return { data: { viewer: { accounts: [{ workersInvocationsAdaptive: [] }] } } };
      return envelope([]);
    },
  });
  assert.equal(calls.filter(([kind]) => kind === 'value').length, 2);
  assert.ok(
    rows.some((r) => r.item === 'routes.public' && r.result === 'OCCUPIED_REVIEW_REQUIRED'),
  );
  const output = JSON.stringify(rows);
  for (const hidden of [token, 'private-worker', 'private.example', 'unrelated.example', 'code0'])
    assert.ok(!output.includes(hidden));
  assert.ok(rows.some((r) => r.item === 'analytics.read' && r.result === 'PASS' && r.unverified));
});
