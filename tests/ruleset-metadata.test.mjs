import test from 'node:test';
import assert from 'node:assert/strict';
import { ACCOUNT, ADMIN_ZONE, EXPECTED, createCFClient, safeError } from '../scripts/cf-client.mjs';
import { bootstrapSecurity, inspectSecurity } from '../scripts/security-bootstrap.mjs';
import { validateRulesetCatalog } from '../scripts/ruleset-metadata.mjs';

const privateData = 'private-ruleset-name-expression';
const metadata = (index, phase, kind = 'zone') => ({
  id: index.toString(16).padStart(32, '0'),
  kind,
  phase,
  name: privateData,
});
const entrypoints = [
  'http_request_dynamic_redirect',
  'http_request_origin',
  'http_request_firewall_managed',
  'http_ratelimit',
  'http_custom_errors',
  'http_request_firewall_custom',
  'http_response_compression',
  'http_request_cache_settings',
].map((phase, index) => metadata(index + 20, phase));
const definitions = [
  'http_request_sanitize',
  ...Array(4).fill('http_request_firewall_managed'),
  'ddos_l7',
].map((phase, index) => metadata(index + 1, phase, 'managed'));
const json = (result) => new Response(JSON.stringify({ success: true, result }));

function fixture({ catalog = [...definitions, ...entrypoints], accounts = [], detail } = {}) {
  const calls = [];
  const client = createCFClient('dummy-test-token', {
    allowWrites: true,
    fetcher: async (url, options) => {
      calls.push({ url, options });
      assert.equal(new URL(url).hostname, 'api.cloudflare.com');
      assert.equal(options.method, 'GET');
      assert.equal(options.redirect, 'error');
      assert.equal(options.body, undefined);
      const path = new URL(url).pathname.slice('/client/v4'.length);
      if (path === `${ACCOUNT}/access/organizations`)
        return json({ auth_domain: EXPECTED.CF_ACCESS_TEAM_DOMAIN });
      if (path === `${ACCOUNT}/access/identity_providers`)
        return json([{ id: 'existing-otp', type: 'onetimepin' }]);
      if (path === `${ACCOUNT}/access/apps`) return json([]);
      if (path === `${ADMIN_ZONE}/bot_management`) return json({ fight_mode: false });
      if (path === `${ADMIN_ZONE}/settings`) return json([]);
      if (path === `${ADMIN_ZONE}/rulesets`) return json(catalog);
      if (path === `${ACCOUNT}/rulesets`) return json(accounts);
      const r = [...catalog, ...accounts].find((m) => path.endsWith(`/rulesets/${m.id}`));
      assert.ok(r, 'Only a validated catalog ID can become a detail endpoint');
      const custom = detail?.(r, path);
      return custom || json({ ...r, rules: [] });
    },
  });
  return { client, calls };
}

test('security inspection reads all eight actual zone entrypoints and never managed catalog definitions', async () => {
  const { client, calls } = fixture();
  const snapshot = await inspectSecurity(client, null);
  assert.equal(snapshot.rulesets.length, 8);
  assert.deepEqual(
    snapshot.rulesets.map((r) => r.phase),
    entrypoints.map((r) => r.phase),
  );
  assert.equal(snapshot.entry.id, entrypoints[5].id);
  assert.equal(calls.length, 15);
  assert.ok(
    !calls.some((c) => definitions.some((r) => new URL(c.url).pathname.endsWith(`/${r.id}`))),
  );
  assert.ok(calls.every((c) => c.options.method === 'GET'));
});

test('undeployed managed and custom definitions do not count as an active security phase', async () => {
  const { client, calls } = fixture({
    catalog: [...definitions, metadata(40, 'http_request_firewall_custom', 'custom')],
  });
  const snapshot = await inspectSecurity(client, null);
  assert.deepEqual(snapshot.rulesets, []);
  assert.equal(snapshot.entry, null);
  assert.equal(calls.length, 7);
});

test('untrusted catalog IDs, phase/kind labels and duplicate entrypoints fail before detail reads or writes', async () => {
  const valid = entrypoints[0];
  for (const catalog of [
    [{ ...valid, id: '../foreign-resource' }],
    [{ ...valid, phase: privateData }],
    [{ ...valid, kind: privateData }],
    [null],
    [valid, { ...valid, kind: 'managed' }],
    [valid, { ...valid, id: 'f'.repeat(32) }],
  ]) {
    const { client, calls } = fixture({ catalog });
    await assert.rejects(bootstrapSecurity(client, { owner_id: privateData }), (error) => {
      assert.match(error.code, /RULESET_CATALOG_INVALID|MULTIPLE_RULESET_PHASE_ENTRYPOINTS/);
      assert.doesNotMatch(JSON.stringify(safeError(error)), /private-ruleset|foreign-resource/);
      return true;
    });
    assert.equal(calls.length, 7);
  }
  assert.throws(() => validateRulesetCatalog({ result: [] }), { code: 'RULESET_CATALOG_INVALID' });
});

test('zone detail must match catalog ID, kind and phase and include a rules array', async () => {
  const r = entrypoints[0];
  for (const change of [
    { id: 'a'.repeat(32) },
    { kind: 'managed' },
    { phase: 'http_request_firewall_managed' },
    { rules: undefined },
    { rules: {} },
  ]) {
    const { client, calls } = fixture({
      catalog: [r],
      detail: () => json({ ...r, rules: [], private: privateData, ...change }),
    });
    await assert.rejects(bootstrapSecurity(client, { owner_id: privateData }), (error) => {
      assert.equal(
        error.code,
        'RULESET_DETAIL_ZONE_HTTP_REQUEST_DYNAMIC_REDIRECT_RULESET_DETAIL_METADATA_MISMATCH',
      );
      assert.equal(safeError(error).endpoint_category, 'ZONE_RULESETS');
      assert.equal(safeError(error).request_method, 'GET');
      assert.doesNotMatch(JSON.stringify(safeError(error)), /private-ruleset|000000/);
      return true;
    });
    assert.equal(calls.length, 8);
  }
});

test('zone detail 403 retains safe phase, HTTP status and numeric CF codes and cannot reach writes', async () => {
  const r = entrypoints[0];
  const { client, calls } = fixture({
    catalog: [r],
    detail: () =>
      new Response(
        JSON.stringify({ success: false, errors: [{ code: 10000, message: privateData }] }),
        { status: 403 },
      ),
  });
  await assert.rejects(bootstrapSecurity(client, { owner_id: privateData }), (error) => {
    assert.deepEqual(safeError(error), {
      code: 'RULESET_DETAIL_ZONE_HTTP_REQUEST_DYNAMIC_REDIRECT_PERMISSION_DENIED',
      http_status: 403,
      cf_error_codes: [10000],
      endpoint_category: 'ZONE_RULESETS',
      request_method: 'GET',
      media_type: 'TEXT',
      body_shape: 'JSON_OBJECT',
      numeric_code_count: 1,
      error_count: 1,
      cf_mitigated: 'NONE',
      detail: 'Raw responses, credentials and business data are withheld.',
    });
    assert.doesNotMatch(JSON.stringify(safeError(error)), /private-ruleset/);
    return true;
  });
  assert.equal(calls.length, 8);
});

test('account custom root detail must match metadata and cannot turn a malformed response into an empty ruleset', async () => {
  const root = metadata(50, 'http_request_firewall_custom', 'root');
  for (const change of [
    { id: 'a'.repeat(32) },
    { kind: 'managed' },
    { phase: 'http_ratelimit' },
    { rules: undefined },
    { rules: {} },
  ]) {
    const { client, calls } = fixture({
      accounts: [root],
      detail: (r) => (r.kind === 'root' ? json({ ...r, rules: [], ...change }) : null),
    });
    await assert.rejects(bootstrapSecurity(client, { owner_id: privateData }), {
      code: 'ACCOUNT_RULESET_DETAIL_METADATA_MISMATCH',
    });
    assert.equal(calls.length, 8);
  }
});

test('enabled account custom rules and unowned same-named zone security rules remain hard conflicts', async () => {
  const root = metadata(50, 'http_request_firewall_custom', 'root');
  const account = fixture({
    accounts: [root],
    detail: (r) => (r.kind === 'root' ? json({ ...r, rules: [{ enabled: true }] }) : null),
  });
  await assert.rejects(inspectSecurity(account.client, null), {
    code: 'ACCOUNT_CUSTOM_RULES_REVIEW_REQUIRED',
  });
  const custom = entrypoints[5];
  const zone = fixture({
    catalog: [custom],
    detail: () =>
      json({
        ...custom,
        rules: [{ ref: 'shortlink_new_api_skip', description: privateData }],
      }),
  });
  await assert.rejects(inspectSecurity(zone.client, null), {
    code: 'SAME_NAMED_WAF_RULE_UNOWNED',
  });
});
