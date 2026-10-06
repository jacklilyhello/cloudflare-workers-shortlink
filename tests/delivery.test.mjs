import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import {
  EXPECTED,
  ACCOUNT,
  ADMIN_ZONE,
  DeliveryError,
  createCFClient,
  listAll,
  requireAction,
  safeError,
  verifyAccount,
} from '../scripts/cf-client.mjs';
import { qualifyPolicy, main as qualify } from '../scripts/qualify-readonly.mjs';
import {
  validateManifest,
  workerOwnerMatches,
  inspectHost,
  prepareResources,
  objectPath,
  reconcileD1,
  requireBootstrapComplete,
  privateSnapshot,
} from '../scripts/deploy-resources.mjs';
import { deploymentConfiguration } from '../scripts/deploy.mjs';
import {
  API_MATCH,
  GUARD_MATCH,
  GUARD_REF,
  SKIP_REF,
  DENY_REF,
  productionPolicyReady,
  apiIPCondition,
  validateAccessPolicy,
  unrelatedRulesUnchanged,
  accessAppTouchesHost,
  bootstrapSecurity,
} from '../scripts/security-bootstrap.mjs';

const owner = '0f377c05-d37d-4b8c-a08e-95730b1c1dfe';
const d1 = '4e844b76-30b4-47e7-9d53-ff76c3e9a23a';
const manifest = () => ({
  schema: 1,
  project: 'jacklilyhello/cloudflare-workers-shortlink',
  account: EXPECTED.CLOUDFLARE_ACCOUNT_ID,
  worker: 'shortlink-new',
  environment: 'test',
  bucket: 'shortlink-new-backups',
  owner_id: owner,
  d1: { id: d1, name: 'shortlink-new-test' },
  domains: {},
  security: { apps: { admin: { id: 'a'.repeat(32), aud: 'b'.repeat(64) } } },
});
const response = (result, extra = {}) =>
  new Response(JSON.stringify({ success: true, result, ...extra }), {
    headers: { 'Content-Type': 'application/json' },
  });
const ownRule = (ref, action, expression) => ({
  id: ref,
  ref,
  action,
  expression,
  enabled: true,
  description: `shortlink-new:${owner}:purpose`,
});

test('security-before survives a successful snapshot followed by a failed manifest checkpoint', async () => {
  const first = manifest();
  const recovered = manifest();
  let setting = 'on';
  let stored = null;
  let snapshotWrites = 0;
  const client = {
    optional: async (path, options) => {
      assert.equal(path, objectPath(`delivery/${owner}/security-before.json`));
      assert.equal(options.raw, true);
      return stored;
    },
    request: async (path, options) => {
      if (options?.method === 'PUT') {
        if (path === objectPath(`delivery/${owner}/security-before.json`)) {
          stored = options.body;
          snapshotWrites++;
          return { result: {} };
        }
        assert.equal(path, objectPath('delivery/ownership.json'));
        throw new DeliveryError('CHECKPOINT_FAILED');
      }
      assert.equal(options?.method, undefined);
      const pathname = new URL(`https://x${path}`).pathname;
      if (pathname.endsWith('/access/organizations'))
        return { result: { auth_domain: EXPECTED.CF_ACCESS_TEAM_DOMAIN } };
      if (pathname.endsWith('/access/identity_providers'))
        return { result: [{ id: 'otp-existing', type: 'onetimepin' }] };
      if (pathname.endsWith('/bot_management')) return { result: { fight_mode: false } };
      if (pathname.endsWith('/settings'))
        return { result: [{ id: 'browser_check', value: setting }] };
      assert.ok(pathname.endsWith('/access/apps') || pathname.endsWith('/rulesets'));
      return { result: [] };
    },
  };
  await assert.rejects(bootstrapSecurity(client, first), { code: 'CHECKPOINT_FAILED' });
  const originalSnapshot = stored;
  setting = 'off'; // A later external change must not replace the original recovery evidence.
  await assert.rejects(bootstrapSecurity(client, recovered), { code: 'CHECKPOINT_FAILED' });
  assert.equal(snapshotWrites, 1);
  assert.equal(stored, originalSnapshot);
  assert.equal(JSON.parse(stored).settings[0].value, 'on');

  let calls = 0;
  await assert.rejects(
    privateSnapshot(
      { optional: async () => calls++ },
      { ...manifest(), bucket: 'unrelated-bucket' },
      'security-before',
      {},
      { preserveExisting: true },
    ),
    { code: 'RESOURCE_OWNERSHIP_UNPROVEN' },
  );
  assert.equal(calls, 0);
});

test('ordinary deployment requires completed bootstrap and primary registration while preserving runtime domain status', async () => {
  const completed = manifest();
  completed.worker_created = true;
  completed.security.status = 'ready';
  completed.journal = [{ step: 'worker-upload', state: 'complete' }];
  completed.domains = {
    'test.gfw.mom': {
      id: 'public-owned',
      zone_id: EXPECTED.CF_ZONE_ID_GFW_MOM,
      dns_signature: 'a'.repeat(64),
    },
    'link-admin.lily.lat': {
      id: 'admin-owned',
      zone_id: EXPECTED.CF_ZONE_ID_LILY_LAT,
      dns_signature: 'b'.repeat(64),
    },
  };
  const domain = {
    hostname: 'test.gfw.mom',
    bound: 0,
    enabled: 0,
    binding_state: 'failed',
  };
  let registered = true;
  const calls = [];
  const client = {
    request: async (path, options) => {
      calls.push({ path, options });
      if (path.endsWith('/query')) {
        assert.match(options.json.sql, /^SELECT /);
        return {
          result: [
            {
              success: true,
              results: options.json.sql.includes('FROM domains')
                ? registered
                  ? [domain]
                  : []
                : [
                    {
                      project: completed.project,
                      owner_id: owner,
                      account_id: completed.account,
                      worker: completed.worker,
                    },
                  ],
            },
          ],
        };
      }
      return { result: { name: 'shortlink-new-test', uuid: d1 } };
    },
  };
  const failed = structuredClone(domain);
  await assert.doesNotReject(requireBootstrapComplete(client, completed));
  assert.deepEqual(domain, failed);
  domain.bound = 1;
  domain.binding_state = 'verified';
  const verified = structuredClone(domain);
  await assert.doesNotReject(requireBootstrapComplete(client, completed));
  assert.deepEqual(domain, verified);
  registered = false;
  await assert.rejects(requireBootstrapComplete(client, completed), {
    code: 'BOOTSTRAP_RECOVERY_REQUIRED',
  });
  registered = true;
  for (const mutate of [
    (m) => {
      delete m.domains['link-admin.lily.lat'];
    },
    (m) => {
      m.journal = [{ step: 'worker-upload', state: 'intent' }];
    },
    (m) => {
      m.security.status = 'creating';
    },
  ]) {
    const incomplete = structuredClone(completed);
    mutate(incomplete);
    const before = calls.length;
    await assert.rejects(requireBootstrapComplete(client, incomplete), {
      code: 'BOOTSTRAP_RECOVERY_REQUIRED',
    });
    assert.equal(calls.length, before);
  }
  assert.ok(
    calls.every((c) =>
      c.options?.json ? c.options.json.sql.startsWith('SELECT ') : !c.options?.method,
    ),
  );
});

test('ordinary deployment recovers failed domain verification only after checking real CF bindings and never changes domain state', async () => {
  const completed = manifest();
  completed.worker_created = true;
  completed.security.status = 'ready';
  completed.journal = [{ step: 'worker-upload', state: 'complete' }];
  const domains = [
    {
      id: 'public-owned',
      hostname: EXPECTED.PUBLIC_HOSTNAME,
      service: 'shortlink-new',
      zone_id: EXPECTED.CF_ZONE_ID_GFW_MOM,
    },
    {
      id: 'admin-owned',
      hostname: EXPECTED.ADMIN_HOSTNAME,
      service: 'shortlink-new',
      zone_id: EXPECTED.CF_ZONE_ID_LILY_LAT,
    },
  ];
  const dnsZones = domains.map((domain) => domain.zone_id);
  const dns = domains.map((domain) => ({
    id: `dns-${domain.id}`,
    name: domain.hostname,
    type: 'AAAA',
    content: '100::',
    proxied: true,
  }));
  for (let i = 0; i < domains.length; i++) {
    completed.domains[domains[i].hostname] = {
      id: domains[i].id,
      zone_id: domains[i].zone_id,
      dns_signature: createHash('sha256')
        .update(
          JSON.stringify([
            { id: dns[i].id, type: dns[i].type, content: dns[i].content, proxied: true, meta: {} },
          ]),
        )
        .digest('hex'),
    };
  }
  const runtimeDomain = {
    hostname: EXPECTED.PUBLIC_HOSTNAME,
    bound: 0,
    enabled: 0,
    binding_state: 'failed',
  };
  const originalDomain = structuredClone(runtimeDomain);
  const originalManifest = structuredClone(completed);
  const bindings = [
    { name: 'RESOURCE_OWNER_ID', type: 'plain_text', text: owner },
    { name: 'DB', type: 'd1', id: d1 },
    { name: 'BACKUPS', type: 'r2_bucket', bucket_name: completed.bucket },
  ];
  const calls = [];
  const client = {
    optional: async (path, options) => {
      calls.push({ path, options });
      if (path === objectPath('delivery/ownership.json')) return JSON.stringify(completed);
      assert.equal(path, `${ACCOUNT}/workers/scripts/shortlink-new/settings`);
      return { result: { bindings } };
    },
    request: async (path, options) => {
      calls.push({ path, options });
      if (path.endsWith('/query')) {
        assert.match(options.json.sql, /^SELECT /);
        return {
          result: [
            {
              success: true,
              results: options.json.sql.includes('FROM domains')
                ? [runtimeDomain]
                : [
                    {
                      project: completed.project,
                      owner_id: owner,
                      account_id: completed.account,
                      worker: completed.worker,
                    },
                  ],
            },
          ],
        };
      }
      assert.ok(!options?.method || options.method === 'GET');
      const url = new URL(`https://x${path}`);
      if (url.pathname.endsWith('/r2/buckets'))
        return { result: { buckets: [{ name: completed.bucket }] } };
      if (url.pathname === `${ACCOUNT}/d1/database/${d1}`)
        return { result: { name: completed.d1.name, uuid: d1 } };
      let result;
      if (url.pathname.endsWith('/d1/database')) result = [{ name: completed.d1.name, uuid: d1 }];
      else if (url.pathname.endsWith('/workers/domains')) result = domains;
      else if (url.pathname.endsWith('/dns_records'))
        result = dns.filter((record, i) => url.pathname.includes(dnsZones[i]));
      else {
        assert.ok(url.pathname.endsWith('/workers/routes'));
        result = [];
      }
      return { result, result_info: { total_count: result.length } };
    },
  };
  assert.deepEqual(await prepareResources(client), originalManifest);
  assert.deepEqual(runtimeDomain, originalDomain);
  const publicDomain = domains.shift();
  await assert.rejects(prepareResources(client), { code: 'OWNED_DOMAIN_MISSING' });
  domains.unshift({ ...publicDomain, service: 'another-worker' });
  await assert.rejects(prepareResources(client), { code: 'EXISTING_DOMAIN_UNOWNED' });
  domains[0] = publicDomain;
  dns[0].id = 'replaced-dns-record';
  await assert.rejects(prepareResources(client), { code: 'OWNED_DNS_DRIFT_OR_UNPROVEN' });
  dns[0].id = 'dns-public-owned';
  bindings[0].text = 'another-owner';
  await assert.rejects(prepareResources(client), { code: 'EXISTING_WORKER_UNOWNED' });
  assert.deepEqual(runtimeDomain, originalDomain);
  assert.ok(
    calls.every(({ options }) =>
      options?.json
        ? options.json.sql.startsWith('SELECT ')
        : !options?.method || options.method === 'GET',
    ),
  );
});

test('local/manual/foreign repo/foreign worker guards stop before writes', () => {
  const allowed = {
    ...EXPECTED,
    GITHUB_ACTIONS: 'true',
    GITHUB_EVENT_NAME: 'workflow_dispatch',
    GITHUB_REPOSITORY: 'jacklilyhello/cloudflare-workers-shortlink',
    GITHUB_REF: 'refs/heads/main',
    CONFIRM_TARGET: 'initialize shortlink-new test only',
    CLOUDFLARE_API_TOKEN: 'dummy-token',
  };
  assert.doesNotThrow(() => requireAction(allowed, allowed.CONFIRM_TARGET));
  for (const changed of [
    { GITHUB_ACTIONS: '' },
    { GITHUB_EVENT_NAME: 'push' },
    { GITHUB_REF: 'refs/heads/codex/task' },
    { GITHUB_REPOSITORY: 'someone/else' },
    { WORKER_NAME: 'short-link' },
    { PUBLIC_HOSTNAME: 'gfw.mom' },
    { CONFIRM_TARGET: '' },
  ])
    assert.throws(
      () => requireAction({ ...allowed, ...changed }, allowed.CONFIRM_TARGET),
      DeliveryError,
    );
});
test('API client keeps authentication on fixed host, protects KV/legacy and hides remote secrets', async () => {
  const calls = [];
  const c = createCFClient('dummy-token', {
    fetcher: async (url, opts) => {
      calls.push({ url, opts });
      return response({});
    },
  });
  await c.request(`${ADMIN_ZONE}/settings`);
  assert.equal(calls[0].opts.redirect, 'error');
  assert.equal(new URL(calls[0].url).hostname, 'api.cloudflare.com');
  await assert.rejects(c.request('/accounts/other/workers/scripts/x/settings'), {
    code: 'FOREIGN_RESOURCE_FORBIDDEN',
  });
  await assert.rejects(c.request(`${ACCOUNT}/d1/database`, { method: 'POST', json: {} }), {
    code: 'LOCAL_CLOUDFLARE_WRITE_FORBIDDEN',
  });
  const w = createCFClient('dummy-token', { allowWrites: true, fetcher: c.request });
  await assert.rejects(
    w.request(`${ACCOUNT}/storage/kv/namespaces/${EXPECTED.LEGACY_KV_NAMESPACE_ID}/values/a`, {
      method: 'PUT',
      body: 'private-url',
    }),
    { code: 'PROTECTED_RESOURCE_WRITE_FORBIDDEN' },
  );
  await assert.rejects(w.request(`${ACCOUNT}/workers/scripts/short-link`, { method: 'PUT' }), {
    code: 'PROTECTED_RESOURCE_WRITE_FORBIDDEN',
  });
  const denied = createCFClient('dummy-token', {
    fetcher: async () =>
      new Response(
        JSON.stringify({
          success: false,
          errors: [{ code: 10000, message: 'private-secret-target-url' }],
        }),
        { status: 403 },
      ),
  });
  let error;
  try {
    await denied.request(`${ADMIN_ZONE}/settings`);
  } catch (e) {
    error = e;
  }
  assert.equal(error.code, 'PERMISSION_DENIED');
  assert.doesNotMatch(JSON.stringify(safeError(error)), /private-secret-target-url/);
});
test('403 diagnostics distinguish bounded media, JSON shape and numeric error counts without response text', async (t) => {
  const privateValue = 'synthetic-secret-target-header-value';
  const cases = [
    {
      name: 'HTML denial',
      body: `<html>${privateValue}</html>`,
      contentType: 'text/html; charset=UTF-8',
      media: 'HTML',
      shape: 'NON_JSON',
      count: null,
      numeric: null,
      codes: [],
    },
    {
      name: 'plain-text denial',
      body: privateValue,
      contentType: 'text/plain',
      media: 'TEXT',
      shape: 'NON_JSON',
      count: null,
      numeric: null,
      codes: [],
    },
    {
      name: 'JSON object without an errors array',
      body: '{}',
      contentType: 'Application/JSON; charset=utf-8',
      media: 'JSON',
      shape: 'JSON_OBJECT',
      count: null,
      numeric: null,
      codes: [],
    },
    {
      name: 'nonnumeric error codes are not coerced',
      body: JSON.stringify({
        success: false,
        errors: [
          { code: '10000', message: privateValue },
          { code: privateValue },
          { code: 1.5 },
          null,
        ],
      }),
      contentType: 'application/problem+json',
      media: 'JSON',
      shape: 'JSON_OBJECT',
      count: 4,
      numeric: 0,
      codes: [],
      codeShape: 'MIXED',
      messageHint: 'OTHER',
    },
    {
      name: 'numeric JSON errors retain existing codes',
      body: JSON.stringify({
        success: false,
        errors: [
          { code: 10000, message: privateValue, documentation_url: `https://${privateValue}` },
          { code: 9109, message: privateValue },
        ],
      }),
      contentType: 'application/json',
      media: 'JSON',
      shape: 'JSON_OBJECT',
      count: 2,
      numeric: 2,
      codes: [10000, 9109],
      codeShape: 'INTEGER',
      messageHint: 'OTHER',
    },
    {
      name: 'empty errors array is a known zero',
      body: '{"success":false,"errors":[]}',
      contentType: 'application/octet-stream',
      media: 'OTHER',
      shape: 'JSON_OBJECT',
      count: 0,
      numeric: 0,
      codes: [],
      codeShape: 'NONE',
      messageHint: 'NONE',
    },
    {
      name: 'JSON array is not a provider error object',
      body: JSON.stringify([{ message: privateValue }]),
      contentType: 'application/json',
      media: 'JSON',
      shape: 'JSON_OTHER',
      count: null,
      numeric: null,
      codes: [],
    },
    {
      name: 'JSON null does not become a successful credential check',
      body: 'null',
      contentType: 'application/json',
      media: 'JSON',
      shape: 'JSON_OTHER',
      count: null,
      numeric: null,
      codes: [],
    },
    {
      name: 'missing content type stays unknown',
      body: privateValue,
      contentType: null,
      media: 'MISSING',
      shape: 'NON_JSON',
      count: null,
      numeric: null,
      codes: [],
    },
  ];
  for (const fixture of cases) {
    await t.test(fixture.name, async () => {
      let requests = 0;
      const client = createCFClient(privateValue, {
        fetcher: async (address, options) => {
          requests++;
          assert.equal(address, `https://api.cloudflare.com/client/v4${ADMIN_ZONE}/settings`);
          assert.equal(options.method, 'GET');
          assert.equal(options.redirect, 'error');
          const response = new Response(fixture.body, {
            status: 403,
            headers: { 'x-private-fixture': privateValue, 'cf-mitigated': privateValue },
          });
          if (fixture.contentType) response.headers.set('content-type', fixture.contentType);
          else response.headers.delete('content-type');
          return response;
        },
      });
      await assert.rejects(client.request(`${ADMIN_ZONE}/settings`), (error) => {
        assert.ok(error instanceof DeliveryError);
        assert.deepEqual(safeError(error), {
          code: 'PERMISSION_DENIED',
          http_status: 403,
          cf_error_codes: fixture.codes,
          endpoint_category: 'ZONE_SETTINGS',
          request_method: 'GET',
          media_type: fixture.media,
          body_shape: fixture.shape,
          numeric_code_count: fixture.numeric,
          error_count: fixture.count,
          error_code_shape: fixture.codeShape || 'UNKNOWN',
          error_message_hint: fixture.messageHint || 'UNKNOWN',
          cf_mitigated: 'NONE',
          detail: 'Raw responses, credentials and business data are withheld.',
        });
        assert.doesNotMatch(
          JSON.stringify(error.responseContext) + JSON.stringify(safeError(error)),
          /synthetic-secret|https:|\/zones\/|Bearer|documentation_url|x-private/,
        );
        return true;
      });
      assert.equal(requests, 1, 'diagnostics never retry the request');
    });
  }
});
test('403 diagnostic counts are capped while the original eight-code limit is preserved', async () => {
  const errors = Array.from({ length: 1001 }, (_, index) => ({ code: 10000 + index }));
  const client = createCFClient('synthetic-token', {
    fetcher: async () => Response.json({ success: false, errors }, { status: 403 }),
  });
  await assert.rejects(client.request(`${ADMIN_ZONE}/settings`), (error) => {
    const safe = safeError(error);
    assert.deepEqual(
      safe.cf_error_codes,
      errors.slice(0, 8).map((entry) => entry.code),
    );
    assert.equal(safe.numeric_code_count, 1000);
    assert.equal(safe.error_count, 1000);
    assert.equal(safe.error_code_shape, 'UNKNOWN');
    assert.equal(safe.error_message_hint, 'UNKNOWN');
    return true;
  });
});
test('403 code shapes and bounded lexical hints preserve refusal and never reveal provider strings', async (t) => {
  const privateValue = `sl_${'d'.repeat(64)}`;
  const privateURL = `https://example.invalid/private/${privateValue}`;
  const cases = [
    {
      name: 'integer permission error',
      errors: [{ code: 10000, message: `Permission denied: ${privateValue}` }],
      shape: 'INTEGER',
      hint: 'PERMISSION',
      codes: [10000],
    },
    {
      name: 'decimal string remains separate from numeric CF codes',
      errors: [{ code: '10000', message: `Not authorized ${privateValue}` }],
      shape: 'DECIMAL_STRING',
      hint: 'PERMISSION',
      codes: [],
    },
    {
      name: 'other string and syntax validation',
      errors: [{ code: 'provider-symbol', message: `Invalid syntax ${privateValue}` }],
      shape: 'OTHER_STRING',
      hint: 'VALIDATION',
      codes: [],
    },
    {
      name: 'missing code and entitlement clue',
      errors: [{ message: `Plan entitlement requires upgrade ${privateValue}` }],
      shape: 'MISSING',
      hint: 'ENTITLEMENT',
      codes: [],
    },
    {
      name: 'asset prose is a clue without exposing the asset address',
      errors: [{ code: null, message: `Custom error asset was not found ${privateURL}` }],
      shape: 'UNKNOWN',
      hint: 'ASSET',
      codes: [],
    },
    {
      name: 'noninteger numeric code and unsupported clue',
      errors: [{ code: 1.5, message: `Operation is not supported ${privateValue}` }],
      shape: 'UNKNOWN',
      hint: 'UNSUPPORTED',
      codes: [],
    },
    {
      name: 'provider text without a known clue stays other',
      errors: [{ code: 'withheld', message: `${privateValue} ${privateURL}` }],
      shape: 'OTHER_STRING',
      hint: 'OTHER',
      codes: [],
    },
    {
      name: 'missing messages are a known absence',
      errors: [{ code: 10000 }, { code: 9109, message: null }],
      shape: 'INTEGER',
      hint: 'NONE',
      codes: [10000, 9109],
    },
    {
      name: 'multiple error shapes and multiple messages are mixed',
      errors: [
        { code: 10000, message: `Forbidden ${privateValue}` },
        { code: '10000', message: `Asset name could not be found ${privateValue}` },
        {},
      ],
      shape: 'MIXED',
      hint: 'MIXED',
      codes: [10000],
    },
    {
      name: 'one message can contain multiple distinct clues',
      errors: [
        { code: '10000', message: `Permission to access this asset was denied ${privateValue}` },
      ],
      shape: 'DECIMAL_STRING',
      hint: 'MIXED',
      codes: [],
    },
    {
      name: 'keywords inside URL and absolute or relative paths are not prose clues',
      errors: [
        {
          code: 10000,
          message: `Request failed https://example.invalid/asset/permission/plan/invalid/unsupported /asset/plan/invalid/unsupported asset/permission/${privateValue}`,
        },
      ],
      shape: 'INTEGER',
      hint: 'OTHER',
      codes: [10000],
    },
    {
      name: 'permission prose is not reclassified by an asset in the URL',
      errors: [
        { code: 10000, message: `Permission denied https://example.invalid/asset/${privateValue}` },
      ],
      shape: 'INTEGER',
      hint: 'PERMISSION',
      codes: [10000],
    },
    {
      name: 'oversized messages are not partially classified',
      errors: [{ code: '10000', message: `Permission denied ${privateValue}${'x'.repeat(2048)}` }],
      shape: 'DECIMAL_STRING',
      hint: 'UNKNOWN',
      codes: [],
    },
    {
      name: 'oversized code strings are not scanned or coerced',
      errors: [{ code: '1'.repeat(2049), message: `Forbidden ${privateValue}` }],
      shape: 'UNKNOWN',
      hint: 'PERMISSION',
      codes: [],
    },
    {
      name: 'malformed message data remains unknown',
      errors: [{ code: true, message: { privateValue, permission: 'denied' } }],
      shape: 'UNKNOWN',
      hint: 'UNKNOWN',
      codes: [],
    },
  ];
  const path = `${ADMIN_ZONE}/rulesets/${'1'.repeat(32)}/rules/${'2'.repeat(32)}?dry_run=true`;
  for (const fixture of cases) {
    await t.test(fixture.name, async () => {
      let requests = 0;
      const client = createCFClient(privateValue, {
        allowWrites: true,
        fetcher: async (address, options) => {
          requests++;
          assert.equal(address, `https://api.cloudflare.com/client/v4${path}`);
          assert.equal(options.method, 'PATCH');
          assert.equal(options.redirect, 'error');
          return Response.json(
            {
              success: false,
              errors: fixture.errors,
              documentation_url: privateURL,
              messages: [{ code: 10000, message: `Asset permission ${privateValue}` }],
            },
            { status: 403, headers: { 'x-private-fixture': privateValue } },
          );
        },
      });
      await assert.rejects(
        client.request(path, { method: 'PATCH', json: { enabled: true } }),
        (error) => {
          assert.equal(error.code, 'PERMISSION_DENIED');
          assert.equal(error.status, 403);
          const safe = safeError(error);
          assert.equal(safe.error_code_shape, fixture.shape);
          assert.equal(safe.error_message_hint, fixture.hint);
          assert.deepEqual(safe.cf_error_codes, fixture.codes);
          assert.equal(safe.endpoint_category, 'ZONE_RULESETS');
          assert.equal(safe.request_method, 'PATCH');
          assert.equal(safe.cf_mitigated, 'NONE');
          const serialized = JSON.stringify(error.responseContext) + JSON.stringify(safe);
          assert.ok(!serialized.includes(privateValue));
          assert.doesNotMatch(
            serialized,
            /example\.invalid|provider-symbol|documentation_url|x-private|\/rulesets\/|Bearer/,
          );
          return true;
        },
      );
      assert.equal(requests, 1, 'classification does not authorize or retry a denied request');
    });
  }
});
test('safe error contexts reject spoofed text, extra fields and unbounded counts', () => {
  const privateValue = 'synthetic-secret-private-body';
  const unknown = {
    media_type: privateValue,
    body_shape: privateValue,
    numeric_code_count: Infinity,
    error_count: -1,
    error_code_shape: privateValue,
    error_message_hint: privateValue,
    cf_mitigated: privateValue,
    raw_body: privateValue,
  };
  const error = new DeliveryError('FIXED_CODE', 403, [], 'ZONE_RULESETS', unknown);
  assert.doesNotMatch(JSON.stringify(error.responseContext), /synthetic-secret|raw_body/);
  error.responseContext = { ...unknown, numeric_code_count: 1001, error_count: '1' };
  for (const candidate of [error, new Error(privateValue)]) {
    const safe = safeError(candidate);
    assert.equal(safe.media_type, 'MISSING');
    assert.equal(safe.body_shape, null);
    assert.equal(safe.numeric_code_count, null);
    assert.equal(safe.error_count, null);
    assert.equal(safe.error_code_shape, 'UNKNOWN');
    assert.equal(safe.error_message_hint, 'UNKNOWN');
    assert.equal(safe.cf_mitigated, 'NONE');
    assert.doesNotMatch(JSON.stringify(safe), /synthetic-secret|raw_body/);
  }
});
test('CF challenge classification cancels unread bodies and records only its fixed enum', async () => {
  const streamed = streamedResponse([Buffer.from('synthetic-secret-challenge-body')], {
    status: 403,
    headers: { 'cf-mitigated': 'challenge', 'content-type': 'text/html' },
  });
  const client = createCFClient('synthetic-token', { fetcher: async () => streamed.response });
  await assert.rejects(client.request(`${ADMIN_ZONE}/settings`), (error) => {
    const safe = safeError(error);
    assert.equal(safe.code, 'CF_API_CHALLENGE');
    assert.equal(safe.http_status, 403);
    assert.equal(safe.media_type, 'HTML');
    assert.equal(safe.body_shape, null);
    assert.equal(safe.numeric_code_count, null);
    assert.equal(safe.error_count, null);
    assert.equal(safe.error_code_shape, 'UNKNOWN');
    assert.equal(safe.error_message_hint, 'UNKNOWN');
    assert.equal(safe.cf_mitigated, 'CHALLENGE');
    assert.doesNotMatch(JSON.stringify(safe), /synthetic-secret|challenge-body/);
    return true;
  });
  assert.equal(streamed.observed.pulls, 0);
  assert.equal(streamed.observed.cancellations, 1);
});
const rawValuePath = `${ACCOUNT}/storage/kv/namespaces/${EXPECTED.LEGACY_KV_NAMESPACE_ID}/values/private-fixture-key`;
function streamedResponse(chunks, { status = 200, headers = {} } = {}) {
  const observed = { pulls: 0, cancellations: 0 };
  let next = 0;
  const body = new ReadableStream(
    {
      pull(controller) {
        observed.pulls++;
        if (next === chunks.length) controller.close();
        else controller.enqueue(chunks[next++]);
      },
      cancel() {
        observed.cancellations++;
      },
    },
    { highWaterMark: 0 },
  );
  return { response: new Response(body, { status, headers }), observed };
}
test('bounded CF raw reads preserve split UTF-8 and a genuinely encoded replacement character', async () => {
  const original = 'https://example.com/中🙂?encoded=%2f&repeat=one&repeat=two#\uFFFD';
  const encoded = Buffer.from(original);
  const streamed = streamedResponse(Array.from(encoded, (byte) => Uint8Array.of(byte)));
  const client = createCFClient('dummy-token', {
    fetcher: async () => streamed.response,
  });
  const actual = await client.request(rawValuePath, { raw: true, maxBytes: 16 * 1024 });
  assert.equal(actual, original);
  assert.deepEqual(Buffer.from(actual), encoded);
  assert.equal(streamed.observed.pulls, encoded.length + 1);
});
test('bounded CF reads preserve a raw BOM without normalizing JSON responses', async () => {
  const bom = Buffer.from([0xef, 0xbb, 0xbf]);
  const rawBytes = Buffer.concat([bom, Buffer.from('https://example.com/中')]);
  const rawClient = createCFClient('dummy-token', {
    fetcher: async () => streamedResponse([rawBytes.subarray(0, 1), rawBytes.subarray(1)]).response,
  });
  const raw = await rawClient.request(rawValuePath, { raw: true });
  assert.equal(raw.charCodeAt(0), 0xfeff);
  assert.deepEqual(Buffer.from(raw), rawBytes);
  const jsonClient = createCFClient('dummy-token', {
    fetcher: async () =>
      new Response(Buffer.concat([bom, Buffer.from('{"success":true,"result":{}}')])),
  });
  await assert.rejects(jsonClient.request(`${ADMIN_ZONE}/settings`), {
    code: 'NON_JSON_RESPONSE',
    status: 200,
  });
});
test('malformed, overlong and truncated raw UTF-8 fail with the original HTTP status and safe diagnostics', async (t) => {
  const privateValue = 'private-credential-url-key-fixture';
  for (const [name, malformed] of [
    ['invalid byte', [0xff]],
    ['invalid continuation', [0xe2, 0x28, 0xa1]],
    ['overlong sequence', [0xc0, 0xaf]],
    ['truncated sequence', [0xe2, 0x82]],
  ]) {
    for (const status of [200, 201, 401, 403, 429, 500]) {
      await t.test(`${name}, HTTP ${status}`, async () => {
        const bytes = Buffer.concat([
          Buffer.from(`https://example.com/${privateValue}`),
          Buffer.from(malformed),
        ]);
        const streamed = streamedResponse(
          Array.from(bytes, (byte) => Uint8Array.of(byte)),
          { status },
        );
        const client = createCFClient(privateValue, { fetcher: async () => streamed.response });
        await assert.rejects(
          client.optional(`${rawValuePath}?private=${privateValue}`, { raw: true }),
          (error) => {
            assert.ok(error instanceof DeliveryError);
            assert.equal(error.message, 'INVALID_UTF8_RESPONSE');
            const safe = safeError(error);
            assert.deepEqual(safe, {
              code: 'INVALID_UTF8_RESPONSE',
              http_status: status,
              cf_error_codes: [],
              endpoint_category: 'LEGACY_KV_VALUE',
              request_method: 'GET',
              media_type: 'MISSING',
              body_shape: null,
              numeric_code_count: null,
              error_count: null,
              error_code_shape: 'UNKNOWN',
              error_message_hint: 'UNKNOWN',
              cf_mitigated: 'NONE',
              detail: 'Raw responses, credentials and business data are withheld.',
            });
            assert.doesNotMatch(
              JSON.stringify(safe),
              /private-|example\.com|\/accounts\/|Bearer|decoder|encoded data/,
            );
            return true;
          },
        );
        assert.equal(streamed.observed.pulls, bytes.length + 1);
      });
    }
  }
});
test('invalid UTF-8 in a CF JSON response is distinct from valid UTF-8 with invalid JSON syntax', async () => {
  const invalidBytes = Buffer.concat([
    Buffer.from('{"success":true,"result":"private-json-fixture-'),
    Buffer.from([0xff]),
    Buffer.from('"}'),
  ]);
  const invalidUTF8 = createCFClient('dummy-token', {
    fetcher: async () => new Response(invalidBytes, { status: 200 }),
  });
  await assert.rejects(invalidUTF8.request(`${ADMIN_ZONE}/settings`), (error) => {
    assert.equal(error.code, 'INVALID_UTF8_RESPONSE');
    assert.equal(error.status, 200);
    assert.equal(safeError(error).endpoint_category, 'ZONE_SETTINGS');
    assert.doesNotMatch(JSON.stringify(safeError(error)), /private-json-fixture/);
    return true;
  });
  const invalidJSON = createCFClient('dummy-token', {
    fetcher: async () => new Response('private-json-fixture-\uFFFD{'),
  });
  await assert.rejects(invalidJSON.request(`${ADMIN_ZONE}/settings`), {
    code: 'NON_JSON_RESPONSE',
    status: 200,
  });
});
test('valid UTF-8 error responses retain authentication and permission classification without leaking messages', async () => {
  for (const [status, code] of [
    [401, 'AUTH_FAILED'],
    [403, 'PERMISSION_DENIED'],
  ]) {
    const privateValue = 'private-error-fixture-中-\uFFFD';
    const encoded = Buffer.from(
      JSON.stringify({ success: false, errors: [{ code: 10000, message: privateValue }] }),
    );
    const client = createCFClient('dummy-token', {
      fetcher: async () =>
        streamedResponse(
          Array.from(encoded, (byte) => Uint8Array.of(byte)),
          { status },
        ).response,
    });
    await assert.rejects(client.request(`${ACCOUNT}/tokens/verify`), (error) => {
      assert.equal(error.code, code);
      assert.equal(error.status, status);
      assert.deepEqual(error.cfCodes, [10000]);
      assert.doesNotMatch(JSON.stringify(safeError(error)), /private-error-fixture|中|\uFFFD/);
      return true;
    });
  }
});
test('oversized CF bodies still cancel before UTF-8 decoding for successful and denied requests', async (t) => {
  const maxBytes = 16 * 1024;
  const oversized = Buffer.alloc(maxBytes + 1, 0xff);
  for (const status of [200, 403]) {
    for (const declared of [true, false]) {
      await t.test(`HTTP ${status}, ${declared ? 'declared' : 'streamed'} size`, async () => {
        const streamed = streamedResponse([oversized], {
          status,
          headers: declared ? { 'content-length': String(oversized.length) } : {},
        });
        const client = createCFClient('dummy-token', { fetcher: async () => streamed.response });
        await assert.rejects(client.request(rawValuePath, { raw: true, maxBytes }), {
          code: 'RESPONSE_TOO_LARGE',
          status,
        });
        assert.equal(streamed.observed.pulls, declared ? 0 : 1);
        assert.equal(streamed.observed.cancellations, 1);
      });
    }
  }
});
test('CF failures expose only fixed endpoint categories, never paths, private keys, tokens or responses', async () => {
  const privateValue = 'private-business-url-token-key';
  const denied = createCFClient(privateValue, {
    fetcher: async () =>
      new Response(
        JSON.stringify({ success: false, errors: [{ code: 10000, message: privateValue }] }),
        { status: 403 },
      ),
  });
  for (const [path, category] of [
    [`${ACCOUNT}/tokens/verify`, 'ACCOUNT_TOKEN_VERIFY'],
    [`${ACCOUNT}/tokens/${'a'.repeat(32)}`, 'ACCOUNT_TOKEN_POLICY'],
    [`${ADMIN_ZONE}/bot_management`, 'ZONE_BOT_MANAGEMENT'],
    [
      `${ACCOUNT}/storage/kv/namespaces/${EXPECTED.LEGACY_KV_NAMESPACE_ID}/values/${privateValue}?query=${privateValue}`,
      'LEGACY_KV_VALUE',
    ],
    [objectPath(`delivery/${owner}/${privateValue}.json`), 'R2_OBJECT'],
  ]) {
    let failure;
    try {
      await denied.request(path);
    } catch (error) {
      failure = safeError(error);
    }
    assert.equal(failure.endpoint_category, category);
    assert.equal(failure.request_method, 'GET');
    assert.equal(failure.code, 'PERMISSION_DENIED');
    assert.deepEqual(failure.cf_error_codes, [10000]);
    assert.doesNotMatch(JSON.stringify(failure), /private-business|\/accounts\/|query=|\.json/);
  }
  assert.equal(
    safeError(new DeliveryError('FIXED_CODE', 403, [], privateValue)).endpoint_category,
    null,
  );
  const spoofed = new DeliveryError('FIXED_CODE');
  spoofed.endpointCategory = privateValue;
  spoofed.requestMethod = privateValue;
  assert.equal(safeError(spoofed).endpoint_category, null);
  assert.equal(safeError(spoofed).request_method, null);
  let writeFailure;
  const deniedWrite = createCFClient(privateValue, {
    allowWrites: true,
    fetcher: async () =>
      new Response(JSON.stringify({ success: false, errors: [{ code: 10000 }] }), { status: 403 }),
  });
  try {
    await deniedWrite.request(`${ACCOUNT}/r2/buckets`, {
      method: 'POST',
      json: { name: 'shortlink-new-backups' },
    });
  } catch (error) {
    writeFailure = safeError(error);
  }
  assert.equal(writeFailure.endpoint_category, 'R2_BUCKETS');
  assert.equal(writeFailure.request_method, 'POST');
});
test('token verification or fixed resource refusal stops account preflight before any write', async () => {
  for (const failedEndpoint of ['ACCOUNT_TOKEN_VERIFY', 'PUBLIC_ZONE_DETAILS']) {
    const calls = [];
    const client = createCFClient('dummy-token', {
      allowWrites: true,
      fetcher: async (url, options) => {
        calls.push({ url, options });
        const path = new URL(url).pathname;
        if (path.endsWith('/tokens/verify') && failedEndpoint !== 'ACCOUNT_TOKEN_VERIFY')
          return response({ status: 'active', id: 'a'.repeat(32) });
        // Policy GET 403 is optional; neither verify nor fixed Zone 403 is treated as permission success.
        return new Response(
          JSON.stringify({ success: false, errors: [{ code: 10000, message: 'withheld' }] }),
          { status: 403 },
        );
      },
    });
    await assert.rejects(verifyAccount(client), (error) => {
      assert.equal(safeError(error).endpoint_category, failedEndpoint);
      return error.code === 'PERMISSION_DENIED';
    });
    assert.equal(calls.length, failedEndpoint === 'ACCOUNT_TOKEN_VERIFY' ? 1 : 3);
    assert.ok(calls.every((call) => call.options.method === 'GET'));
    assert.ok(calls.every((call) => !call.url.includes('/user/tokens/verify')));
  }
});
test('write timeouts are ambiguous and never blindly retried', async () => {
  let calls = 0;
  const c = createCFClient('dummy-token', {
    allowWrites: true,
    fetcher: async () => {
      calls++;
      throw new Error('private-network-detail');
    },
  });
  await assert.rejects(
    c.request(`${ACCOUNT}/d1/database`, { method: 'POST', json: { name: 'shortlink-new-test' } }),
    { code: 'WRITE_RESULT_UNKNOWN_RECONCILE_REQUIRED' },
  );
  assert.equal(calls, 1);
});
test('pagination reads every page and rejects partial/repeated cursors', async () => {
  let calls = 0;
  const all = await listAll(
    {
      request: async (path) => {
        calls++;
        const p = new URL(`https://x${path}`).searchParams.get('page');
        return { result: [{ id: p }], result_info: { total_pages: 2, total_count: 2 } };
      },
    },
    `${ACCOUNT}/access/apps`,
    { pageSize: 1 },
  );
  assert.equal(all.length, 2);
  assert.equal(calls, 2);
  await assert.rejects(
    listAll(
      { request: async () => ({ result: [], result_info: { total_count: 5 } }) },
      `${ACCOUNT}/access/apps`,
    ),
    { code: 'INCOMPLETE_PAGINATION' },
  );
  await assert.rejects(
    listAll(
      { request: async () => ({ result: [1], result_info: { cursor: 'same' } }) },
      `${ACCOUNT}/access/apps`,
    ),
    { code: 'PAGINATION_CURSOR_REPEATED' },
  );
});
test('official Rulesets pagination uses max 50 and cursors.after, with no page parameter', async () => {
  const calls = [];
  const result = await listAll(
    {
      request: async (path) => {
        const params = new URL(`https://x${path}`).searchParams;
        calls.push(params);
        assert.equal(params.get('per_page'), '50');
        assert.equal(params.has('page'), false);
        return params.has('cursor')
          ? { result: [{ id: 'second' }], result_info: { cursors: {} } }
          : { result: [{ id: 'first' }], result_info: { cursors: { after: 'next-cursor' } } };
      },
    },
    `${ADMIN_ZONE}/rulesets`,
  );
  assert.equal(result.length, 2);
  assert.equal(calls[1].get('cursor'), 'next-cursor');
});
test('qualification understands official read names without mistaking product names for actions', async () => {
  const read = {
    name: 'local-shortlink-readonly',
    policies: [
      {
        effect: 'allow',
        permission_groups: [
          'Bot Management Read',
          'Managed headers Read',
          'Account Rule Lists Read',
          'Read-Only',
          'Read PCAPs',
        ].map((name) => ({ name })),
        resources: { [`com.cloudflare.api.account.${EXPECTED.CLOUDFLARE_ACCOUNT_ID}`]: '*' },
      },
    ],
  };
  assert.equal(qualifyPolicy(read).result, 'READONLY_QUALIFIED');
  const edited = structuredClone(read);
  edited.policies[0].permission_groups.push({ name: 'Zone WAF Write' });
  assert.equal(qualifyPolicy(edited).result, 'PENDING');
  const unnamed = structuredClone(read);
  unnamed.name = 'global-token';
  assert.equal(qualifyPolicy(unnamed).result, 'PENDING');
  const calls = [];
  const result = await qualify({ CLOUDFLARE_API_TOKEN: 'dummy-token' }, async (url) => {
    calls.push(new URL(url).pathname);
    return response(url.endsWith('/verify') ? { id: 'c'.repeat(32), status: 'active' } : read);
  });
  assert.equal(result.result, 'READONLY_QUALIFIED');
  assert.equal(calls.length, 2);
  assert.match(calls[0], /\/tokens\/verify$/);
  assert.match(calls[1], /\/tokens\/c{32}$/);
});
test('same-named unowned bucket or worker is refused before creation', async () => {
  const calls = [];
  const c = {
    request: async (path, options) => {
      calls.push({ path, options });
      if (path.includes('/r2/buckets?'))
        return {
          result: { buckets: [{ name: 'shortlink-new-backups' }] },
          result_info: { total_count: 1 },
        };
      throw new Error('unexpected');
    },
    optional: async (path) => {
      assert.equal(path, objectPath('delivery/ownership.json'));
      return null;
    },
  };
  await assert.rejects(prepareResources(c, { bootstrap: true }), {
    code: 'EXISTING_R2_BUCKET_UNOWNED',
  });
  assert.ok(calls.every((x) => !x.options?.method || x.options.method === 'GET'));
  const m = manifest();
  assert.doesNotThrow(() => validateManifest(m));
  assert.throws(() => validateManifest({ ...m, worker: 'short-link' }), {
    code: 'RESOURCE_OWNERSHIP_UNPROVEN',
  });
  assert.equal(workerOwnerMatches({ bindings: [{ name: 'DB', type: 'd1', id: d1 }] }, m), false);
});
test('D1 checkpoint recovery requires exact owned marker, not a name or creation intent', async () => {
  const m = manifest();
  delete m.d1;
  m.journal = [{ step: 'create-d1', state: 'intent' }];
  const writes = [];
  const client = {
    request: async (path, options) => {
      if (path.endsWith('/query')) {
        assert.match(options.json.sql, /^SELECT project/);
        return {
          result: [
            {
              success: true,
              results: [
                { project: m.project, owner_id: owner, account_id: m.account, worker: m.worker },
              ],
            },
          ],
        };
      }
      writes.push(path);
      return { result: {} };
    },
  };
  await reconcileD1(client, m, { name: 'shortlink-new-test', uuid: d1 });
  assert.equal(m.d1.id, d1);
  assert.deepEqual(writes, [objectPath('delivery/ownership.json')]);
  const bad = manifest();
  delete bad.d1;
  bad.journal = [{ step: 'create-d1', state: 'intent' }];
  await assert.rejects(
    reconcileD1(
      {
        request: async () => ({
          result: [{ success: true, results: [{ owner_id: 'someone-else' }] }],
        }),
      },
      bad,
      { name: 'shortlink-new-test', uuid: d1 },
    ),
    { code: 'EXISTING_D1_UNOWNED' },
  );
  assert.equal(bad.d1, undefined);
});
test('Custom Domain recovery is limited to recorded owner/zone/service intent and verifies DNS fingerprint', async () => {
  const m = manifest();
  m.worker_created = true;
  m.domain_intents = {
    'test.gfw.mom': {
      owner_id: owner,
      zone_id: EXPECTED.CF_ZONE_ID_GFW_MOM,
      service: 'shortlink-new',
    },
  };
  const writes = [];
  const client = {
    optional: async () => ({
      result: {
        bindings: [
          { name: 'RESOURCE_OWNER_ID', type: 'plain_text', text: owner },
          { name: 'DB', type: 'd1', id: d1 },
          { name: 'BACKUPS', type: 'r2_bucket', bucket_name: 'shortlink-new-backups' },
        ],
      },
    }),
    request: async (path, options) => {
      if (options?.method === 'PUT') {
        writes.push(path);
        return { result: {} };
      }
      if (path.endsWith('/query'))
        return {
          result: [
            {
              success: true,
              results: [
                { project: m.project, owner_id: owner, account_id: m.account, worker: m.worker },
              ],
            },
          ],
        };
      if (path === `${ACCOUNT}/d1/database/${d1}`)
        return { result: { name: 'shortlink-new-test', uuid: d1 } };
      const result = path.includes('/dns_records')
        ? [
            {
              id: 'dns-created',
              name: 'test.gfw.mom',
              type: 'AAAA',
              content: '100::',
              proxied: true,
            },
          ]
        : path.includes('/workers/domains')
          ? [
              {
                id: 'domain-created',
                hostname: 'test.gfw.mom',
                service: 'shortlink-new',
                zone_id: EXPECTED.CF_ZONE_ID_GFW_MOM,
              },
            ]
          : [];
      return { result, result_info: { total_count: result.length } };
    },
  };
  await inspectHost(client, 'test.gfw.mom', m, { recover: true });
  assert.equal(m.domains['test.gfw.mom'].id, 'domain-created');
  assert.match(m.domains['test.gfw.mom'].dns_signature, /^[a-f\d]{64}$/);
  assert.ok(writes.every((p) => p === objectPath('delivery/ownership.json')));
  const stolen = manifest();
  stolen.worker_created = true;
  stolen.domain_intents = {
    'test.gfw.mom': { ...m.domain_intents['test.gfw.mom'], owner_id: 'other' },
  };
  await assert.rejects(inspectHost(client, 'test.gfw.mom', stolen, { recover: true }), {
    code: 'EXISTING_DOMAIN_UNOWNED',
  });
});
test('wildcard routes and preexisting custom domains fail closed without overwriting', async () => {
  const c = {
    request: async (path) => ({
      result: path.includes('/workers/routes')
        ? [{ pattern: '*.gfw.mom/*', script: 'existing' }]
        : path.includes('/workers/domains')
          ? []
          : [],
      result_info: { total_count: path.includes('/workers/routes') ? 1 : 0 },
    }),
  };
  await assert.rejects(inspectHost(c, 'test.gfw.mom', manifest()), {
    code: 'BROAD_OR_EXISTING_WORKER_ROUTE_CONFLICT',
  });
  assert.equal(accessAppTouchesHost({ domain: '*.lily.lat' }, 'link-admin.lily.lat'), true);
  assert.equal(
    accessAppTouchesHost(
      {
        domain: 'other.example.com',
        destinations: [{ uri: 'link-admin.lily.lat/admin', type: 'public' }],
      },
      'link-admin.lily.lat',
    ),
    true,
  );
});
test('Access allows only two direct emails; Bypass is isolated from administrator identity', () => {
  const p = {
    decision: 'allow',
    include: EXPECTED.ADMIN_EMAILS.split(',').map((email) => ({ email: { email } })),
  };
  assert.doesNotThrow(() => validateAccessPolicy([p]));
  assert.throws(() => validateAccessPolicy([{ ...p, include: [{ everyone: {} }] }]), {
    code: 'ACCESS_EMAILS_UNSAFE',
  });
  assert.throws(
    () => validateAccessPolicy([p, { decision: 'bypass', include: [{ everyone: {} }] }]),
    { code: 'ACCESS_POLICY_COUNT_UNSAFE' },
  );
  assert.doesNotThrow(() =>
    validateAccessPolicy([{ decision: 'bypass', include: [{ everyone: {} }] }], true),
  );
});
test('production requires explicit complementary deny before narrowed Skip, no widening or OR', () => {
  const temporary = [
    ownRule(GUARD_REF, 'block', GUARD_MATCH),
    ownRule(SKIP_REF, 'skip', API_MATCH),
  ];
  assert.throws(() => productionPolicyReady(temporary, owner), {
    code: 'PRODUCTION_TEMPORARY_ALL_IP_FORBIDDEN',
  });
  const restricted = [
    ownRule(GUARD_REF, 'block', GUARD_MATCH),
    ownRule(DENY_REF, 'block', `${API_MATCH} and not (ip.src in $shortlink_api_allowlist)`),
    ownRule(SKIP_REF, 'skip', `${API_MATCH} and (ip.src in $shortlink_api_allowlist)`),
  ];
  assert.equal(productionPolicyReady(restricted, owner), true);
  assert.throws(() => productionPolicyReady([restricted[0], restricted[2], restricted[1]], owner), {
    code: 'PRODUCTION_DENY_OUTSIDE_ALLOWLIST_REQUIRED',
  });
  assert.throws(() => apiIPCondition(`${API_MATCH} or true`), { code: 'WAF_SKIP_SCOPE_UNSAFE' });
  assert.throws(() => apiIPCondition('(http.host eq "link-admin.lily.lat")'), {
    code: 'WAF_SKIP_SCOPE_UNSAFE',
  });
  assert.throws(
    () => apiIPCondition(`${API_MATCH} and (ip.src in $shortlink_api_allowlist or true)`),
    { code: 'WAF_IP_CONDITION_REVIEW_REQUIRED' },
  );
});
test('production rejects earlier Skips that could bypass the outside-allowlist Block', () => {
  const deny = ownRule(
    DENY_REF,
    'block',
    `${API_MATCH} and not (ip.src in $shortlink_api_allowlist)`,
  );
  const restricted = [
    ownRule(GUARD_REF, 'block', GUARD_MATCH),
    deny,
    ownRule(SKIP_REF, 'skip', `${API_MATCH} and (ip.src in $shortlink_api_allowlist)`),
  ];
  const earlier = {
    id: 'unrelated-skip',
    action: 'skip',
    expression: 'true',
    enabled: true,
    action_parameters: { ruleset: 'current' },
  };
  for (const action_parameters of [
    { ruleset: 'current' },
    { rules: { 'custom-ruleset': [deny.id] } },
    { phases: ['http_request_firewall_custom'] },
  ])
    assert.throws(
      () => productionPolicyReady([{ ...earlier, action_parameters }, ...restricted], owner),
      { code: 'PRODUCTION_EARLIER_SKIP_CAN_BYPASS_DENY' },
    );
  assert.equal(productionPolicyReady([{ ...earlier, enabled: false }, ...restricted], owner), true);
  assert.equal(
    productionPolicyReady(
      [
        {
          ...earlier,
          action_parameters: {
            phases: ['http_request_firewall_managed'],
            rulesets: ['managed-ruleset'],
            rules: { 'managed-ruleset': ['managed-rule'] },
          },
        },
        ...restricted,
      ],
      owner,
    ),
    true,
  );
  assert.equal(productionPolicyReady([restricted[0], deny, earlier, restricted[2]], owner), true);
});
test('WAF unrelated objects and their relative execution order are preserved', () => {
  const a = {
    id: 'old-a',
    ref: 'old-a',
    action: 'managed_challenge',
    expression: 'some-rule',
    action_parameters: { custom: 1 },
  };
  const b = { id: 'old-b', ref: 'old-b', action: 'block', expression: 'other-rule' };
  assert.equal(
    unrelatedRulesUnchanged(
      [a, b],
      [ownRule(SKIP_REF, 'skip', API_MATCH), a, b],
      new Set([SKIP_REF]),
    ),
    true,
  );
  assert.equal(unrelatedRulesUnchanged([a, b], [b, a], new Set([SKIP_REF])), false);
  assert.equal(unrelatedRulesUnchanged([a], [{ ...a, action_parameters: {} }], new Set()), false);
});
test('generated config serves assets through Worker and contains no old route, secret or deployment token', () => {
  const config = deploymentConfiguration(manifest(), 'shortlink-new.lilyya.workers.dev');
  assert.equal(config.assets.run_worker_first, true);
  assert.equal(config.assets.directory, '../dist');
  assert.equal(config.main, '../src/index.ts');
  assert.equal(config.name, 'shortlink-new');
  assert.deepEqual(config.compatibility_flags, ['global_fetch_strictly_public']);
  assert.equal(config.routes, undefined);
  assert.equal(config.vars.PUBLIC_HOSTNAME, 'test.gfw.mom');
  assert.equal(config.vars.ADMIN_HOSTNAME, 'link-admin.lily.lat');
  assert.equal(config.vars.TURNSTILE_SECRET_KEY, undefined);
  assert.doesNotMatch(JSON.stringify(config), /CLOUDFLARE_API_TOKEN|LEGACY_KV/);
});
test('deployment and explicit maintenance workflows remain manual, mutually exclusive and do not leak artifacts', () => {
  for (const name of [
    'bootstrap-test',
    'deploy-test',
    'security-test',
    'migrate-legacy',
    'deploy-production',
  ]) {
    const yaml = readFileSync(`.github/workflows/${name}.yml`, 'utf8');
    assert.match(yaml, /on:\n  workflow_dispatch:/);
    assert.doesNotMatch(yaml, /\n  (push|schedule|pull_request|workflow_call|workflow_run):/);
    assert.match(yaml, /group: shortlink-new-cloudflare/);
    assert.match(yaml, /cancel-in-progress: false/);
    assert.doesNotMatch(yaml, /upload-artifact|gh workflow run|workflow_dispatch.*curl/);
    assert.match(yaml, /CONFIRM_TARGET:/);
  }
  const ci = readFileSync('.github/workflows/ci.yml', 'utf8');
  assert.doesNotMatch(ci, /secrets\.|CLOUDFLARE_API_TOKEN|scripts\/deploy|scripts\/migrate-legacy/);
});

test('account preflight requires full R2 REST management permission, not bucket item permissions', async () => {
  const tokenId = 'a'.repeat(32);
  const fixture = (r2Permission) => {
    const calls = [];
    const client = createCFClient('dummy-token', {
      allowWrites: true,
      fetcher: async (url, options) => {
        const path = new URL(url).pathname.slice('/client/v4'.length);
        calls.push({ path, method: options.method });
        assert.equal(options.method, 'GET');
        if (path === `${ACCOUNT}/tokens/verify`) return response({ status: 'active', id: tokenId });
        if (path === `${ACCOUNT}/tokens/${tokenId}`) {
          if (r2Permission === null)
            return new Response(JSON.stringify({ success: false, errors: [{ code: 10000 }] }), {
              status: 403,
            });
          return response({
            policies: [
              {
                effect: 'allow',
                permission_groups: ['Workers Scripts Write', 'D1 Write', r2Permission].map(
                  (name) => ({ name }),
                ),
              },
            ],
          });
        }
        if (path === `/zones/${EXPECTED.CF_ZONE_ID_GFW_MOM}`)
          return response({ name: 'gfw.mom', account: { id: EXPECTED.CLOUDFLARE_ACCOUNT_ID } });
        if (path === ADMIN_ZONE)
          return response({ name: 'lily.lat', account: { id: EXPECTED.CLOUDFLARE_ACCOUNT_ID } });
        assert.equal(path, `${ACCOUNT}/workers/scripts/${EXPECTED.LEGACY_WORKER_NAME}/settings`);
        return response({
          bindings: [
            {
              name: 'LINKS',
              type: 'kv_namespace',
              namespace_id: EXPECTED.LEGACY_KV_NAMESPACE_ID,
            },
          ],
        });
      },
    });
    return { client, calls };
  };
  for (const permission of [
    'Workers R2 Storage Bucket Item Write',
    'Workers R2 Storage Bucket Item Read',
    'Workers R2 Storage Read',
    'Workers R2 Storage Edit',
  ]) {
    const { client, calls } = fixture(permission);
    await assert.rejects(verifyAccount(client), {
      code: 'DEPLOY_TOKEN_POLICY_MISSING_CAPABILITY',
    });
    assert.deepEqual(calls, [
      { path: `${ACCOUNT}/tokens/verify`, method: 'GET' },
      { path: `${ACCOUNT}/tokens/${tokenId}`, method: 'GET' },
    ]);
  }
  const full = fixture('Workers R2 Storage Write');
  const verified = await verifyAccount(full.client);
  assert.equal(verified.active, true);
  assert.equal(verified.policy_read, 'reviewed');
  assert.equal(verified.allow_permission_count, 3);
  assert.equal(full.calls.length, 5);
  assert.ok(full.calls.every(({ method }) => method === 'GET'));

  const unreadable = fixture(null);
  const optionalPolicy = await verifyAccount(unreadable.client);
  assert.equal(optionalPolicy.policy_read, 'permission_unavailable');
  assert.equal(optionalPolicy.allow_permission_count, null);
  assert.equal(unreadable.calls.length, 5);
  assert.ok(unreadable.calls.every(({ method }) => method === 'GET'));
});
