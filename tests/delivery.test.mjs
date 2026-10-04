import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  EXPECTED,
  ACCOUNT,
  ADMIN_ZONE,
  DeliveryError,
  createCFClient,
  listAll,
  requireAction,
  safeError,
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

test('ordinary deployment refuses incomplete bootstrap checkpoints and an unbound DB domain before any write', async () => {
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
  let bound = 0;
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
                ? [{ hostname: 'test.gfw.mom', bound, enabled: 0 }]
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
  await assert.rejects(requireBootstrapComplete(client, completed), {
    code: 'BOOTSTRAP_RECOVERY_REQUIRED',
  });
  bound = 1;
  await assert.doesNotReject(requireBootstrapComplete(client, completed));
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
  assert.equal(config.routes, undefined);
  assert.equal(config.vars.PUBLIC_HOSTNAME, 'test.gfw.mom');
  assert.equal(config.vars.ADMIN_HOSTNAME, 'link-admin.lily.lat');
  assert.equal(config.vars.TURNSTILE_SECRET_KEY, undefined);
  assert.doesNotMatch(JSON.stringify(config), /CLOUDFLARE_API_TOKEN|LEGACY_KV/);
});
test('only CI has automatic events; cloud writes are manual, same mutual exclusion, no artifact leakage', () => {
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
