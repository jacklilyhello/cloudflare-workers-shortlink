import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { ACCOUNT, ADMIN_ZONE, EXPECTED, BUCKET, DeliveryError } from '../scripts/cf-client.mjs';
import { objectPath } from '../scripts/deploy-resources.mjs';
import {
  API_MATCH,
  GUARD_MATCH,
  GUARD_REF,
  SKIP_REF,
  DENY_REF,
  verifySecurity,
  TEST_ALL_IP_CONDITION,
  TEST_ALL_IP_CHECKPOINT_KEY,
} from '../scripts/security-bootstrap.mjs';
import {
  restrictAPI,
  renameSecurity,
  accessRenameBody,
  REVIEWED_IP_CONDITION,
  allowTestAllIP,
  CONFIRMATIONS,
  updateAdminPolicies,
  accessPolicyUpdateBody,
} from '../scripts/security-maintenance.mjs';
import {
  DISPLAY_NAMES,
  ownedRule,
  POLICY_NAMES,
  POLICY_CHECKPOINT_KEY,
  PREVIOUS_ADMIN_EMAILS,
} from '../scripts/security-ownership.mjs';
import {
  domainReadPolicyQualified,
  selectDomainReadCredential,
} from '../scripts/domain-read-credential.mjs';

const copy = (v) => structuredClone(v);
const hash = (s) => createHash('sha256').update(s).digest('hex');
function fixture() {
  const owner = '92e9e731-1f9c-4e7d-a526-2efa8d294c48';
  const prefix = `shortlink-new:${owner}:`;
  const customId = 'a'.repeat(32);
  const errorId = 'b'.repeat(32);
  const errorRuleId = 'c'.repeat(32);
  const otp = { id: 'd'.repeat(32), type: 'onetimepin' };
  const rules = [
    {
      id: '1'.repeat(32),
      ref: GUARD_REF,
      description: `${prefix}guard`,
      action: 'block',
      expression: GUARD_MATCH,
      enabled: true,
    },
    {
      id: '2'.repeat(32),
      ref: SKIP_REF,
      description: `${prefix}all-ip`,
      action: 'skip',
      expression: API_MATCH,
      enabled: true,
      action_parameters: { ruleset: 'current', products: ['bic'], phases: ['http_ratelimit'] },
      logging: { enabled: true },
    },
    {
      id: '3'.repeat(32),
      ref: 'other_service',
      action: 'skip',
      expression: '(http.host eq "other.lily.lat")',
      enabled: true,
      action_parameters: { ruleset: 'current' },
      description: 'Existing unrelated rule',
    },
  ];
  const entry = { id: customId, kind: 'zone', phase: 'http_request_firewall_custom', rules };
  const errorExpression = `(http.response.code eq 403) and not ${API_MATCH}`;
  const errors = {
    id: errorId,
    kind: 'zone',
    phase: 'http_custom_errors',
    rules: [{ id: errorRuleId, action: 'serve_error', expression: errorExpression, enabled: true }],
  };
  const apps = Object.entries({
    admin: 'admin',
    api: 'machine',
    children: 'machine-children-guard',
  }).map(([key, suffix], i) => ({
    id: `00000000-0000-0000-0000-00000000000${i}`,
    uid: `00000000-0000-0000-0000-00000000000${i}`,
    aud: String(i + 4).repeat(64),
    type: 'self_hosted',
    name: `${prefix}${suffix}`,
    domain: `${EXPECTED.ADMIN_HOSTNAME}${['', '/api/shorten', '/api/shorten/*'][i]}`,
    allowed_idps: [otp.id],
    allow_authenticate_via_warp: false,
    app_launcher_visible: false,
    auto_redirect_to_identity: true,
    session_duration: '12h',
    enable_binding_cookie: false,
    http_only_cookie_attribute: true,
    options_preflight_bypass: false,
    eager_redirect_cookie_setting: true,
    policies: [
      {
        id: `policy-${i}`,
        name: `${prefix}policy`,
        decision: i === 1 ? 'bypass' : 'allow',
        include:
          i === 1
            ? [{ everyone: {} }]
            : EXPECTED.ADMIN_EMAILS.split(',').map((email) => ({ email: { email } })),
        exclude: [],
        require: [],
        precedence: 1,
        reusable: false,
        uid: `policy-${i}`,
        created_at: '2026-10-01T00:00:00Z',
        updated_at: '2026-10-01T00:00:00Z',
      },
    ],
  }));
  const manifest = {
    schema: 1,
    project: 'jacklilyhello/cloudflare-workers-shortlink',
    owner_id: owner,
    account: EXPECTED.CLOUDFLARE_ACCOUNT_ID,
    worker: EXPECTED.WORKER_NAME,
    environment: 'test',
    bucket: BUCKET,
    d1: { id: '00000000-0000-0000-0000-111111111111', name: 'shortlink-new-test' },
    domains: {},
    security: {
      status: 'ready',
      ruleset_id: customId,
      skip_parameters: copy(rules[1].action_parameters),
      rules: { [GUARD_REF]: rules[0].id, [SKIP_REF]: rules[1].id },
      apps: Object.fromEntries(
        apps.map((a, i) => [['admin', 'api', 'children'][i], { id: a.id, aud: a.aud }]),
      ),
      custom_error_api: {
        status: 'applied',
        ruleset_id: errorId,
        rule_id: errorRuleId,
        expected_expression_sha256: hash(errorExpression),
      },
    },
  };
  const worker = {
    bindings: [
      { name: 'RESOURCE_OWNER_ID', type: 'plain_text', text: owner },
      { name: 'DB', type: 'd1', id: manifest.d1.id },
      { name: 'BACKUPS', type: 'r2_bucket', bucket_name: BUCKET },
    ],
  };
  const objects = new Map();
  const calls = [];
  let afterCreate;
  const request = async (path, options = {}) => {
    const url = new URL(`https://api.cloudflare.com/client/v4${path}`);
    const p = url.pathname.slice('/client/v4'.length);
    const method = options.method || 'GET';
    calls.push({ path: p, method, json: copy(options.json) });
    if (p.includes('/r2/')) {
      if (method === 'PUT') {
        objects.set(p, options.body);
        return { result: {} };
      }
      assert.ok(objects.has(p), 'checkpoint object exists');
      return options.raw ? objects.get(p) : { result: {} };
    }
    if (p === `${ADMIN_ZONE}/rulesets/${customId}/rules` && method === 'POST') {
      const made = { ...copy(options.json), id: '9'.repeat(32) };
      delete made.position;
      entry.rules.splice(
        entry.rules.findIndex((r) => r.id === options.json.position.before),
        0,
        made,
      );
      if (afterCreate) await afterCreate(entry);
      return { result: copy(entry) };
    }
    if (p.startsWith(`${ADMIN_ZONE}/rulesets/${customId}/rules/`) && method === 'PATCH') {
      assert.equal(options.json.position, undefined);
      const id = p.split('/').at(-1);
      const i = entry.rules.findIndex((r) => r.id === id);
      entry.rules[i] = { ...copy(options.json), id, version: '2' };
      return { result: copy(entry) };
    }
    if (p.startsWith(`${ACCOUNT}/access/apps/`)) {
      const parts = p.split('/');
      const app = apps.find((a) => a.id === parts[5]);
      assert.ok(app);
      if (parts.at(-1) === 'policies')
        return { result: copy(app.policies), result_info: { total_pages: 1 } };
      if (parts[6] === 'policies') {
        const policy = app.policies.find((item) => item.id === parts[7]);
        assert.ok(policy);
        if (method === 'PUT')
          Object.assign(policy, copy(options.json), { updated_at: '2026-10-07T05:00:00Z' });
        return { result: copy(policy) };
      }
      if (method === 'PUT') {
        assert.deepEqual(
          options.json.policies,
          app.policies.map((x) => ({ id: x.id })),
        );
        const policies = app.policies;
        Object.assign(app, copy(options.json), { policies });
      }
      return { result: copy(app) };
    }
    assert.equal(method, 'GET');
    const fixed = new Map([
      [`${ACCOUNT}/access/organizations`, { auth_domain: EXPECTED.CF_ACCESS_TEAM_DOMAIN }],
      [`${ACCOUNT}/access/identity_providers`, [otp]],
      [`${ACCOUNT}/access/apps`, apps],
      [`${ADMIN_ZONE}/bot_management`, { fight_mode: false }],
      [`${ADMIN_ZONE}/settings`, []],
      [`${ACCOUNT}/rulesets`, []],
      [`${ADMIN_ZONE}/rulesets`, [{ id: customId, kind: 'zone', phase: entry.phase }]],
      [`${ADMIN_ZONE}/rulesets/${customId}`, entry],
      [`${ADMIN_ZONE}/rulesets/${errorId}`, errors],
      [`${ACCOUNT}/workers/scripts/${EXPECTED.WORKER_NAME}/settings`, worker],
    ]);
    assert.ok(fixed.has(p), `known request ${p}`);
    return { result: copy(fixed.get(p)), result_info: { total_pages: 1 } };
  };
  const client = { request, optional: async (p, o) => (objects.has(p) ? request(p, o) : null) };
  return {
    client,
    manifest,
    entry,
    apps,
    calls,
    errors,
    objects,
    worker,
    setAfterCreate: (f) => {
      afterCreate = f;
    },
  };
}
const allIPEnv = () => ({
  ...EXPECTED,
  GITHUB_ACTIONS: 'true',
  GITHUB_EVENT_NAME: 'workflow_dispatch',
  GITHUB_REPOSITORY: 'jacklilyhello/cloudflare-workers-shortlink',
  GITHUB_REF: 'refs/heads/main',
  GITHUB_RUN_ID: '37350000001',
  CLOUDFLARE_API_TOKEN: 'fixture-not-a-real-token',
  SECURITY_OPERATION: 'allow-test-all-ip',
  CONFIRM_TARGET: CONFIRMATIONS['allow-test-all-ip'],
});
async function namedRestrictedFixture() {
  const f = fixture();
  await restrictAPI(f.client, f.manifest);
  await renameSecurity(f.client, f.manifest);
  return f;
}
const adminPolicyEnv = () => ({
  ...allIPEnv(),
  SECURITY_OPERATION: 'update-admin-policies',
  CONFIRM_TARGET: CONFIRMATIONS['update-admin-policies'],
});
async function previousAdministratorFixture() {
  const f = await namedRestrictedFixture();
  await allowTestAllIP(f.client, f.manifest, { env: allIPEnv() });
  for (const i of [0, 2])
    f.apps[i].policies[0].include = PREVIOUS_ADMIN_EMAILS.split(',').map((email) => ({
      email: { email },
    }));
  return f;
}
test('administrator operation changes only three policy names and two email selectors, preserving identities, associations and current all-IP policy', async () => {
  const f = await previousAdministratorFixture(),
    before = copy(f.apps),
    rules = copy(f.entry),
    errors = copy(f.errors),
    start = f.calls.length;
  await assert.rejects(verifySecurity(f.client, f.manifest), { code: 'ACCESS_EMAILS_UNSAFE' });
  const result = await updateAdminPolicies(f.client, f.manifest, { env: adminPolicyEnv() });
  assert.equal(result.changes.length, 3);
  assert.equal(result.administrator_count, 3);
  assert.deepEqual(f.entry, rules);
  assert.deepEqual(f.errors, errors);
  assert.equal(f.manifest.security.access_policies.status, 'complete');
  for (const [index, key] of ['admin', 'api', 'children'].entries()) {
    assert.equal(f.apps[index].policies[0].name, POLICY_NAMES[key]);
    assert.deepEqual({ ...f.apps[index], policies: null }, { ...before[index], policies: null });
    const stable = ({ name, include, updated_at, ...rest }) => rest;
    assert.deepEqual(stable(f.apps[index].policies[0]), stable(before[index].policies[0]));
    assert.deepEqual(
      f.apps[index].policies[0].include,
      index === 1
        ? [{ everyone: {} }]
        : EXPECTED.ADMIN_EMAILS.split(',').map((email) => ({ email: { email } })),
    );
  }
  assert.equal(
    f.calls.slice(start).filter((call) => call.method === 'PUT' && call.path.includes('/access/'))
      .length,
    3,
  );
  assert.ok(
    f.calls
      .slice(start)
      .filter((call) => call.path.includes('/access/') && call.method !== 'GET')
      .every((call) => /\/access\/apps\/[^/]+\/policies\/[^/]+$/.test(call.path)),
  );
  await verifySecurity(f.client, f.manifest);
  const writes = f.calls.filter((call) => call.method !== 'GET').length;
  await updateAdminPolicies(f.client, f.manifest, { env: adminPolicyEnv() });
  assert.equal(f.calls.filter((call) => call.method !== 'GET').length, writes);
});
test('policy PUT preserves additional security settings without recreating identities', () => {
  const original = {
    id: 'owned',
    uid: 'owned',
    created_at: 'prior',
    updated_at: 'prior',
    account_id: 'account',
    name: 'Before',
    decision: 'allow',
    precedence: 7,
    reusable: false,
    session_duration: '12h',
    approval_groups: [],
    custom_existing_constraint: { enabled: true },
    include: [{ email: { email: 'old@example.test' } }],
  };
  const body = accessPolicyUpdateBody(original, 'After', [
    { email: { email: 'new@example.test' } },
  ]);
  for (const key of ['id', 'uid', 'created_at', 'updated_at', 'account_id'])
    assert.equal(body[key], undefined);
  assert.deepEqual(body.custom_existing_constraint, original.custom_existing_constraint);
  assert.equal(body.session_duration, '12h');
  assert.equal(body.reusable, false);
  assert.equal(body.precedence, 7);
});
test('an applied policy PUT with a lost response resumes the same checkpoint and never repeats the successful mutation', async () => {
  for (const lostIndex of [0, 1, 2]) {
    const f = await previousAdministratorFixture(),
      request = f.client.request;
    let failed = false,
      path;
    f.client.request = async (p, options = {}) => {
      const result = await request(p, options);
      if (!failed && options.method === 'PUT' && p.endsWith(`/policies/policy-${lostIndex}`)) {
        failed = true;
        path = p;
        throw new DeliveryError('WRITE_RESULT_UNKNOWN_RECONCILE_REQUIRED');
      }
      return result;
    };
    await assert.rejects(updateAdminPolicies(f.client, f.manifest, { env: adminPolicyEnv() }), {
      code: 'WRITE_RESULT_UNKNOWN_RECONCILE_REQUIRED',
    });
    await assert.rejects(verifySecurity(f.client, f.manifest), {
      code: 'ACCESS_POLICY_UPDATE_INCOMPLETE',
    });
    const checkpoint = f.objects.get(
      objectPath(`delivery/${f.manifest.owner_id}/${POLICY_CHECKPOINT_KEY}.json`),
    );
    await updateAdminPolicies(f.client, f.manifest, { env: adminPolicyEnv() });
    assert.equal(f.calls.filter((call) => call.path === path && call.method === 'PUT').length, 1);
    assert.equal(
      f.objects.get(objectPath(`delivery/${f.manifest.owner_id}/${POLICY_CHECKPOINT_KEY}.json`)),
      checkpoint,
    );
    assert.equal(f.manifest.security.access_policies.status, 'complete');
  }
});
test('manual administrator operation stops before all writes for an unauthorized context', async () => {
  const f = await previousAdministratorFixture();
  for (const change of [
    { GITHUB_ACTIONS: '' },
    { GITHUB_EVENT_NAME: 'schedule' },
    { GITHUB_REF: 'refs/heads/codex/other' },
    { APP_ENV: 'production' },
    { SECURITY_OPERATION: 'rename' },
    { CONFIRM_TARGET: CONFIRMATIONS.rename },
    { GITHUB_RUN_ID: '' },
  ]) {
    const start = f.calls.length;
    await assert.rejects(
      updateAdminPolicies(f.client, f.manifest, { env: { ...adminPolicyEnv(), ...change } }),
      DeliveryError,
    );
    assert.equal(f.calls.length, start);
  }
});
test('policy names cannot establish ownership for a replacement ID or reusable conversion', async () => {
  for (const change of [
    (f) => {
      f.apps[0].policies[0].id = 'foreign';
    },
    (f) => {
      f.apps[0].policies[0].reusable = true;
    },
  ]) {
    const f = await previousAdministratorFixture(),
      start = f.calls.length;
    change(f);
    await assert.rejects(updateAdminPolicies(f.client, f.manifest, { env: adminPolicyEnv() }), {
      code: 'ACCESS_POLICY_OWNERSHIP_UNPROVEN',
    });
    assert.ok(f.calls.slice(start).every((call) => call.method === 'GET'));
  }
});
test('ordinary verification without the new policy record proves the immutable old IDs and never trusts labels alone', async () => {
  for (const [code, change] of [
    [
      'ACCESS_POLICY_OWNERSHIP_UNPROVEN',
      (f) => {
        f.apps[0].policies[0].id = 'replacement-with-same-owner-name';
      },
    ],
    [
      'ACCESS_POLICY_OWNERSHIP_UNPROVEN',
      (f) => {
        f.apps[0].policies[0].reusable = true;
      },
    ],
    [
      'ACCESS_POLICY_OWNERSHIP_UNPROVEN',
      (f) => {
        f.apps[0].policies[0].precedence = 99;
      },
    ],
    [
      'ACCESS_POLICY_LEGACY_ID_CHECKPOINT_INVALID',
      (f) => {
        const p = objectPath(`delivery/${f.manifest.owner_id}/security-labels-before.json`);
        const value = JSON.parse(f.objects.get(p));
        value.apps.admin.policies[0].id = 'foreign';
        f.objects.set(p, JSON.stringify(value));
      },
    ],
  ]) {
    const f = await namedRestrictedFixture();
    assert.equal(f.manifest.security.access_policies, undefined);
    change(f);
    const start = f.calls.length;
    await assert.rejects(verifySecurity(f.client, f.manifest), { code });
    assert.ok(f.calls.slice(start).every((call) => call.method === 'GET'));
  }
  const missing = await namedRestrictedFixture(),
    request = missing.client.request;
  const path = objectPath(`delivery/${missing.manifest.owner_id}/security-labels-before.json`);
  missing.client.request = async (p, options) => {
    if (p === path) throw new DeliveryError('RESOURCE_NOT_FOUND', 404);
    return request(p, options);
  };
  await assert.rejects(verifySecurity(missing.client, missing.manifest), {
    code: 'RESOURCE_NOT_FOUND',
  });
  const associations = await namedRestrictedFixture(),
    associationRequest = associations.client.request;
  associations.client.request = async (p, options) => {
    const result = await associationRequest(p, options);
    if (new URL(`https://api.cloudflare.com${p}`).pathname === `${ACCOUNT}/access/apps`)
      result.result[0].policies[0].id = 'another-associated-policy';
    return result;
  };
  await assert.rejects(verifySecurity(associations.client, associations.manifest), {
    code: 'ACCESS_POLICY_APPLICATION_ASSOCIATION_DRIFT',
  });
});
test('completed manifest or receipt failures recover by readback without repeating policy PUTs', async () => {
  for (const lostTarget of ['manifest', 'receipt']) {
    const f = await previousAdministratorFixture(),
      request = f.client.request;
    let failed = false;
    f.client.request = async (p, options = {}) => {
      if (
        !failed &&
        lostTarget === 'receipt' &&
        p.endsWith('/access-admin-policies-after-v1.json') &&
        options.method === 'PUT'
      ) {
        failed = true;
        throw new DeliveryError('WRITE_RESULT_UNKNOWN_RECONCILE_REQUIRED');
      }
      const result = await request(p, options);
      if (
        !failed &&
        lostTarget === 'manifest' &&
        p === objectPath('delivery/ownership.json') &&
        options.method === 'PUT' &&
        JSON.parse(options.body).security.access_policies?.status === 'complete'
      ) {
        failed = true;
        throw new DeliveryError('WRITE_RESULT_UNKNOWN_RECONCILE_REQUIRED');
      }
      return result;
    };
    await assert.rejects(updateAdminPolicies(f.client, f.manifest, { env: adminPolicyEnv() }), {
      code: 'WRITE_RESULT_UNKNOWN_RECONCILE_REQUIRED',
    });
    const restored = JSON.parse(f.objects.get(objectPath('delivery/ownership.json')));
    assert.equal(restored.security.access_policies.status, 'complete');
    const start = f.calls.length;
    await updateAdminPolicies(f.client, restored, { env: adminPolicyEnv() });
    assert.equal(
      f.calls.slice(start).filter((call) => call.method === 'PUT' && call.path.includes('/access/'))
        .length,
      0,
    );
    assert.ok(
      f.objects.has(
        objectPath(`delivery/${f.manifest.owner_id}/access-admin-policies-after-v1.json`),
      ),
    );
  }
});
test('new policy verification rejects substituted app associations, old names, email drift and tampered private proof', async () => {
  for (const [code, change] of [
    [
      'ACCESS_POLICY_OWNERSHIP_UNPROVEN',
      (f) => {
        f.apps[0].policies[0].id = 'foreign';
      },
    ],
    [
      'ACCESS_POLICY_OWNERSHIP_UNPROVEN',
      (f) => {
        f.apps[0].policies[0].name = `${`shortlink-new:${f.manifest.owner_id}:`}old`;
      },
    ],
    [
      'ACCESS_EMAILS_UNSAFE',
      (f) => {
        f.apps[0].policies[0].include.pop();
      },
    ],
    [
      'ACCESS_POLICY_OWNERSHIP_CHECKPOINT_INVALID',
      (f) => {
        const p = objectPath(`delivery/${f.manifest.owner_id}/${POLICY_CHECKPOINT_KEY}.json`);
        const saved = JSON.parse(f.objects.get(p));
        saved.apps.admin.policies[0].id = 'foreign';
        f.objects.set(p, JSON.stringify(saved));
      },
    ],
  ]) {
    const f = await previousAdministratorFixture();
    await updateAdminPolicies(f.client, f.manifest, { env: adminPolicyEnv() });
    change(f);
    const start = f.calls.length;
    await assert.rejects(verifySecurity(f.client, f.manifest), { code });
    assert.ok(f.calls.slice(start).every((call) => call.method === 'GET'));
  }
});
test('policy update stops after a partial mutation when an unrelated protected field drifts', async () => {
  for (const [code, change] of [
    [
      'ACCESS_POLICY_OWNERSHIP_UNPROVEN',
      (f) => {
        f.apps[0].policies[0].precedence = 8;
      },
    ],
    [
      'ACCESS_POLICY_WAF_CHANGED',
      (f) => {
        f.entry.rules.find((rule) => rule.ref === 'other_service').description += ' drift';
      },
    ],
    [
      'ACCESS_POLICY_CUSTOM_ERRORS_CHANGED',
      (f) => {
        f.errors.rules[0].description = 'changed';
      },
    ],
  ]) {
    const f = await previousAdministratorFixture(),
      request = f.client.request,
      start = f.calls.length;
    f.client.request = async (p, options = {}) => {
      const result = await request(p, options);
      if (options.method === 'PUT' && p.endsWith('/policies/policy-0')) change(f);
      return result;
    };
    await assert.rejects(updateAdminPolicies(f.client, f.manifest, { env: adminPolicyEnv() }), {
      code,
    });
    assert.equal(
      f.calls.slice(start).filter((call) => call.method === 'PUT' && call.path.includes('/access/'))
        .length,
      1,
    );
    assert.equal(f.apps[1].policies[0].name, `${`shortlink-new:${f.manifest.owner_id}:`}policy`);
  }
});
test('explicit manual test operation updates only the two owned expressions, preserves names and opens both families only after Skip is widened', async () => {
  const f = await namedRestrictedFixture();
  for (let i = 0; i < 5; i++)
    f.entry.rules.push({
      id: String(i + 4).repeat(32),
      ref: `other-${i}`,
      action: 'managed_challenge',
      enabled: true,
      expression: '(http.host eq "another.lily.lat")',
      description: 'Unrelated',
      version: '7',
      last_updated: 'old',
    });
  const before = copy(f.entry.rules),
    apps = copy(f.apps),
    errors = copy(f.errors);
  const start = f.calls.length;
  const request = f.client.request;
  let intermediateObserved = false;
  f.client.request = async (path, options) => {
    const result = await request(path, options);
    if (options?.method === 'PATCH' && path.endsWith(f.manifest.security.rules[SKIP_REF])) {
      intermediateObserved = true;
      assert.equal(
        f.entry.rules.find((rule) => rule.ref === DENY_REF).expression,
        `${API_MATCH} and not (${REVIEWED_IP_CONDITION})`,
        'original Block still limits network access during the first PATCH',
      );
    }
    return result;
  };
  const result = await allowTestAllIP(f.client, f.manifest, { env: allIPEnv() });
  assert.equal(result.changed, true);
  assert.equal(intermediateObserved, true);
  const operations = f.calls.slice(start);
  const patches = operations.filter((call) => call.method === 'PATCH');
  assert.deepEqual(
    patches.map((call) => call.path.split('/').at(-1)),
    [f.manifest.security.rules[SKIP_REF], f.manifest.security.rules[DENY_REF]],
  );
  assert.ok(
    operations
      .filter((call) => call.method !== 'GET')
      .every((call) =>
        call.method === 'PATCH' ? call.path.includes('/rules/') : call.path.includes('/r2/'),
      ),
  );
  assert.deepEqual(
    f.entry.rules.map((rule) => rule.id),
    before.map((rule) => rule.id),
  );
  for (const original of before) {
    const current = f.entry.rules.find((rule) => rule.id === original.id);
    const ignored = [SKIP_REF, DENY_REF].includes(original.ref)
      ? ['expression', 'version', 'last_updated']
      : [];
    const strip = (rule) =>
      Object.fromEntries(Object.entries(rule).filter(([key]) => !ignored.includes(key)));
    assert.deepEqual(strip(current), strip(original));
  }
  assert.deepEqual(f.apps, apps);
  assert.deepEqual(f.errors, errors);
  assert.equal(
    f.entry.rules.find((rule) => rule.ref === SKIP_REF).expression,
    `${API_MATCH} and (${TEST_ALL_IP_CONDITION})`,
  );
  assert.equal(
    f.entry.rules.find((rule) => rule.ref === DENY_REF).expression,
    `${API_MATCH} and not (${TEST_ALL_IP_CONDITION})`,
  );
  assert.equal(f.manifest.security.temporary_all_ip.status, 'complete');
  assert.equal(
    (await verifySecurity(f.client, f.manifest)).ip_policy,
    'authorized-test-all-ipv4-ipv6',
  );
  await assert.rejects(verifySecurity(f.client, f.manifest, { production: true }), {
    code: 'PRODUCTION_ALL_NETWORK_CIDR_FORBIDDEN',
  });
});
test('completed all-IP operation and normal deployment only verify and preserve later operator lists', async () => {
  const f = await namedRestrictedFixture();
  await allowTestAllIP(f.client, f.manifest, { env: allIPEnv() });
  const writes = f.calls.filter((call) => call.method !== 'GET').length;
  await allowTestAllIP(f.client, f.manifest, { env: allIPEnv() });
  assert.equal(f.calls.filter((call) => call.method !== 'GET').length, writes);
  const condition = 'ip.src in {192.0.2.8 2001:db8::1}';
  f.entry.rules.find((rule) => rule.ref === SKIP_REF).expression =
    `${API_MATCH} and (${condition})`;
  f.entry.rules.find((rule) => rule.ref === DENY_REF).expression =
    `${API_MATCH} and not (${condition})`;
  assert.equal((await verifySecurity(f.client, f.manifest)).ip_policy, 'operator-restricted');
  await allowTestAllIP(f.client, f.manifest, { env: allIPEnv() });
  await restrictAPI(f.client, f.manifest);
  await renameSecurity(f.client, f.manifest);
  assert.equal(f.calls.filter((call) => call.method !== 'GET').length, writes);
  assert.equal(
    f.entry.rules.find((rule) => rule.ref === SKIP_REF).expression,
    `${API_MATCH} and (${condition})`,
  );
});
test('unknown Skip or Block write result re-reads the checkpoint and applies each expression once', async () => {
  for (const lostRef of [SKIP_REF, DENY_REF]) {
    const f = await namedRestrictedFixture();
    const start = f.calls.length;
    const request = f.client.request;
    let failed = false;
    f.client.request = async (path, options) => {
      const result = await request(path, options);
      if (
        !failed &&
        options?.method === 'PATCH' &&
        path.endsWith(f.manifest.security.rules[lostRef])
      ) {
        failed = true;
        throw new DeliveryError('WRITE_RESULT_UNKNOWN_RECONCILE_REQUIRED');
      }
      return result;
    };
    await assert.rejects(allowTestAllIP(f.client, f.manifest, { env: allIPEnv() }), {
      code: 'WRITE_RESULT_UNKNOWN_RECONCILE_REQUIRED',
    });
    const checkpointPath = objectPath(
      `delivery/${f.manifest.owner_id}/${TEST_ALL_IP_CHECKPOINT_KEY}.json`,
    );
    const originalCheckpoint = f.objects.get(checkpointPath);
    await allowTestAllIP(f.client, f.manifest, {
      env: { ...allIPEnv(), GITHUB_RUN_ID: '37350000002' },
    });
    const operations = f.calls.slice(start);
    assert.equal(operations.filter((call) => call.method === 'PATCH').length, 2);
    assert.equal(
      operations.filter((call) => call.method === 'PUT' && call.path === checkpointPath).length,
      1,
    );
    assert.equal(f.objects.get(checkpointPath), originalCheckpoint);
    assert.equal(f.manifest.security.temporary_all_ip.dispatch_run_id, '37350000001');
    assert.equal(f.manifest.security.temporary_all_ip.status, 'complete');
  }
});
test('lost completed manifest response is recovered by readback without a repeated rule PATCH', async () => {
  const f = await namedRestrictedFixture();
  const start = f.calls.length,
    request = f.client.request;
  let failed = false;
  f.client.request = async (path, options) => {
    const result = await request(path, options);
    if (
      !failed &&
      path === objectPath('delivery/ownership.json') &&
      options?.method === 'PUT' &&
      JSON.parse(options.body).security.temporary_all_ip?.status === 'complete'
    ) {
      failed = true;
      throw new DeliveryError('WRITE_RESULT_UNKNOWN_RECONCILE_REQUIRED');
    }
    return result;
  };
  await assert.rejects(allowTestAllIP(f.client, f.manifest, { env: allIPEnv() }), {
    code: 'WRITE_RESULT_UNKNOWN_RECONCILE_REQUIRED',
  });
  const restored = JSON.parse(f.objects.get(objectPath('delivery/ownership.json')));
  await allowTestAllIP(f.client, restored, { env: allIPEnv() });
  assert.equal(f.calls.slice(start).filter((call) => call.method === 'PATCH').length, 2);
});
test('all-IP test operation stops before any write for local, nonmanual, foreign main or confirmation', async () => {
  const f = await namedRestrictedFixture();
  for (const change of [
    { GITHUB_ACTIONS: '' },
    { GITHUB_EVENT_NAME: 'schedule' },
    { GITHUB_REF: 'refs/heads/codex/branch' },
    { GITHUB_REPOSITORY: 'someone/else' },
    { APP_ENV: 'production' },
    { CONFIRM_TARGET: CONFIRMATIONS['restrict-ip'] },
    { SECURITY_OPERATION: 'verify' },
    { GITHUB_RUN_ID: '' },
  ]) {
    const start = f.calls.length;
    await assert.rejects(
      allowTestAllIP(f.client, f.manifest, { env: { ...allIPEnv(), ...change } }),
      DeliveryError,
    );
    assert.equal(f.calls.length, start);
  }
});
test('new all-IP dispatch refuses a previously operator-modified source list and human labels do not prove a foreign rule', async () => {
  const f = await namedRestrictedFixture();
  const condition = 'ip.src in {192.0.2.9}';
  f.entry.rules.find((rule) => rule.ref === SKIP_REF).expression =
    `${API_MATCH} and (${condition})`;
  f.entry.rules.find((rule) => rule.ref === DENY_REF).expression =
    `${API_MATCH} and not (${condition})`;
  const start = f.calls.length;
  await assert.rejects(allowTestAllIP(f.client, f.manifest, { env: allIPEnv() }), {
    code: 'TEST_ALL_API_SOURCE_POLICY_CHANGED',
  });
  assert.ok(f.calls.slice(start).every((call) => call.method === 'GET'));
  const foreign = await namedRestrictedFixture();
  foreign.entry.rules.find((rule) => rule.ref === DENY_REF).id = 'f'.repeat(32);
  const foreignStart = foreign.calls.length;
  await assert.rejects(allowTestAllIP(foreign.client, foreign.manifest, { env: allIPEnv() }), {
    code: 'SAME_NAMED_WAF_RULE_UNOWNED',
  });
  assert.ok(foreign.calls.slice(foreignStart).every((call) => call.method === 'GET'));
});
for (const [name, code, change] of [
  [
    'unrelated rules',
    'TEST_ALL_API_RULESET_CHANGED',
    (f) => {
      f.entry.rules.find((rule) => rule.ref === 'other_service').description += ' drift';
    },
  ],
  [
    'Skip parameters',
    'WAF_SKIP_CAPABILITIES_DRIFT',
    (f) => {
      f.entry.rules.find((rule) => rule.ref === SKIP_REF).action_parameters.products.push('hot');
    },
  ],
  [
    'Custom Errors',
    'TEST_ALL_API_CUSTOM_ERRORS_CHANGED',
    (f) => {
      f.errors.rules[0].description = 'changed';
    },
  ],
  [
    'Worker owner',
    'TEST_ALL_API_WORKER_OWNER_UNPROVEN',
    (f) => {
      f.worker.bindings[0].text = 'another-owner';
    },
  ],
])
  test(`all-IP transition stops before the opening Block PATCH when ${name} drift`, async () => {
    const f = await namedRestrictedFixture(),
      start = f.calls.length,
      request = f.client.request;
    f.client.request = async (path, options) => {
      const result = await request(path, options);
      if (options?.method === 'PATCH' && path.endsWith(f.manifest.security.rules[SKIP_REF]))
        change(f);
      return result;
    };
    await assert.rejects(allowTestAllIP(f.client, f.manifest, { env: allIPEnv() }), { code });
    assert.equal(f.calls.slice(start).filter((call) => call.method === 'PATCH').length, 1);
    assert.equal(
      f.entry.rules.find((rule) => rule.ref === DENY_REF).expression,
      `${API_MATCH} and not (${REVIEWED_IP_CONDITION})`,
    );
  });
for (const [name, code, change] of [
  [
    'path guard',
    'WAF_PATH_GUARD_DRIFT',
    (f) => {
      f.entry.rules.find((rule) => rule.ref === GUARD_REF).expression =
        '(http.host eq "elsewhere.lily.lat")';
    },
  ],
  [
    'disabled path guard',
    'WAF_PATH_GUARD_DRIFT',
    (f) => {
      f.entry.rules.find((rule) => rule.ref === GUARD_REF).enabled = false;
    },
  ],
  [
    'Skip capabilities',
    'WAF_SKIP_CAPABILITIES_DRIFT',
    (f) => {
      f.entry.rules.find((rule) => rule.ref === SKIP_REF).action_parameters.products.push('hot');
    },
  ],
])
  test(`all-IP operation refuses ${name} changed between proof and baseline before any write`, async () => {
    const f = await namedRestrictedFixture(),
      start = f.calls.length,
      request = f.client.request;
    let changed = false;
    f.client.request = async (path, options) => {
      const result = await request(path, options);
      // The Worker settings read is the last fixed GET in the initial project proof.
      // The subsequent before-image GET must independently validate fixed capabilities.
      if (!changed && path === `${ACCOUNT}/workers/scripts/${EXPECTED.WORKER_NAME}/settings`) {
        changed = true;
        change(f);
      }
      return result;
    };
    await assert.rejects(allowTestAllIP(f.client, f.manifest, { env: allIPEnv() }), { code });
    assert.equal(changed, true);
    assert.ok(f.calls.slice(start).every((call) => call.method === 'GET'));
  });
test('test full-IP verification requires the immutable authorization and production never accepts it', async () => {
  const f = await namedRestrictedFixture();
  await allowTestAllIP(f.client, f.manifest, { env: allIPEnv() });
  const record = copy(f.manifest.security.temporary_all_ip);
  delete f.manifest.security.temporary_all_ip;
  await assert.rejects(verifySecurity(f.client, f.manifest), {
    code: 'TEST_ALL_IP_AUTHORIZATION_REQUIRED',
  });
  // The explicit full-IP condition still needs its authorization if a legacy manifest
  // restriction marker is missing. Ordinary test deployment must not silently accept it.
  const restricted = f.manifest.security.restricted_ip;
  delete f.manifest.security.restricted_ip;
  await assert.rejects(verifySecurity(f.client, f.manifest), {
    code: 'TEST_ALL_IP_AUTHORIZATION_REQUIRED',
  });
  f.manifest.security.restricted_ip = restricted;
  f.manifest.security.temporary_all_ip = record;
  const path = objectPath(`delivery/${f.manifest.owner_id}/${TEST_ALL_IP_CHECKPOINT_KEY}.json`);
  const saved = JSON.parse(f.objects.get(path));
  saved.authorization = 'unrelated-manual-operation';
  f.objects.set(path, JSON.stringify(saved));
  await assert.rejects(verifySecurity(f.client, f.manifest), {
    code: 'TEST_ALL_IP_CHECKPOINT_INVALID',
  });
  await assert.rejects(verifySecurity(f.client, f.manifest, { production: true }), {
    code: 'PRODUCTION_ALL_NETWORK_CIDR_FORBIDDEN',
  });
});
test('reviewed restriction blocks all outsiders before narrowing Skip and retains unrelated fields and Custom Errors', async () => {
  const f = fixture();
  const unrelated = copy(f.entry.rules[2]);
  const parameters = copy(f.entry.rules[1].action_parameters);
  const errorBefore = copy(f.errors);
  await restrictAPI(f.client, f.manifest);
  assert.deepEqual(
    f.entry.rules.map((r) => r.ref),
    [GUARD_REF, DENY_REF, SKIP_REF, 'other_service'],
  );
  assert.equal(f.entry.rules[1].expression, `${API_MATCH} and not (${REVIEWED_IP_CONDITION})`);
  assert.equal(f.entry.rules[2].expression, `${API_MATCH} and (${REVIEWED_IP_CONDITION})`);
  assert.deepEqual(f.entry.rules[2].action_parameters, parameters);
  assert.deepEqual(f.entry.rules[3], unrelated);
  assert.deepEqual(f.errors, errorBefore);
  assert.ok(
    f.calls.findIndex((c) => c.method === 'POST') < f.calls.findIndex((c) => c.method === 'PATCH'),
  );
  assert.equal(f.manifest.security.restricted_ip.status, 'complete');
  assert.ok(
    f.objects.has(objectPath(`delivery/${f.manifest.owner_id}/restricted-api-before.json`)),
  );
  const writes = f.calls.filter((c) => c.method !== 'GET').length;
  f.entry.rules[1].expression = `${API_MATCH} and not (ip.src in {192.0.2.8})`;
  f.entry.rules[2].expression = `${API_MATCH} and (ip.src in {192.0.2.8})`;
  await restrictAPI(f.client, f.manifest);
  assert.equal(
    f.calls.filter((c) => c.method !== 'GET').length,
    writes,
    'operator-maintained list is never overwritten',
  );
});
test('lost create response reconciles owned deny without a duplicate or whole-ruleset write', async () => {
  const f = fixture();
  f.setAfterCreate(() => {
    throw new DeliveryError('WRITE_RESULT_UNKNOWN_RECONCILE_REQUIRED');
  });
  await assert.rejects(restrictAPI(f.client, f.manifest), {
    code: 'WRITE_RESULT_UNKNOWN_RECONCILE_REQUIRED',
  });
  f.setAfterCreate(null);
  await restrictAPI(f.client, f.manifest);
  assert.equal(f.calls.filter((c) => c.method === 'POST').length, 1);
  assert.equal(f.entry.rules.filter((r) => r.ref === DENY_REF).length, 1);
  assert.ok(f.calls.filter((c) => c.method === 'PATCH').every((c) => c.path.includes('/rules/')));
});
test('drift after Block creation stops before Skip patch and an earlier bypassing Skip stops restriction', async () => {
  const f = fixture();
  f.setAfterCreate((entry) => {
    entry.rules.find((r) => r.ref === SKIP_REF).action_parameters.products.push('hot');
  });
  await assert.rejects(restrictAPI(f.client, f.manifest), { code: 'WAF_SKIP_PREWRITE_DRIFT' });
  assert.equal(f.calls.filter((c) => c.method === 'PATCH').length, 0);
  const earlier = fixture();
  earlier.entry.rules.unshift({
    id: 'e'.repeat(32),
    ref: 'earlier',
    action: 'skip',
    enabled: true,
    expression: 'true',
    action_parameters: { ruleset: 'current' },
  });
  await assert.rejects(restrictAPI(earlier.client, earlier.manifest), {
    code: 'PRODUCTION_EARLIER_SKIP_CAN_BYPASS_DENY',
  });
  assert.equal(earlier.calls.filter((c) => c.method === 'PATCH').length, 0);
});
test('rename changes only reviewed display fields and IDs, AUD, policies and WAF order remain stable', async () => {
  const f = fixture();
  await restrictAPI(f.client, f.manifest);
  const beforeApps = copy(f.apps);
  const ids = f.entry.rules.map((r) => r.id);
  const parameters = copy(f.entry.rules.find((r) => r.ref === SKIP_REF).action_parameters);
  const result = await renameSecurity(f.client, f.manifest);
  assert.equal(result.changes.length, 6);
  assert.deepEqual(
    f.entry.rules.map((r) => r.id),
    ids,
  );
  assert.deepEqual(f.entry.rules.find((r) => r.ref === SKIP_REF).action_parameters, parameters);
  assert.deepEqual(
    f.apps.map((a) => ({ ...a, name: null })),
    beforeApps.map((a) => ({ ...a, name: null })),
  );
  assert.deepEqual(
    f.apps.map((a) => a.name),
    Object.values(DISPLAY_NAMES.apps),
  );
  await verifySecurity(f.client, f.manifest);
  const writes = f.calls.filter((c) => c.method !== 'GET').length;
  await renameSecurity(f.client, f.manifest);
  assert.equal(f.calls.filter((c) => c.method !== 'GET').length, writes);
  f.entry.rules.find((r) => r.ref === SKIP_REF).expression = API_MATCH;
  await assert.rejects(verifySecurity(f.client, f.manifest), {
    code: 'PRODUCTION_TEMPORARY_ALL_IP_FORBIDDEN',
  });
});
test('readable name cannot prove ownership and unknown Access fields cannot be silently dropped', () => {
  const f = fixture();
  f.manifest.security.display_names = {
    owner_id: f.manifest.owner_id,
    ...DISPLAY_NAMES,
    status: 'complete',
  };
  const rule = { ...f.entry.rules[1], description: DISPLAY_NAMES.rules[SKIP_REF] };
  assert.equal(ownedRule(rule, f.manifest), true);
  assert.equal(ownedRule({ ...rule, id: 'foreign' }, f.manifest), false);
  assert.throws(
    () => accessRenameBody({ ...f.apps[0], unknown_security_option: false }, 'Readable'),
    { code: 'ACCESS_RENAME_FIELDS_UNREVIEWED' },
  );
});
test('lost Access or WAF rename response resumes from recorded identities without repeating the successful rename', async () => {
  for (const lostTarget of ['access', 'waf']) {
    const f = fixture();
    await restrictAPI(f.client, f.manifest);
    const request = f.client.request;
    let failed = false;
    let appliedPath;
    f.client.request = async (path, options = {}) => {
      const result = await request(path, options);
      if (
        !failed &&
        ((lostTarget === 'access' && options.method === 'PUT' && path.includes('/access/apps/')) ||
          (lostTarget === 'waf' && options.method === 'PATCH' && path.includes('/rules/')))
      ) {
        failed = true;
        appliedPath = path;
        throw new DeliveryError('WRITE_RESULT_UNKNOWN_RECONCILE_REQUIRED');
      }
      return result;
    };
    await assert.rejects(renameSecurity(f.client, f.manifest), {
      code: 'WRITE_RESULT_UNKNOWN_RECONCILE_REQUIRED',
    });
    await renameSecurity(f.client, f.manifest);
    assert.equal(f.manifest.security.display_names.status, 'complete');
    assert.equal(
      f.calls.filter(
        (c) => c.path === appliedPath && c.method === (lostTarget === 'access' ? 'PUT' : 'PATCH'),
      ).length,
      1,
    );
  }
});
test('domain verification credential needs proven independent read-only scope, actual fixed endpoints and never deploy token fallback', async () => {
  const accountKey = `com.cloudflare.api.account.${EXPECTED.CLOUDFLARE_ACCOUNT_ID}`;
  const policy = {
    policies: [
      {
        effect: 'allow',
        permission_groups: [{ name: 'Workers Scripts Read' }, { name: 'Analytics Read' }],
        resources: { [accountKey]: '*' },
      },
    ],
  };
  assert.equal(domainReadPolicyQualified(policy), true);
  assert.equal(
    domainReadPolicyQualified({
      policies: [{ ...policy.policies[0], permission_groups: [{ name: 'Workers Scripts Write' }] }],
    }),
    false,
  );
  assert.equal(
    domainReadPolicyQualified({
      policies: [{ ...policy.policies[0], resources: { 'com.cloudflare.api.account.*': '*' } }],
    }),
    false,
  );
  assert.equal(
    domainReadPolicyQualified({
      policies: [{ ...policy.policies[0], permission_groups: [{ name: 'Analytics Read' }] }],
    }),
    false,
  );
  const f = fixture();
  f.manifest.domains[EXPECTED.PUBLIC_HOSTNAME] = { id: 'domain-id' };
  const calls = [];
  const fetcher = async (url, options) => {
    assert.equal(options.method, 'GET');
    assert.equal(options.redirect, 'error');
    calls.push(new URL(url).pathname);
    let result;
    if (url.endsWith('/tokens/verify')) result = { status: 'active', id: 'f'.repeat(32) };
    else if (url.includes('/tokens/')) result = policy;
    else if (url.includes('/settings'))
      result = {
        bindings: [
          { name: 'RESOURCE_OWNER_ID', type: 'plain_text', text: f.manifest.owner_id },
          { name: 'DB', type: 'd1', id: f.manifest.d1.id },
          { name: 'BACKUPS', type: 'r2_bucket', bucket_name: BUCKET },
        ],
      };
    else
      result = [
        {
          id: 'domain-id',
          hostname: EXPECTED.PUBLIC_HOSTNAME,
          service: EXPECTED.WORKER_NAME,
          environment: 'production',
          zone_id: EXPECTED.CF_ZONE_ID_GFW_MOM,
        },
      ];
    return new Response(JSON.stringify({ success: true, result }), {
      headers: { 'Content-Type': 'application/json' },
    });
  };
  const selected = await selectDomainReadCredential(
    {
      CLOUDFLARE_API_TOKEN: 'deploy-secret',
      CF_ANALYTICS_READ_TOKEN: 'independent-readonly-secret',
    },
    f.manifest,
    fetcher,
  );
  assert.equal(selected.source, 'CF_ANALYTICS_READ_TOKEN');
  assert.equal(calls.length, 4);
  const refused = await selectDomainReadCredential(
    { CLOUDFLARE_API_TOKEN: 'deploy-secret', CF_ANALYTICS_READ_TOKEN: 'deploy-secret' },
    f.manifest,
    fetcher,
  );
  assert.equal(refused.token, null);
  assert.equal(calls.length, 4);
  assert.doesNotMatch(JSON.stringify(refused), /deploy-secret/);
});
test('security maintenance uses only dispatch, main, shared mutual exclusion and no deployment command', () => {
  const yaml = readFileSync('.github/workflows/security-maintenance.yml', 'utf8');
  assert.match(yaml, /on:\n  workflow_dispatch:/);
  assert.match(yaml, /group: shortlink-new-cloudflare/);
  assert.match(yaml, /cancel-in-progress: false/);
  assert.match(yaml, /github.ref == 'refs\/heads\/main'/);
  assert.doesNotMatch(yaml, /\n  (push|schedule|pull_request):|scripts\/deploy|upload-artifact/);
  assert.match(yaml, /- allow-test-all-ip/);
  assert.ok(yaml.includes(CONFIRMATIONS['allow-test-all-ip']));
});
