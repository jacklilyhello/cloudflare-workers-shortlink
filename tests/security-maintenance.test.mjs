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
} from '../scripts/security-bootstrap.mjs';
import {
  restrictAPI,
  renameSecurity,
  accessRenameBody,
  REVIEWED_IP_CONDITION,
} from '../scripts/security-maintenance.mjs';
import { DISPLAY_NAMES, ownedRule } from '../scripts/security-ownership.mjs';
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
    setAfterCreate: (f) => {
      afterCreate = f;
    },
  };
}
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
});
