import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  changeCustomErrorRule,
  digest,
  entryDigest,
  exactException,
  proveProjectSecurity,
} from '../scripts/security-api-errors.mjs';
import {
  ACCOUNT,
  ADMIN_ZONE,
  EXPECTED,
  REPOSITORY,
  DeliveryError,
  safeError,
  OWNER_KEY,
} from '../scripts/cf-client.mjs';
import { objectPath } from '../scripts/deploy-resources.mjs';
import { API_MATCH, GUARD_MATCH, GUARD_REF, SKIP_REF } from '../scripts/security-bootstrap.mjs';

const copy = (value) => JSON.parse(JSON.stringify(value));
const owner = 'a86f9ff4-e40b-4c86-9e66-978906f04991';
const id = 'a'.repeat(32);
const ruleId = 'b'.repeat(32);
const snapshotPath = objectPath(`delivery/${owner}/custom-error-api-checkpoint.json`);
const manifestPath = objectPath(OWNER_KEY);
const entryPath = `${ADMIN_ZONE}/rulesets/${id}`;
const patchPath = `${entryPath}/rules/${ruleId}`;
function fixture() {
  const entry = {
    id,
    kind: 'zone',
    phase: 'http_custom_errors',
    name: 'fixture',
    description: 'fixture',
    version: '1',
    last_updated: 'fixture-before',
    rules: [
      {
        id: 'c'.repeat(32),
        expression: 'false',
        action: 'serve_error',
        enabled: false,
        action_parameters: {
          content: 'unchanged original fixture body',
          content_type: 'text/html',
        },
      },
      {
        id: ruleId,
        ref: 'fixture_original',
        description: 'fixture original error',
        action: 'serve_error',
        enabled: true,
        expression: '(http.response.code eq 401) or (http.response.code eq 405)',
        action_parameters: {
          asset_name: 'fixture_asset',
          content_type: 'text/html',
          status_code: 403,
        },
        version: '1',
        last_updated: 'fixture-before',
      },
      {
        id: 'd'.repeat(32),
        expression: 'false',
        action: 'serve_error',
        enabled: false,
        action_parameters: {
          content: 'unchanged trailing fixture body',
          content_type: 'text/html',
        },
      },
    ],
  };
  const original = copy(entry);
  const target = {
    schema: 1,
    kind: 'zone',
    phase: 'http_custom_errors',
    ruleset_id: id,
    rule_id: ruleId,
    original_definition_sha256: digest(
      Object.fromEntries(
        Object.entries(entry.rules[1]).filter(
          ([key]) => !['version', 'last_updated'].includes(key),
        ),
      ),
    ),
    original_entrypoint_sha256: entryDigest(entry),
  };
  const manifest = {
    schema: 1,
    project: REPOSITORY,
    account: EXPECTED.CLOUDFLARE_ACCOUNT_ID,
    worker: EXPECTED.WORKER_NAME,
    environment: 'test',
    bucket: 'shortlink-new-backups',
    owner_id: owner,
    d1: { id: '707a9796-4ce5-47fd-a4ae-e590112ac69e', name: 'shortlink-new-test' },
    security: { status: 'ready', apps: {}, rules: {} },
  };
  const calls = [];
  const objects = new Map();
  let proofs = 0;
  const options = {
    reviewedTarget: target,
    now: () => new Date('2026-10-05T00:00:00.000Z'),
    prove: async () => {
      proofs++;
    },
  };
  const client = {
    optional: async (path) => {
      calls.push({ path, method: 'GET' });
      assert.equal(path, snapshotPath);
      return objects.get(path) ?? null;
    },
    request: async (path, request = {}) => {
      calls.push({ path, ...copy(request), method: request.method || 'GET' });
      if (!request.method) {
        assert.equal(path, entryPath);
        return { success: true, result: copy(entry) };
      }
      if (request.method === 'PUT') {
        assert.ok([snapshotPath, manifestPath].includes(path));
        if (path === snapshotPath) assert.equal(objects.has(path), false, 'immutable checkpoint');
        objects.set(path, request.body);
        return { success: true, result: {} };
      }
      assert.equal(request.method, 'PATCH');
      assert.ok([patchPath, `${patchPath}?dry_run=true`].includes(path));
      assert.deepEqual(Object.keys(request.json).sort(), [
        'action',
        'action_parameters',
        'description',
        'enabled',
        'expression',
        'ref',
      ]);
      assert.deepEqual(request.json.action_parameters, original.rules[1].action_parameters);
      assert.equal(request.json.ref, original.rules[1].ref);
      assert.equal(request.json.enabled, true);
      assert.equal(request.json.description, original.rules[1].description);
      if (path.endsWith('?dry_run=true')) return { success: true, result: null };
      entry.rules[1] = {
        ...copy(request.json),
        id: ruleId,
        version: '2',
        last_updated: 'fixture-after',
      };
      entry.version = '2';
      entry.last_updated = 'fixture-after';
      return { success: true, result: copy(entry) };
    },
  };
  return {
    client,
    manifest,
    target,
    options,
    entry,
    original,
    calls,
    objects,
    proofs: () => proofs,
  };
}
const actualPatches = (f) =>
  f.calls.filter((call) => call.method === 'PATCH' && call.path === patchPath);
const writes = (f) => f.calls.filter((call) => call.method && call.method !== 'GET');

function securityProofFixture() {
  const f = fixture();
  const otp = { id: 'bd751516-c314-4531-a137-a4e5e847cd88', type: 'onetimepin' };
  const customId = '2'.repeat(32);
  const guardId = 'f'.repeat(32);
  const skipId = '1'.repeat(32);
  const prefix = `shortlink-new:${owner}:`;
  const skipParameters = {
    ruleset: 'current',
    products: ['bic'],
    phases: ['http_request_firewall_managed', 'http_ratelimit', 'http_request_sbfm'],
  };
  const customEntry = {
    id: customId,
    kind: 'zone',
    phase: 'http_request_firewall_custom',
    rules: [
      {
        id: guardId,
        ref: GUARD_REF,
        action: 'block',
        enabled: true,
        expression: GUARD_MATCH,
        description: `${prefix}machine-child-path-guard`,
      },
      {
        id: skipId,
        ref: SKIP_REF,
        action: 'skip',
        enabled: true,
        expression: API_MATCH,
        description: `${prefix}machine-api-skip`,
        action_parameters: copy(skipParameters),
      },
    ],
  };
  const applications = ['admin', 'api', 'children'].map((key, index) => ({
    id: `d8f01a24-b7bf-48a8-9318-04aca727608${index}`,
    aud: String(index + 5).repeat(64),
    type: 'self_hosted',
    name: `${prefix}${{ admin: 'admin', api: 'machine', children: 'machine-children-guard' }[key]}`,
    domain: {
      admin: EXPECTED.ADMIN_HOSTNAME,
      api: `${EXPECTED.ADMIN_HOSTNAME}/api/shorten`,
      children: `${EXPECTED.ADMIN_HOSTNAME}/api/shorten/*`,
    }[key],
    allow_authenticate_via_warp: false,
    allowed_idps: [otp.id],
  }));
  // This is the actual manifest structure written by security-bootstrap: rule refs map
  // directly to ID strings; Access app entries are objects containing id and aud.
  f.manifest.security = {
    status: 'ready',
    before_saved: true,
    ruleset_id: customId,
    rules: { [GUARD_REF]: guardId, [SKIP_REF]: skipId },
    apps: Object.fromEntries(
      ['admin', 'api', 'children'].map((key, index) => [
        key,
        { id: applications[index].id, aud: applications[index].aud },
      ]),
    ),
    skip_parameters: copy(skipParameters),
  };
  const worker = {
    bindings: [
      { name: 'RESOURCE_OWNER_ID', type: 'plain_text', text: owner },
      { name: 'DB', type: 'd1', id: f.manifest.d1.id, database_id: f.manifest.d1.id },
      { name: 'BACKUPS', type: 'r2_bucket', bucket_name: f.manifest.bucket },
      { name: 'ASSETS', type: 'assets' },
      { name: 'TURNSTILE_SECRET_KEY', type: 'secret_text' },
    ],
  };
  const pages = new Map([
    [`${ACCOUNT}/access/organizations`, { auth_domain: EXPECTED.CF_ACCESS_TEAM_DOMAIN }],
    [`${ACCOUNT}/access/identity_providers`, [otp]],
    [`${ACCOUNT}/access/apps`, applications],
    [`${ADMIN_ZONE}/bot_management`, { fight_mode: false }],
    [`${ADMIN_ZONE}/settings`, []],
    [
      `${ADMIN_ZONE}/rulesets`,
      [
        { id: customId, kind: 'zone', phase: 'http_request_firewall_custom' },
        { id, kind: 'zone', phase: 'http_custom_errors' },
        { id: '3'.repeat(32), kind: 'managed', phase: 'http_request_firewall_managed' },
      ],
    ],
    [`${ACCOUNT}/rulesets`, []],
    [`${ADMIN_ZONE}/rulesets/${customId}`, customEntry],
    [`${ACCOUNT}/workers/scripts/${EXPECTED.WORKER_NAME}/settings`, worker],
  ]);
  for (const [index, application] of applications.entries())
    pages.set(`${ACCOUNT}/access/apps/${application.id}/policies`, [
      {
        name: `${prefix}fixture-policy-${index}`,
        decision: index === 1 ? 'bypass' : 'allow',
        include:
          index === 1
            ? [{ everyone: {} }]
            : EXPECTED.ADMIN_EMAILS.split(',').map((email) => ({ email: { email } })),
        require: [],
        exclude: [],
        precedence: 1,
      },
    ]);
  const request = f.client.request;
  const proofCalls = [];
  f.client.request = async (path, options = {}) => {
    const url = new URL(`https://api.cloudflare.com/client/v4${path}`);
    const relative = url.pathname.slice('/client/v4'.length);
    if (!pages.has(relative)) return request(path, options);
    assert.equal(options.method || 'GET', 'GET', 'real proof uses readonly endpoints only');
    assert.equal(options.json, undefined, 'proof never executes SQL or sends data');
    assert.ok([...url.searchParams.keys()].every((key) => ['per_page', 'page'].includes(key)));
    proofCalls.push({ path, method: 'GET' });
    return { success: true, result: copy(pages.get(relative)), result_info: { total_pages: 1 } };
  };
  return { ...f, customEntry, applications, pages, worker, proofCalls };
}

test('real security proof accepts actual string-rule manifest and validates protected app policies and Worker bindings', async () => {
  const f = securityProofFixture();
  await proveProjectSecurity(f.client, f.manifest);
  assert.equal(typeof f.manifest.security.rules[GUARD_REF], 'string');
  assert.equal(typeof f.manifest.security.apps.admin, 'object');
  assert.equal(
    f.proofCalls.filter((call) => call.path.endsWith('/policies?per_page=100&page=1')).length,
    3,
  );
  assert.ok(
    f.proofCalls.some((call) => call.path.endsWith('/workers/scripts/shortlink-new/settings')),
  );
  assert.ok(f.proofCalls.every((call) => call.method === 'GET'));
  assert.ok(f.calls.every((call) => call.method === 'GET'));
  assert.ok(
    f.proofCalls.every((call) => !call.path.includes(`/rulesets/${'3'.repeat(32)}`)),
    'managed catalog definitions are not mistaken for deployed entrypoints',
  );
});

test('real proof integrates into the actual change path before every patch and checkpoint write', async () => {
  const f = securityProofFixture();
  const { prove: _unusedStub, ...options } = f.options;
  const result = await changeCustomErrorRule(f.client, f.manifest, options);
  assert.equal(result.changed, true);
  assert.equal(actualPatches(f).length, 1);
  assert.equal(f.manifest.security.custom_error_api.status, 'applied');
  assert.equal(
    f.proofCalls.filter((call) => call.path.endsWith('/workers/scripts/shortlink-new/settings'))
      .length,
    3,
  );
});

test('real proof handles both documented D1 aliases while rejecting conflicting dual-field IDs', async () => {
  for (const remove of ['id', 'database_id', null]) {
    const f = securityProofFixture();
    const database = f.worker.bindings.find((binding) => binding.name === 'DB');
    if (remove) delete database[remove];
    await proveProjectSecurity(f.client, f.manifest);
  }
  for (const change of ['id', 'database_id']) {
    const f = securityProofFixture();
    f.worker.bindings.find((binding) => binding.name === 'DB')[change] =
      '5d651f88-d50a-4146-8099-0931f12b5bcc';
    await assert.rejects(proveProjectSecurity(f.client, f.manifest), {
      code: 'PROJECT_WORKER_D1_DRIFT',
    });
    assert.equal(writes(f).length, 0);
  }
});

test('real proof rejects mismatched rule strings, object-shaped rule records and other actual ownership drift before writes', async () => {
  for (const [mutate, code] of [
    [
      (f) => {
        f.manifest.security.rules[GUARD_REF] = { id: f.manifest.security.rules[GUARD_REF] };
      },
      'PROJECT_WAF_ID_OWNERSHIP_UNPROVEN',
    ],
    [
      (f) => {
        f.manifest.security.rules[SKIP_REF] = '9'.repeat(32);
      },
      'PROJECT_WAF_ID_OWNERSHIP_UNPROVEN',
    ],
    [
      (f) => {
        f.manifest.security.ruleset_id = '8'.repeat(32);
      },
      'PROJECT_WAF_ID_OWNERSHIP_UNPROVEN',
    ],
    [
      (f) => {
        f.customEntry.rules[0].id = '7'.repeat(32);
      },
      'PROJECT_WAF_ID_OWNERSHIP_UNPROVEN',
    ],
    [
      (f) => {
        f.manifest.security.apps.admin.id = '51d45d91-3578-45ef-9c3c-f1384e361b2d';
      },
      'ACCESS_APPLICATION_DRIFT',
    ],
    [
      (f) => {
        f.worker.bindings.find((binding) => binding.name === 'RESOURCE_OWNER_ID').text = 'foreign';
      },
      'PROJECT_WORKER_OWNER_UNPROVEN',
    ],
    [
      (f) => {
        f.worker.bindings.push(copy(f.worker.bindings.find((binding) => binding.name === 'DB')));
      },
      'PROJECT_WORKER_D1_DRIFT',
    ],
    [
      (f) => {
        f.worker.bindings.find((binding) => binding.name === 'BACKUPS').bucket_name =
          'foreign-bucket';
      },
      'PROJECT_WORKER_R2_DRIFT',
    ],
    [
      (f) => {
        delete f.manifest.d1;
      },
      'RESOURCE_BOOTSTRAP_REQUIRED',
    ],
  ]) {
    const f = securityProofFixture();
    mutate(f);
    const { prove: _unusedStub, ...options } = f.options;
    await assert.rejects(changeCustomErrorRule(f.client, f.manifest, options), { code });
    assert.equal(writes(f).length, 0);
    assert.equal(f.objects.size, 0);
  }
});

test('complete rule definition, exact grouped exception, dry run first and immutable preimage', async () => {
  const f = fixture();
  const result = await changeCustomErrorRule(f.client, f.manifest, f.options);
  assert.equal(result.changed, true);
  assert.equal(actualPatches(f).length, 1);
  assert.equal(f.calls.find((call) => call.method !== 'GET').path, `${patchPath}?dry_run=true`);
  assert.equal(f.entry.rules[1].expression, exactException(f.original.rules[1].expression));
  assert.match(
    f.entry.rules[1].expression,
    /^\(.* or .*\) and not \(http\.host eq "link-admin\.lily\.lat" and http\.request\.uri\.path eq "\/api\/shorten"\)$/,
  );
  assert.deepEqual(f.entry.rules[0], f.original.rules[0]);
  assert.deepEqual(f.entry.rules[2], f.original.rules[2]);
  const checkpoint = JSON.parse(f.objects.get(snapshotPath));
  assert.deepEqual(checkpoint.original_entrypoint, f.original);
  assert.equal(f.manifest.security.custom_error_api.status, 'applied');
  assert.equal(f.proofs(), 3);
  const repeated = await changeCustomErrorRule(f.client, f.manifest, f.options);
  assert.equal(repeated.recovered_without_rule_write, true);
  assert.equal(actualPatches(f).length, 1);
  assert.equal(
    f.calls.filter((call) => call.method === 'PUT' && call.path === snapshotPath).length,
    1,
  );
  assert.ok(
    writes(f).every((call) =>
      [snapshotPath, manifestPath, patchPath, `${patchPath}?dry_run=true`].includes(call.path),
    ),
  );
});

test('ownership proof failure precedes every request and every write', async () => {
  const f = fixture();
  await assert.rejects(
    changeCustomErrorRule(f.client, f.manifest, {
      ...f.options,
      prove: async () => {
        throw new DeliveryError('PROJECT_WAF_ID_OWNERSHIP_UNPROVEN');
      },
    }),
    { code: 'PROJECT_WAF_ID_OWNERSHIP_UNPROVEN' },
  );
  assert.equal(f.calls.length, 0);
});

test('wrong metadata, wrong ID, reordered rules or unknown target fields cannot authorize writes', async () => {
  for (const mutate of [
    (f) => {
      f.entry.kind = 'managed';
    },
    (f) => {
      f.entry.phase = 'http_request_firewall_custom';
    },
    (f) => {
      f.entry.rules[1].id = 'e'.repeat(32);
    },
    (f) => {
      f.entry.rules.reverse();
    },
    (f) => {
      f.entry.rules[1].logging = { enabled: true };
    },
    (f) => {
      f.entry.rules[1].action_parameters.content = 'unreviewed';
    },
  ]) {
    const f = fixture();
    mutate(f);
    await assert.rejects(changeCustomErrorRule(f.client, f.manifest, f.options));
    assert.equal(writes(f).length, 0);
  }
});

test('dry-run permission failure writes neither rule nor R2 checkpoint or manifest', async () => {
  const f = fixture();
  const request = f.client.request;
  f.client.request = async (path, options) => {
    if (path.endsWith('?dry_run=true')) throw new DeliveryError('PERMISSION_DENIED', 403);
    return request(path, options);
  };
  await assert.rejects(changeCustomErrorRule(f.client, f.manifest, f.options), {
    code: 'CUSTOM_ERROR_DRY_RUN_PERMISSION_DENIED',
    status: 403,
  });
  assert.equal(f.objects.size, 0);
  assert.equal(actualPatches(f).length, 0);
});

test('dry-run denial exposes only fixed category and no endpoint IDs or response payload', async () => {
  const f = fixture();
  const request = f.client.request;
  f.client.request = async (path, options) => {
    if (path.endsWith('?dry_run=true')) throw new DeliveryError('PERMISSION_DENIED', 403, [10000]);
    return request(path, options);
  };
  await assert.rejects(changeCustomErrorRule(f.client, f.manifest, f.options), (error) => {
    assert.deepEqual(safeError(error), {
      code: 'CUSTOM_ERROR_DRY_RUN_PERMISSION_DENIED',
      http_status: 403,
      cf_error_codes: [10000],
      endpoint_category: 'ZONE_RULESETS',
      request_method: 'PATCH',
      detail: 'Raw responses, credentials and business data are withheld.',
    });
    assert.doesNotMatch(JSON.stringify(safeError(error)), /fixture|rulesets\/|owner_id/);
    return true;
  });
  assert.equal(f.objects.size, 0);
  assert.equal(actualPatches(f).length, 0);
});

test('an unexpected new version during dry-run prevents all persistent writes', async () => {
  const f = fixture();
  const request = f.client.request;
  f.client.request = async (path, options) => {
    const response = await request(path, options);
    if (path.endsWith('?dry_run=true')) f.entry.version = 'unexpected-server-or-concurrent-version';
    return response;
  };
  await assert.rejects(changeCustomErrorRule(f.client, f.manifest, f.options), {
    code: 'CUSTOM_ERROR_DRY_RUN_OR_CONCURRENT_DRIFT',
  });
  assert.equal(f.objects.size, 0);
  assert.equal(actualPatches(f).length, 0);
});

test('unexpected dry-run result cannot fall through to a real patch', async () => {
  const f = fixture();
  const request = f.client.request;
  f.client.request = async (path, options) =>
    path.endsWith('?dry_run=true')
      ? { success: true, result: copy(f.entry) }
      : request(path, options);
  await assert.rejects(changeCustomErrorRule(f.client, f.manifest, f.options), {
    code: 'CUSTOM_ERROR_DRY_RUN_RESPONSE_INVALID',
  });
  assert.equal(f.objects.size, 0);
  assert.equal(actualPatches(f).length, 0);
});

test('external mutation between saved checkpoint and patch stops without overwriting', async () => {
  const f = fixture();
  f.options.prove = async () => {
    if (f.manifest.security.custom_error_api?.status === 'planned')
      f.entry.rules[0].description = 'external operator change';
  };
  await assert.rejects(changeCustomErrorRule(f.client, f.manifest, f.options), {
    code: 'CUSTOM_ERROR_PREWRITE_DRIFT',
  });
  assert.equal(actualPatches(f).length, 0);
  assert.equal(f.entry.rules[0].description, 'external operator change');
  assert.ok(f.objects.has(snapshotPath));
});

test('lost PATCH response is reconciled on retry, never patched twice', async () => {
  const f = fixture();
  const request = f.client.request;
  let lost = true;
  f.client.request = async (path, options) => {
    const result = await request(path, options);
    if (path === patchPath && options?.method === 'PATCH' && lost) {
      lost = false;
      throw new DeliveryError('WRITE_RESULT_UNKNOWN_RECONCILE_REQUIRED');
    }
    return result;
  };
  await assert.rejects(changeCustomErrorRule(f.client, f.manifest, f.options), {
    code: 'WRITE_RESULT_UNKNOWN_RECONCILE_REQUIRED',
  });
  assert.equal(f.manifest.security.custom_error_api.status, 'planned');
  const result = await changeCustomErrorRule(f.client, f.manifest, f.options);
  assert.equal(result.recovered_without_rule_write, true);
  assert.equal(actualPatches(f).length, 1);
  assert.equal(f.manifest.security.custom_error_api.status, 'applied');
});

test('manifest failure after successful patch can recover from immutable checkpoint', async () => {
  const f = fixture();
  const request = f.client.request;
  let fail = true;
  f.client.request = async (path, options) => {
    if (
      path === manifestPath &&
      JSON.parse(options.body).security.custom_error_api.status === 'applied' &&
      fail
    ) {
      fail = false;
      throw new DeliveryError('WRITE_RESULT_UNKNOWN_RECONCILE_REQUIRED');
    }
    return request(path, options);
  };
  await assert.rejects(changeCustomErrorRule(f.client, f.manifest, f.options));
  const actualManifest = JSON.parse(f.objects.get(manifestPath));
  assert.equal(actualManifest.security.custom_error_api.status, 'planned');
  const result = await changeCustomErrorRule(f.client, actualManifest, f.options);
  assert.equal(result.recovered_without_rule_write, true);
  assert.equal(actualPatches(f).length, 1);
});

test('failed manifest planning prevents the rule PATCH and reuses the first checkpoint', async () => {
  const f = fixture();
  const request = f.client.request;
  let fail = true;
  f.client.request = async (path, options) => {
    if (path === manifestPath && fail) {
      fail = false;
      throw new DeliveryError('WRITE_RESULT_UNKNOWN_RECONCILE_REQUIRED');
    }
    return request(path, options);
  };
  await assert.rejects(changeCustomErrorRule(f.client, f.manifest, f.options));
  assert.equal(actualPatches(f).length, 0);
  await changeCustomErrorRule(f.client, f.manifest, f.options);
  assert.equal(actualPatches(f).length, 1);
  assert.equal(
    f.calls.filter((call) => call.method === 'PUT' && call.path === snapshotPath).length,
    1,
  );
});

test('read-back detects changed response configuration or unrelated rule changes and does not restore them', async () => {
  for (const mutate of [
    (f) => {
      f.entry.rules[1].action_parameters.asset_name = 'external_other_asset';
    },
    (f) => {
      f.entry.rules[0].description = 'external operator change';
    },
  ]) {
    const f = fixture();
    const request = f.client.request;
    f.client.request = async (path, options) => {
      const response = await request(path, options);
      if (path === patchPath && options?.method === 'PATCH') mutate(f);
      return response;
    };
    await assert.rejects(changeCustomErrorRule(f.client, f.manifest, f.options), {
      code: 'CUSTOM_ERROR_POSTWRITE_DRIFT',
    });
    assert.equal(actualPatches(f).length, 1, 'no automatic rollback of external changes');
    await assert.rejects(changeCustomErrorRule(f.client, f.manifest, f.options), {
      code: 'CUSTOM_ERROR_CURRENT_DRIFT',
    });
    assert.equal(actualPatches(f).length, 1);
  }
});

test('tampered immutable checkpoint and mismatched manifest linkage both fail closed', async () => {
  for (const mutate of [
    (f) => {
      const cp = JSON.parse(f.objects.get(snapshotPath));
      cp.owner_id = '137e95ba-1b13-4a6b-9aa4-946491690e23';
      f.objects.set(snapshotPath, JSON.stringify(cp));
    },
    (f) => {
      f.manifest.security.custom_error_api.checkpoint_sha256 = '0'.repeat(64);
    },
  ]) {
    const f = fixture();
    await changeCustomErrorRule(f.client, f.manifest, f.options);
    const count = writes(f).length;
    mutate(f);
    await assert.rejects(changeCustomErrorRule(f.client, f.manifest, f.options));
    assert.equal(writes(f).length, count);
  }
});

test('rollback restores only the reviewed rule and is idempotent; operator drift blocks it', async () => {
  const f = fixture();
  await changeCustomErrorRule(f.client, f.manifest, f.options);
  const checkpoint = f.objects.get(snapshotPath);
  const result = await changeCustomErrorRule(f.client, f.manifest, {
    ...f.options,
    operation: 'rollback',
  });
  assert.equal(result.changed, true);
  assert.equal(entryDigest(f.entry), entryDigest(f.original));
  assert.equal(f.objects.get(snapshotPath), checkpoint);
  assert.equal(f.manifest.security.custom_error_api.status, 'rolled_back');
  await changeCustomErrorRule(f.client, f.manifest, { ...f.options, operation: 'rollback' });
  assert.equal(actualPatches(f).length, 2);
  await changeCustomErrorRule(f.client, f.manifest, f.options);
  f.entry.rules[1].description = 'operator revision';
  await assert.rejects(
    changeCustomErrorRule(f.client, f.manifest, { ...f.options, operation: 'rollback' }),
    {
      code: 'CUSTOM_ERROR_CURRENT_DRIFT',
    },
  );
  assert.equal(actualPatches(f).length, 3);
});

test('rollback requires the original checkpoint and rejects unreviewed operations', async () => {
  const f = fixture();
  await assert.rejects(
    changeCustomErrorRule(f.client, f.manifest, { ...f.options, operation: 'rollback' }),
  );
  assert.equal(writes(f).length, 0);
  await assert.rejects(
    changeCustomErrorRule(f.client, f.manifest, { ...f.options, operation: 'remove' }),
  );
  assert.equal(writes(f).length, 0);
});

test('proposed workflow is manual/main/test-only with secret solely in final step', () => {
  const workflow = readFileSync(
    new URL('../.github/workflows/security-api-errors.yml', import.meta.url),
    'utf8',
  );
  assert.match(workflow, /workflow_dispatch:/);
  assert.match(workflow, /github\.ref == 'refs\/heads\/main'/);
  assert.match(workflow, /group: shortlink-new-cloudflare/);
  assert.match(workflow, /cancel-in-progress: false/);
  assert.match(workflow, /environment: shortlink-test/);
  assert.equal((workflow.match(/secrets\.CLOUDFLARE_API_TOKEN/g) || []).length, 1);
  assert.match(workflow, /run: node scripts\/security-api-errors\.mjs\s*$/);
  assert.doesNotMatch(workflow, /\b(?:push|pull_request|schedule):|upload-artifact|always\(\)/);
});
