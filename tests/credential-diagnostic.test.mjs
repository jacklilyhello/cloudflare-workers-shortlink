import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import {
  ACCOUNT,
  PUBLIC_ZONE,
  ADMIN_ZONE,
  EXPECTED,
  BUCKET,
  DATABASE,
  OWNER_KEY,
} from '../scripts/cf-client.mjs';
import { CONFIRMATION, main } from '../scripts/credential-diagnostic.mjs';
import { objectPath } from '../scripts/deploy-resources.mjs';

const sensitive = 'private-business-data-token-key';
const tokenId = 'a'.repeat(32);
const zoneCatalog = [
  { id: '1'.repeat(32), kind: 'managed', phase: 'http_request_sanitize' },
  { id: '2'.repeat(32), kind: 'managed', phase: 'http_request_firewall_managed' },
  { id: '3'.repeat(32), kind: 'zone', phase: 'http_request_firewall_custom' },
];
const env = () => ({
  ...EXPECTED,
  GITHUB_ACTIONS: 'true',
  GITHUB_EVENT_NAME: 'workflow_dispatch',
  GITHUB_REPOSITORY: 'jacklilyhello/cloudflare-workers-shortlink',
  GITHUB_REF: 'refs/heads/main',
  CONFIRM_TARGET: CONFIRMATION,
  CLOUDFLARE_API_TOKEN: sensitive,
});
const json = (result, extra = {}) =>
  new Response(JSON.stringify({ success: true, result, ...extra }));
const denial = () =>
  new Response(JSON.stringify({ success: false, errors: [{ code: 10000, message: sensitive }] }), {
    status: 403,
  });
function fixture(url) {
  const path = new URL(url).pathname.slice('/client/v4'.length);
  if (path === `${ACCOUNT}/tokens/verify`) return json({ status: 'active', id: tokenId });
  if (path === `${ACCOUNT}/tokens/${tokenId}`)
    return json({
      policies: [
        {
          effect: 'allow',
          permission_groups: [{ name: sensitive, id: sensitive }],
          resources: { [sensitive]: '*' },
        },
      ],
    });
  if (path === PUBLIC_ZONE || path === ADMIN_ZONE)
    return json({
      name: path === PUBLIC_ZONE ? 'gfw.mom' : 'lily.lat',
      account: { id: EXPECTED.CLOUDFLARE_ACCOUNT_ID },
    });
  if (path.endsWith(`/workers/scripts/${EXPECTED.LEGACY_WORKER_NAME}/settings`))
    return json({
      bindings: [
        { name: 'LINKS', type: 'kv_namespace', namespace_id: EXPECTED.LEGACY_KV_NAMESPACE_ID },
        { name: sensitive, text: sensitive },
      ],
    });
  if (path.endsWith('/workers/subdomain')) return json({ subdomain: sensitive });
  if (path.endsWith('/access/organizations'))
    return json({ auth_domain: EXPECTED.CF_ACCESS_TEAM_DOMAIN });
  if (path.endsWith('/access/identity_providers'))
    return json([{ id: sensitive, type: 'onetimepin' }], { result_info: { total_count: 1 } });
  if (path.endsWith('/bot_management')) return json({ fight_mode: false, private: sensitive });
  if (path.endsWith('/settings')) return json([{ id: sensitive, value: sensitive }]);
  if (path.endsWith('/d1/database'))
    return json([{ name: DATABASE, uuid: sensitive }], { result_info: { total_count: 1 } });
  if (path === `${ACCOUNT}/r2/buckets`)
    return json({ buckets: [{ name: BUCKET, private: sensitive }] });
  if (path === objectPath(OWNER_KEY))
    return new Response(
      JSON.stringify({
        schema: 1,
        project: env().GITHUB_REPOSITORY,
        account: EXPECTED.CLOUDFLARE_ACCOUNT_ID,
        worker: EXPECTED.WORKER_NAME,
        environment: 'test',
        bucket: BUCKET,
        owner_id: 'ab733f50-89fb-439c-abda-bab2d91f20f0',
        private: sensitive,
      }),
    );
  if (path.endsWith('/keys')) {
    const limit = Number(new URL(url).searchParams.get('limit'));
    if (!Number.isInteger(limit) || limit < 10 || limit > 1000)
      return new Response(
        JSON.stringify({ success: false, errors: [{ code: 10028, message: sensitive }] }),
        { status: 400 },
      );
    return json(
      Array.from({ length: 10 }, (_, index) => ({
        name: `${sensitive}-${index}`,
        metadata: { private: sensitive },
      })),
    );
  }
  if (path === `${ADMIN_ZONE}/rulesets`)
    return json(zoneCatalog, { result_info: { total_count: zoneCatalog.length } });
  if (path === `${ACCOUNT}/rulesets`)
    return json([zoneCatalog[1]], { result_info: { total_count: 1 } });
  if (path === `${ADMIN_ZONE}/rulesets/${zoneCatalog[2].id}`)
    return json({
      ...zoneCatalog[2],
      name: sensitive,
      rules: [{ expression: sensitive, private: sensitive }],
    });
  if (
    ['/workers/domains', '/access/apps', '/rulesets', '/dns_records', '/workers/routes'].some(
      (ending) => path.endsWith(ending),
    )
  )
    return json([{ id: sensitive, name: sensitive, hostname: sensitive }], {
      result_info: { total_count: 1 },
    });
  throw new Error(sensitive);
}
test('diagnostic uses only fixed-host GET endpoints and reports counts without private response data', async () => {
  const calls = [];
  const report = await main([], env(), {
    fetcher: async (url, options) => {
      calls.push({ url, options });
      return fixture(url);
    },
  });
  assert.equal(report.exit_code, 0);
  assert.equal(report.credential_verification, 'active');
  assert.equal(report.deployment_ready, false);
  assert.equal(report.write_capabilities, 'unverified');
  assert.equal(report.verified_token_id_sha256, createHash('sha256').update(tokenId).digest('hex'));
  assert.equal(report.admin_zone_plan_category, 'unknown');
  assert.equal(report.self_policy.available, true);
  assert.equal(report.self_policy.effective_write_capability, 'unverified');
  assert.equal(report.checks.length, 23);
  assert.equal(report.counts.zone_ruleset_count, 3);
  assert.equal(report.counts.zone_entrypoint_count, 1);
  assert.deepEqual(
    report.checks
      .filter((c) => c.ruleset_kind)
      .map((c) => ({ kind: c.ruleset_kind, phase: c.ruleset_phase })),
    [{ kind: 'zone', phase: 'http_request_firewall_custom' }],
  );
  assert.equal(report.counts.sampled_kv_key_count, 10);
  assert.ok(report.checks.every((c) => ['active', 'read_success'].includes(c.result)));
  assert.ok(calls.every((c) => new URL(c.url).hostname === 'api.cloudflare.com'));
  assert.ok(
    calls.every(
      (c) =>
        c.options.method === 'GET' &&
        c.options.body === undefined &&
        c.options.redirect === 'error',
    ),
  );
  assert.equal(calls.length, 23);
  assert.ok(
    !calls.some((c) => zoneCatalog.slice(0, 2).some((r) => c.url.includes(`/rulesets/${r.id}`))),
  );
  const keyRead = calls.find((c) => new URL(c.url).pathname.endsWith('/keys'));
  assert.equal(new URL(keyRead.url).search, '?limit=10');
  assert.ok(
    calls.every(
      (c) =>
        !c.url.includes('/values/') && !c.url.includes('/query') && !c.url.includes('/user/tokens'),
    ),
  );
  assert.doesNotMatch(
    JSON.stringify(report),
    /private-business|\/accounts\/|namespace_id|\.workers\.dev|permission_groups|owner_id|https?:/,
  );
});
test('verify 403 remains unverified, skips own policy and independently reports other endpoint failures without retries', async () => {
  const calls = [];
  const report = await main([], env(), {
    fetcher: async (url, options) => {
      calls.push({ url, options });
      const path = new URL(url).pathname;
      if (path.endsWith('/tokens/verify') || path.endsWith('/bot_management')) return denial();
      if (path.endsWith('/settings') && !path.includes('/workers/scripts/'))
        throw new Error(sensitive);
      return fixture(url);
    },
  });
  assert.equal(report.exit_code, 2);
  assert.equal(report.credential_verification, 'unverified');
  assert.equal(report.verified_token_id_sha256, null);
  assert.equal(report.deployment_ready, false);
  assert.equal(
    report.checks.find((c) => c.check === 'account-token-verify').endpoint_category,
    'ACCOUNT_TOKEN_VERIFY',
  );
  assert.equal(report.checks.find((c) => c.check === 'self-token-policy').result, 'unverified');
  assert.equal(
    report.checks.find((c) => c.check === 'admin-zone-bot-management').code,
    'PERMISSION_DENIED',
  );
  assert.equal(
    report.checks.find((c) => c.check === 'admin-zone-settings').code,
    'NETWORK_OR_REDIRECT_BLOCKED',
  );
  assert.equal(
    report.checks.find((c) => c.check === 'legacy-kv-key-structure').result,
    'read_success',
  );
  assert.ok(!calls.some((c) => new URL(c.url).pathname.endsWith(`/tokens/${tokenId}`)));
  assert.equal(calls.filter((c) => c.url.endsWith('/tokens/verify')).length, 1);
  assert.equal(calls.length, 22);
  assert.ok(calls.every((c) => c.options.method === 'GET'));
  assert.doesNotMatch(JSON.stringify(report), /private-business|https?:|\/accounts\/|\/user\//);
});
test('new-resource absence and optional policy refusal do not fail necessary reads or qualify writes', async () => {
  const report = await main([], env(), {
    fetcher: async (url) => {
      const path = new URL(url).pathname.slice('/client/v4'.length);
      if (path === `${ACCOUNT}/tokens/${tokenId}`) return denial();
      if (path === `${ACCOUNT}/d1/database`) return json([], { result_info: { total_count: 0 } });
      if (path === `${ACCOUNT}/r2/buckets`) return json({ buckets: [] });
      if (path === objectPath(OWNER_KEY))
        return new Response(
          JSON.stringify({ success: false, errors: [{ code: 10000, message: sensitive }] }),
          { status: 404 },
        );
      return fixture(url);
    },
  });
  assert.equal(report.exit_code, 0);
  assert.equal(report.credential_verification, 'active');
  assert.equal(report.write_capabilities, 'unverified');
  assert.equal(report.counts.matching_d1_count, 0);
  assert.equal(report.counts.matching_r2_count, 0);
  assert.equal(
    report.checks.find((c) => c.check === 'self-token-policy').result,
    'optional_unverified',
  );
  assert.equal(report.checks.find((c) => c.check === 'self-token-policy').optional, true);
  assert.equal(report.self_policy.available, false);
  for (const label of ['new-d1-catalog', 'new-r2-catalog', 'new-r2-ownership-manifest'])
    assert.equal(report.checks.find((c) => c.check === label).result, 'absence');
  assert.equal(report.checks.find((c) => c.check === 'new-r2-ownership-manifest').http_status, 404);
  assert.doesNotMatch(JSON.stringify(report), /private-business|owner_id|permission_groups/);
});

test('visible self-policy distinguishes fixed Zone Custom Errors from Custom Pages and conditional deny', async () => {
  const fixed = `com.cloudflare.api.account.zone.${EXPECTED.CF_ZONE_ID_LILY_LAT}`;
  const foreign = `com.cloudflare.api.account.zone.${'f'.repeat(32)}`;
  for (const [resources, expectedAllow] of [
    [{ [fixed]: '*' }, true],
    [{ [foreign]: '*' }, false],
  ]) {
    const report = await main([], env(), {
      fetcher: async (url) => {
        if (new URL(url).pathname.endsWith(`/tokens/${tokenId}`))
          return json({
            name: 'github-shortlink-deploy',
            policies: [
              { effect: 'allow', permission_groups: [{ name: 'Custom Errors Write' }], resources },
              { effect: 'allow', permission_groups: [{ name: 'Custom Pages Write' }], resources },
              {
                effect: 'deny',
                permission_groups: [{ name: 'Custom Errors Write' }],
                resources: { [fixed]: '*' },
                condition: { request_ip: { in: [sensitive] } },
              },
            ],
          });
        return fixture(url);
      },
    });
    assert.equal(report.exit_code, 0);
    assert.equal(report.self_policy.name_matches_expected, true);
    assert.equal(report.self_policy.custom_errors_write_allow_for_fixed_zone, expectedAllow);
    assert.equal(report.self_policy.custom_errors_write_matching_deny, true);
    assert.equal(report.self_policy.custom_pages_write_group_present, true);
    assert.equal(report.self_policy.conditional_policy_present, true);
    assert.equal(report.write_capabilities, 'unverified');
    assert.doesNotMatch(
      JSON.stringify(report),
      /private-business|permission_groups|request_ip|\.zone\./,
    );
    assert.ok(!JSON.stringify(report).includes(tokenId));
  }
});

test('standard paid, free and unknown Zone plans remain diagnostic context and never prove write permission', async () => {
  for (const [plan, expected] of [
    [{ name: 'Free Website', legacy_id: 'free' }, 'free'],
    [{ name: 'Pro' }, 'pro'],
    [{ name: 'Business Plan' }, 'business'],
    [{ name: 'Enterprise' }, 'enterprise'],
    [{ name: sensitive }, 'unknown'],
  ]) {
    const report = await main([], env(), {
      fetcher: async (url) =>
        new URL(url).pathname === `/client/v4${ADMIN_ZONE}`
          ? json({ name: 'lily.lat', account: { id: EXPECTED.CLOUDFLARE_ACCOUNT_ID }, plan })
          : fixture(url),
    });
    assert.equal(report.exit_code, 0);
    assert.equal(report.admin_zone_plan_category, expected);
    assert.equal(report.deployment_ready, false);
    assert.equal(report.write_capabilities, 'unverified');
    assert.doesNotMatch(JSON.stringify(report), /private-business/);
  }
});

test('policy diagnostics recognize fixed-account nested Zone grants and Edit aliases without treating account-only or foreign grants as Zone access', async () => {
  const account = `com.cloudflare.api.account.${EXPECTED.CLOUDFLARE_ACCOUNT_ID}`;
  for (const [resources, expected] of [
    [{ [account]: { 'com.cloudflare.api.account.zone.*': '*' } }, true],
    [
      { [account]: { [`com.cloudflare.api.account.zone.${EXPECTED.CF_ZONE_ID_LILY_LAT}`]: '*' } },
      true,
    ],
    [{ [account]: '*' }, false],
    [
      {
        [`com.cloudflare.api.account.${'f'.repeat(32)}`]: {
          'com.cloudflare.api.account.zone.*': '*',
        },
      },
      false,
    ],
  ]) {
    const report = await main([], env(), {
      fetcher: async (url) =>
        new URL(url).pathname.endsWith(`/tokens/${tokenId}`)
          ? json({
              policies: [
                {
                  effect: 'allow',
                  permission_groups: [
                    { name: 'Custom Error Rules Edit' },
                    { name: 'Custom Pages Edit' },
                  ],
                  resources,
                },
                {
                  effect: 'deny',
                  permission_groups: [{ name: 'Custom Error Rules Edit' }],
                  resources,
                },
              ],
            })
          : fixture(url),
    });
    assert.equal(report.exit_code, 0);
    assert.equal(report.self_policy.custom_errors_write_allow_for_fixed_zone, expected);
    assert.equal(report.self_policy.custom_errors_write_matching_deny, expected);
    assert.equal(report.self_policy.custom_pages_write_group_present, true);
    assert.equal(report.self_policy.effective_write_capability, 'unverified');
    assert.doesNotMatch(
      JSON.stringify(report),
      /permission_groups|com\.cloudflare|private-business/,
    );
  }
});

test('optional policy unavailability does not conceal a required Zone permission failure', async () => {
  const report = await main([], env(), {
    fetcher: async (url) => {
      const path = new URL(url).pathname;
      if (path.endsWith(`/tokens/${tokenId}`) || path === `/client/v4${ADMIN_ZONE}`)
        return denial();
      return fixture(url);
    },
  });
  assert.equal(report.exit_code, 2);
  assert.equal(
    report.checks.find((c) => c.check === 'self-token-policy').result,
    'optional_unverified',
  );
  assert.equal(report.checks.find((c) => c.check === 'admin-zone-account').result, 'failed');
  assert.equal(report.write_capabilities, 'unverified');
});
test('KV key diagnostics cap the sample at ten and do not retry or print unexpected key data', async () => {
  let keyRequests = 0;
  const report = await main([], env(), {
    fetcher: async (url) => {
      if (new URL(url).pathname.endsWith('/keys')) {
        keyRequests++;
        assert.equal(new URL(url).searchParams.get('limit'), '10');
        return json(Array.from({ length: 11 }, (_, index) => ({ name: `${sensitive}-${index}` })));
      }
      return fixture(url);
    },
  });
  assert.equal(report.exit_code, 2);
  assert.equal(
    report.checks.find((c) => c.check === 'legacy-kv-key-structure').code,
    'KV_KEY_STRUCTURE_INVALID',
  );
  assert.equal(keyRequests, 1);
  assert.equal(report.counts.sampled_kv_key_count, undefined);
  assert.doesNotMatch(JSON.stringify(report), /private-business/);
});
test('diagnostic reports actual entrypoint detail refusals by fixed phase and continues independent GETs', async () => {
  const extra = { id: '5'.repeat(32), kind: 'zone', phase: 'http_request_dynamic_redirect' };
  const calls = [];
  const report = await main([], env(), {
    fetcher: async (url, options) => {
      calls.push({ url, options });
      const path = new URL(url).pathname.slice('/client/v4'.length);
      if (path === `${ADMIN_ZONE}/rulesets`)
        return json([...zoneCatalog, extra], { result_info: { total_count: 4 } });
      if (path === `${ADMIN_ZONE}/rulesets/${extra.id}`) return denial();
      return fixture(url);
    },
  });
  const failed = report.checks.find(
    (c) => c.check === 'admin-zone-ruleset-http_request_dynamic_redirect',
  );
  assert.equal(report.exit_code, 2);
  assert.equal(report.deployment_ready, false);
  assert.equal(report.counts.zone_entrypoint_count, 2);
  assert.equal(failed.code, 'RULESET_DETAIL_ZONE_HTTP_REQUEST_DYNAMIC_REDIRECT_PERMISSION_DENIED');
  assert.equal(failed.ruleset_kind, 'zone');
  assert.equal(failed.ruleset_phase, 'http_request_dynamic_redirect');
  assert.equal(failed.http_status, 403);
  assert.equal(failed.endpoint_category, 'ZONE_RULESETS');
  assert.equal(failed.request_method, 'GET');
  assert.equal(
    report.checks.find((c) => c.check === 'legacy-kv-key-structure').result,
    'read_success',
  );
  assert.equal(calls.filter((c) => c.url.includes(`/rulesets/${extra.id}`)).length, 1);
  assert.ok(calls.every((c) => c.options.method === 'GET' && !c.options.body));
  assert.doesNotMatch(JSON.stringify(report), /private-business|555555555|\/zones\//);
});
test('diagnostic rejects untrusted metadata before constructing detail URLs or output labels', async () => {
  for (const change of [{ id: sensitive }, { kind: sensitive }, { phase: sensitive }]) {
    const calls = [];
    const report = await main([], env(), {
      fetcher: async (url) => {
        calls.push(url);
        if (new URL(url).pathname === `/client/v4${ADMIN_ZONE}/rulesets`)
          return json([{ ...zoneCatalog[2], ...change }]);
        return fixture(url);
      },
    });
    assert.equal(
      report.checks.find((c) => c.check === 'admin-zone-rulesets').code,
      'RULESET_CATALOG_INVALID',
    );
    assert.equal(report.counts.zone_entrypoint_count, undefined);
    assert.ok(!calls.some((url) => url.includes(`/rulesets/${zoneCatalog[2].id}`)));
    assert.doesNotMatch(JSON.stringify(report), /private-business/);
  }
});
test('diagnostic rejects successful detail responses with mismatching metadata and exposes no raw data', async () => {
  const report = await main([], env(), {
    fetcher: async (url) => {
      if (new URL(url).pathname === `/client/v4${ADMIN_ZONE}/rulesets/${zoneCatalog[2].id}`)
        return json({ ...zoneCatalog[2], phase: sensitive, rules: [], private: sensitive });
      return fixture(url);
    },
  });
  const failed = report.checks.find((c) => c.ruleset_kind === 'zone');
  assert.equal(
    failed.code,
    'RULESET_DETAIL_ZONE_HTTP_REQUEST_FIREWALL_CUSTOM_RULESET_DETAIL_METADATA_MISMATCH',
  );
  assert.equal(failed.ruleset_phase, 'http_request_firewall_custom');
  assert.equal(failed.endpoint_category, 'ZONE_RULESETS');
  assert.equal(report.exit_code, 2);
  assert.doesNotMatch(JSON.stringify(report), /private-business/);
});
test('diagnostic refuses non-main, automatic events, wrong fixed variables or arbitrary arguments before requests', async () => {
  let calls = 0;
  const options = {
    fetcher: async () => {
      calls++;
      return json({});
    },
  };
  for (const changes of [
    { GITHUB_EVENT_NAME: 'push' },
    { GITHUB_REF: 'refs/heads/codex/task' },
    { GITHUB_REPOSITORY: 'other/repo' },
    { PUBLIC_HOSTNAME: 'gfw.mom' },
    { CONFIRM_TARGET: 'deploy' },
    { CLOUDFLARE_API_TOKEN: '' },
  ])
    await assert.rejects(main([], { ...env(), ...changes }, options));
  await assert.rejects(main(['--endpoint'], env(), options), {
    code: 'DIAGNOSTIC_ARGUMENTS_FORBIDDEN',
  });
  assert.equal(calls, 0);
});
test('workflow is dispatch only, pinned, main guarded, and exposes only the deployment Secret to its last step', () => {
  const yaml = readFileSync('.github/workflows/credential-diagnostic.yml', 'utf8');
  assert.match(yaml, /on:\n  workflow_dispatch:/);
  assert.doesNotMatch(yaml, /\n  (push|schedule|pull_request|workflow_call|workflow_run):/);
  assert.match(yaml, /permissions:\n  contents: read/);
  assert.match(yaml, /if: github\.ref == 'refs\/heads\/main'/);
  assert.match(yaml, /fetch-depth: 0/);
  assert.match(yaml, /actions\/checkout@[a-f\d]{40}/);
  assert.match(yaml, /actions\/setup-node@[a-f\d]{40}/);
  assert.match(yaml, /run: npm ci\n      - run: npm run check/);
  assert.match(yaml, /node scripts\/credential-diagnostic\.mjs\s*$/);
  assert.equal((yaml.match(/secrets\./g) || []).length, 1);
  assert.doesNotMatch(yaml, /TURNSTILE_SECRET_KEY|wrangler|upload-artifact|gh workflow run/);
  assert.doesNotMatch(
    yaml.split('- name: Read fixed deployment credential diagnostics')[0],
    /secrets\./,
  );
  for (const name of Object.keys(EXPECTED)) assert.ok(yaml.includes(`vars.${name}`));
  assert.ok(yaml.includes(CONFIRMATION));
});
