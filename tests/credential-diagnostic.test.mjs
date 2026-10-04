import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
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
  assert.equal(report.checks.length, 22);
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
  assert.equal(calls.length, 22);
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
  assert.equal(calls.length, 21);
  assert.ok(calls.every((c) => c.options.method === 'GET'));
  assert.doesNotMatch(JSON.stringify(report), /private-business|https?:|\/accounts\/|\/user\//);
});
test('new-resource absence and policy refusal are not read success or deployment credential qualification', async () => {
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
  assert.equal(report.exit_code, 2);
  assert.equal(report.credential_verification, 'active');
  assert.equal(report.write_capabilities, 'unverified');
  assert.equal(report.counts.matching_d1_count, 0);
  assert.equal(report.counts.matching_r2_count, 0);
  assert.equal(report.checks.find((c) => c.check === 'self-token-policy').result, 'failed');
  for (const label of ['new-d1-catalog', 'new-r2-catalog', 'new-r2-ownership-manifest'])
    assert.equal(report.checks.find((c) => c.check === label).result, 'absence');
  assert.equal(report.checks.find((c) => c.check === 'new-r2-ownership-manifest').http_status, 404);
  assert.doesNotMatch(JSON.stringify(report), /private-business|owner_id|permission_groups/);
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
