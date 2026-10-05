import test from 'node:test';
import assert from 'node:assert/strict';
import {
  domainReadPolicyDiagnostics,
  domainReadPolicyQualified,
  selectDomainReadCredential,
} from '../scripts/domain-read-credential.mjs';
import { EXPECTED } from '../scripts/cf-client.mjs';

const accountKey = `com.cloudflare.api.account.${EXPECTED.CLOUDFLARE_ACCOUNT_ID}`;
const allow = {
  effect: 'allow',
  permission_groups: [{ name: 'Workers Scripts Read' }, { name: 'Account API Tokens Read' }],
  resources: { [accountKey]: '*' },
};
test('domain reader policy diagnostics distinguish gate failures without exposing policy data', () => {
  assert.equal(domainReadPolicyQualified({ policies: [allow] }), true);
  for (const [permission, readOnly, workerRead] of [
    ['Workers Scripts Write', false, false],
    ['Account API Tokens Read', true, false],
    ['Unapproved Service Read', true, false],
  ]) {
    const checks = domainReadPolicyDiagnostics({
      name: 'PRIVATE_TOKEN_NAME',
      condition: { request_ip: { in: ['PRIVATE_IP'] } },
      policies: [{ ...allow, permission_groups: [{ name: permission }] }],
    });
    assert.equal(checks.qualified, false);
    assert.equal(checks.read_only_permissions, readOnly);
    assert.equal(checks.workers_scripts_read_present, workerRead);
    assert.doesNotMatch(JSON.stringify(checks), /PRIVATE|Workers Scripts|Unapproved Service/);
    assert.ok(
      Object.values(checks).every((value) => typeof value === 'boolean' || Number.isInteger(value)),
    );
  }
  const nested = domainReadPolicyDiagnostics({
    policies: [
      { ...allow, resources: { [accountKey]: { 'com.cloudflare.api.account.zone.*': '*' } } },
    ],
  });
  assert.equal(nested.fixed_project_scope, false);
  assert.equal(nested.fixed_account_scope_present, true);
  assert.equal(nested.nested_resource_value_count, 1);
  assert.equal(nested.qualified, false);
  const foreign = domainReadPolicyDiagnostics({
    policies: [
      { ...allow, resources: { 'com.cloudflare.api.account.PRIVATE_OTHER_ACCOUNT': '*' } },
    ],
  });
  assert.equal(foreign.unexpected_resource_key_count, 1);
  assert.equal(foreign.fixed_project_scope, false);
  assert.doesNotMatch(JSON.stringify(foreign), /PRIVATE_OTHER_ACCOUNT/);
  for (const policy of [null, {}, { policies: [{}] }, { policies: [null] }])
    assert.equal(domainReadPolicyQualified(policy), false);
});
test('unqualified domain reader reports safe subchecks and stops before resource reads or writes', async () => {
  const token = 'PRIVATE_DOMAIN_CREDENTIAL';
  const calls = [];
  const fetcher = async (url, options) => {
    assert.equal(options.method, 'GET');
    assert.equal(options.redirect, 'error');
    calls.push(new URL(url).pathname);
    const result = url.endsWith('/tokens/verify')
      ? { status: 'active', id: 'f'.repeat(32) }
      : {
          name: 'PRIVATE_POLICY_NAME',
          policies: [
            { ...allow, resources: { 'com.cloudflare.api.account.PRIVATE_FOREIGN': '*' } },
          ],
        };
    return new Response(JSON.stringify({ success: true, result }), {
      headers: { 'Content-Type': 'application/json' },
    });
  };
  const selected = await selectDomainReadCredential(
    { CLOUDFLARE_API_TOKEN: 'PRIVATE_DEPLOY_CREDENTIAL', CF_DOMAIN_READ_TOKEN: token },
    {},
    fetcher,
  );
  assert.equal(selected.token, null);
  assert.equal(calls.length, 2);
  assert.equal(selected.checks[0].code, 'DOMAIN_READ_ONLY_POLICY_UNPROVEN');
  assert.equal(selected.checks[0].token_active_verified, true);
  assert.equal(selected.checks[0].own_policy_read_verified, true);
  assert.equal(selected.checks[0].policy_checks.unexpected_resource_key_count, 1);
  assert.doesNotMatch(JSON.stringify(selected), /PRIVATE|ffffffff/);
});
