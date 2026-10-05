#!/usr/bin/env node
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import {
  ACCOUNT,
  PUBLIC_ZONE,
  ADMIN_ZONE,
  EXPECTED,
  BUCKET,
  DATABASE,
  OWNER_KEY,
  DeliveryError,
  ensure,
  createCFClient,
  listAll,
  requireAction,
  safeError,
} from './cf-client.mjs';
import { objectPath, validateManifest } from './deploy-resources.mjs';
import { readZoneEntrypoint, rulesetContext, validateRulesetCatalog } from './ruleset-metadata.mjs';

export const CONFIRMATION = 'verify shortlink-new deployment credential read only';
const COUNT_KEYS = new Set([
  'policy_allow_count',
  'policy_permission_group_count',
  'custom_domain_count',
  'identity_provider_count',
  'otp_provider_count',
  'access_application_count',
  'zone_setting_count',
  'zone_ruleset_count',
  'zone_entrypoint_count',
  'account_ruleset_count',
  'public_dns_count',
  'admin_dns_count',
  'public_route_count',
  'admin_route_count',
  'matching_d1_count',
  'matching_r2_count',
  'ownership_manifest_count',
  'sampled_kv_key_count',
]);
const array = (value) => {
  ensure(Array.isArray(value), 'DIAGNOSTIC_RESPONSE_INVALID');
  return value;
};
function planCategory(plan) {
  const legacy = typeof plan?.legacy_id === 'string' ? plan.legacy_id.toLowerCase() : '';
  if (['free', 'pro', 'business', 'enterprise'].includes(legacy)) return legacy;
  const name = typeof plan?.name === 'string' ? plan.name.toLowerCase() : '';
  for (const category of ['enterprise', 'business', 'pro', 'free'])
    if (new RegExp(`^${category}(?: plan| website)?$`).test(name)) return category;
  return 'unknown';
}
function policySummary(token, policies) {
  const fixedZone = `com.cloudflare.api.account.zone.${EXPECTED.CF_ZONE_ID_LILY_LAT}`;
  const zoneKeys = [fixedZone, 'com.cloudflare.api.account.zone.*'];
  const includesZone = (policy) => {
    const nested =
      policy.resources?.[`com.cloudflare.api.account.${EXPECTED.CLOUDFLARE_ACCOUNT_ID}`];
    return zoneKeys.some((key) => policy.resources?.[key] === '*' || nested?.[key] === '*');
  };
  const customErrors = new Set(['Custom Errors Write', 'Custom Error Rules Edit']);
  const customPages = new Set(['Custom Pages Write', 'Custom Pages Edit']);
  const hasGroup = (policy, names) =>
    array(policy.permission_groups).some((group) => names.has(group?.name));
  return {
    available: true,
    name_matches_expected:
      typeof token.name === 'string' ? token.name === 'github-shortlink-deploy' : null,
    custom_errors_write_allow_for_fixed_zone: policies.some(
      (policy) =>
        policy.effect === 'allow' && hasGroup(policy, customErrors) && includesZone(policy),
    ),
    custom_errors_write_matching_deny: policies.some(
      (policy) =>
        policy.effect === 'deny' && hasGroup(policy, customErrors) && includesZone(policy),
    ),
    custom_pages_write_group_present: policies.some((policy) => hasGroup(policy, customPages)),
    conditional_policy_present: policies.some(
      (policy) => policy.condition !== undefined || policy.conditions !== undefined,
    ),
    effective_write_capability: 'unverified',
  };
}
const failure = (check, error) => {
  const safe = safeError(error);
  return {
    check,
    result:
      safe.code === 'NOT_FOUND' && check === 'new-r2-ownership-manifest' ? 'absence' : 'failed',
    code: safe.code,
    http_status: safe.http_status,
    cf_error_codes: safe.cf_error_codes,
    endpoint_category: safe.endpoint_category,
    request_method: ['GET', 'POST', 'PUT', 'PATCH'].includes(safe.request_method)
      ? safe.request_method
      : null,
    media_type: safe.media_type,
    body_shape: safe.body_shape,
    numeric_code_count: safe.numeric_code_count,
    error_count: safe.error_count,
    error_code_shape: safe.error_code_shape,
    error_message_hint: safe.error_message_hint,
    cf_mitigated: safe.cf_mitigated,
  };
};
export async function runCredentialDiagnostic(client) {
  const checks = [];
  const counts = {};
  let verifiedId = null;
  let selfPolicy = { available: false, effective_write_capability: 'unverified' };
  let adminPlan = 'unknown';
  const check = async (label, inspect, context = {}) => {
    try {
      const outcome = (await inspect()) || {};
      for (const [key, value] of Object.entries(outcome.counts || {})) {
        ensure(
          COUNT_KEYS.has(key) && Number.isSafeInteger(value) && value >= 0,
          'DIAGNOSTIC_COUNT_INVALID',
        );
        counts[key] = value;
      }
      checks.push({
        check: label,
        ...context,
        result: outcome.result || 'read_success',
        code: null,
        http_status: null,
        cf_error_codes: [],
        endpoint_category: null,
        request_method: 'GET',
      });
    } catch (error) {
      const outcome = failure(label, error);
      checks.push({
        ...outcome,
        ...context,
        result: context.optional ? 'optional_unverified' : outcome.result,
      });
    }
  };
  const list = (path, options = {}) => listAll(client, path, { maxPages: 10, ...options });
  await check('account-token-verify', async () => {
    const p = await client.request(`${ACCOUNT}/tokens/verify`);
    ensure(
      p.result?.status === 'active' && /^[a-f\d]{32}$/i.test(p.result.id),
      'DIAGNOSTIC_TOKEN_NOT_ACTIVE',
    );
    verifiedId = p.result.id;
    return { result: 'active' };
  });
  if (verifiedId) {
    await check(
      'self-token-policy',
      async () => {
        const token = (await client.request(`${ACCOUNT}/tokens/${verifiedId}`)).result;
        const policies = array(token?.policies);
        const allow = policies.filter((p) => p.effect === 'allow');
        const groupCount = allow.reduce((n, p) => n + array(p.permission_groups).length, 0);
        selfPolicy = policySummary(token, policies);
        return {
          counts: {
            policy_allow_count: allow.length,
            policy_permission_group_count: groupCount,
          },
        };
      },
      { optional: true },
    );
  } else {
    checks.push({
      check: 'self-token-policy',
      result: 'unverified',
      code: 'ACCOUNT_VERIFICATION_REQUIRED',
      http_status: null,
      cf_error_codes: [],
      endpoint_category: 'ACCOUNT_TOKEN_POLICY',
      request_method: null,
    });
  }
  // Independent, fixed GET diagnostics remain useful when verification fails. They never authorize apply.
  for (const [label, zone, name] of [
    ['public-zone-account', PUBLIC_ZONE, 'gfw.mom'],
    ['admin-zone-account', ADMIN_ZONE, 'lily.lat'],
  ])
    await check(label, async () => {
      const p = await client.request(zone);
      ensure(
        p.result?.name === name && p.result.account?.id === EXPECTED.CLOUDFLARE_ACCOUNT_ID,
        'ZONE_ACCOUNT_MISMATCH',
      );
      if (zone === ADMIN_ZONE) adminPlan = planCategory(p.result.plan);
    });
  await check('legacy-worker-links-binding', async () => {
    const p = await client.request(
      `${ACCOUNT}/workers/scripts/${EXPECTED.LEGACY_WORKER_NAME}/settings`,
    );
    ensure(
      array(p.result?.bindings).some(
        (b) =>
          b.name === 'LINKS' &&
          b.type === 'kv_namespace' &&
          b.namespace_id === EXPECTED.LEGACY_KV_NAMESPACE_ID,
      ),
      'LEGACY_KV_BINDING_MISMATCH',
    );
  });
  await check('workers-subdomain', async () => {
    const p = await client.request(`${ACCOUNT}/workers/subdomain`);
    ensure(
      /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(p.result?.subdomain || ''),
      'WORKERS_SUBDOMAIN_INVALID',
    );
  });
  await check('workers-custom-domains', async () => ({
    counts: { custom_domain_count: (await list(`${ACCOUNT}/workers/domains`)).length },
  }));
  await check('access-organization', async () => {
    const p = await client.request(`${ACCOUNT}/access/organizations`);
    ensure(
      p.result?.auth_domain === EXPECTED.CF_ACCESS_TEAM_DOMAIN,
      'ACCESS_ORGANIZATION_MISMATCH',
    );
  });
  await check('access-identity-providers', async () => {
    const idps = await list(`${ACCOUNT}/access/identity_providers`);
    return {
      counts: {
        identity_provider_count: idps.length,
        otp_provider_count: idps.filter((p) => p.type === 'onetimepin').length,
      },
    };
  });
  await check('access-applications', async () => ({
    counts: { access_application_count: (await list(`${ACCOUNT}/access/apps`)).length },
  }));
  await check('admin-zone-bot-management', async () => {
    const p = await client.request(`${ADMIN_ZONE}/bot_management`);
    ensure(
      p.result && typeof p.result === 'object' && !Array.isArray(p.result),
      'DIAGNOSTIC_RESPONSE_INVALID',
    );
  });
  await check('admin-zone-settings', async () => ({
    counts: {
      zone_setting_count: array((await client.request(`${ADMIN_ZONE}/settings`)).result).length,
    },
  }));
  let zoneEntrypoints = null;
  await check('admin-zone-rulesets', async () => {
    const metadata = validateRulesetCatalog(await list(`${ADMIN_ZONE}/rulesets`));
    zoneEntrypoints = metadata.filter((r) => r.kind === 'zone');
    return {
      counts: {
        zone_ruleset_count: metadata.length,
        zone_entrypoint_count: zoneEntrypoints.length,
      },
    };
  });
  for (const r of zoneEntrypoints || [])
    await check(
      `admin-zone-ruleset-${r.phase}`,
      async () => {
        await readZoneEntrypoint(client, r);
      },
      rulesetContext(r),
    );
  await check('account-rulesets', async () => ({
    counts: {
      account_ruleset_count: validateRulesetCatalog(await list(`${ACCOUNT}/rulesets`)).length,
    },
  }));
  for (const [label, zone, host, prefix] of [
    ['public', PUBLIC_ZONE, EXPECTED.PUBLIC_HOSTNAME, 'public'],
    ['admin', ADMIN_ZONE, EXPECTED.ADMIN_HOSTNAME, 'admin'],
  ]) {
    await check(`${label}-dns`, async () => ({
      counts: { [`${prefix}_dns_count`]: (await list(`${zone}/dns_records?name=${host}`)).length },
    }));
    await check(`${label}-worker-routes`, async () => ({
      counts: { [`${prefix}_route_count`]: (await list(`${zone}/workers/routes`)).length },
    }));
  }
  await check('new-d1-catalog', async () => {
    const found = (await list(`${ACCOUNT}/d1/database?name=${DATABASE}`)).filter(
      (d) => d.name === DATABASE,
    );
    return {
      result: found.length ? 'read_success' : 'absence',
      counts: { matching_d1_count: found.length },
    };
  });
  await check('new-r2-catalog', async () => {
    const found = (
      await list(`${ACCOUNT}/r2/buckets?name_contains=${BUCKET}`, {
        select: (p) => p.result?.buckets,
      })
    ).filter((b) => b.name === BUCKET);
    return {
      result: found.length ? 'read_success' : 'absence',
      counts: { matching_r2_count: found.length },
    };
  });
  await check('new-r2-ownership-manifest', async () => {
    const raw = await client.request(objectPath(OWNER_KEY), { raw: true, maxBytes: 256 * 1024 });
    let manifest;
    try {
      manifest = JSON.parse(raw);
    } catch {
      throw new DeliveryError('OWNERSHIP_MANIFEST_INVALID');
    }
    validateManifest(manifest);
    return { counts: { ownership_manifest_count: 1 } };
  });
  await check('legacy-kv-key-structure', async () => {
    const p = await client.request(
      `${ACCOUNT}/storage/kv/namespaces/${EXPECTED.LEGACY_KV_NAMESPACE_ID}/keys?limit=10`,
    );
    const keys = array(p.result);
    ensure(
      keys.length <= 10 &&
        keys.every(
          (k) => typeof k.name === 'string' && (!k.metadata || typeof k.metadata === 'object'),
        ),
      'KV_KEY_STRUCTURE_INVALID',
    );
    return { counts: { sampled_kv_key_count: keys.length } };
  });
  return {
    credential_verification: verifiedId ? 'active' : 'unverified',
    verified_token_id_sha256: verifiedId
      ? createHash('sha256').update(verifiedId).digest('hex')
      : null,
    self_policy: selfPolicy,
    admin_zone_plan_category: adminPlan,
    deployment_ready: false,
    write_capabilities: 'unverified',
    checks,
    counts,
    exit_code: checks.every(
      (c) =>
        ['read_success', 'active', 'absence'].includes(c.result) ||
        (c.optional === true && c.result === 'optional_unverified'),
    )
      ? 0
      : 2,
  };
}
export async function main(args = process.argv.slice(2), env = process.env, { fetcher } = {}) {
  ensure(args.length === 0, 'DIAGNOSTIC_ARGUMENTS_FORBIDDEN');
  requireAction(env, CONFIRMATION);
  const client = createCFClient(env.CLOUDFLARE_API_TOKEN, fetcher ? { fetcher } : {});
  return runCredentialDiagnostic(client);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const report = await main();
    console.log(JSON.stringify(report));
    process.exitCode = report.exit_code;
  } catch (error) {
    console.error(JSON.stringify(failure('workflow-scope', error)));
    process.exitCode = 2;
  }
}
