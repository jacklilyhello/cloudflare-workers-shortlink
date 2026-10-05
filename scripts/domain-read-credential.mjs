import { pathToFileURL } from 'node:url';
import {
  ACCOUNT,
  EXPECTED,
  DeliveryError,
  ensure,
  createCFClient,
  requireAction,
  safeError,
} from './cf-client.mjs';
import { qualifyPolicy } from './qualify-readonly.mjs';
import { readManifest } from './deploy-resources.mjs';

const ALLOWED_PERMISSIONS = new Set([
  'Workers Scripts Read',
  'Account API Tokens Read',
  'API Tokens Read',
  'Analytics Read',
  'Account Analytics Read',
]);
export function domainReadPolicyQualified(policy) {
  return domainReadPolicyDiagnostics(policy).qualified;
}
export function domainReadPolicyDiagnostics(policy) {
  const policies = Array.isArray(policy?.policies) ? policy.policies : [];
  const allowed = policies.filter((p) => p?.effect === 'allow');
  const validShape =
    policies.length > 0 &&
    policies.every(
      (p) =>
        p &&
        ['allow', 'deny'].includes(p.effect) &&
        Array.isArray(p.permission_groups) &&
        p.permission_groups.every((g) => g && typeof g === 'object' && !Array.isArray(g)) &&
        p.resources &&
        typeof p.resources === 'object' &&
        !Array.isArray(p.resources),
    );
  if (!validShape) return { qualified: false, policy_shape_valid: false };
  const qualified = qualifyPolicy({ ...policy, name: 'shortlink readonly domain verification' });
  const permissions = allowed.flatMap((p) => p.permission_groups.map((g) => g.name));
  const resources = allowed.flatMap((p) => Object.entries(p.resources));
  const accountKey = `com.cloudflare.api.account.${EXPECTED.CLOUDFLARE_ACCOUNT_ID}`;
  const zoneKeys = new Set([
    `com.cloudflare.api.account.zone.${EXPECTED.CF_ZONE_ID_GFW_MOM}`,
    `com.cloudflare.api.account.zone.${EXPECTED.CF_ZONE_ID_LILY_LAT}`,
  ]);
  const workersRead = permissions.includes('Workers Scripts Read');
  const groupsAllowed = permissions.every((name) => ALLOWED_PERMISSIONS.has(name));
  const proven =
    qualified.read_only_permissions &&
    qualified.fixed_project_scope &&
    workersRead &&
    groupsAllowed;
  // Only fixed booleans and bounded counts leave this process. No policy names,
  // permission labels, resource keys/values, conditions or credential IDs are serialized.
  const count = (items) => Math.min(items.length, 1000);
  return {
    qualified: proven,
    policy_shape_valid: true,
    read_only_permissions: qualified.read_only_permissions,
    fixed_project_scope: qualified.fixed_project_scope,
    workers_scripts_read_present: workersRead,
    only_approved_permission_groups: groupsAllowed,
    allow_policy_count: count(allowed),
    allow_permission_count: count(permissions),
    missing_permission_name_count: count(permissions.filter((name) => typeof name !== 'string')),
    non_read_permission_name_count: count(
      permissions.filter((name) => typeof name !== 'string' || !/\bread\b/i.test(name)),
    ),
    write_like_permission_name_count: count(
      permissions.filter(
        (name) =>
          typeof name === 'string' &&
          /\b(write|edit|delete|purge|revoke|manage|create)\b/i.test(name),
      ),
    ),
    unapproved_permission_count: count(
      permissions.filter((name) => !ALLOWED_PERMISSIONS.has(name)),
    ),
    fixed_account_scope_present: resources.some(([key]) => key === accountKey),
    fixed_zone_scope_count: count(resources.filter(([key]) => zoneKeys.has(key))),
    unexpected_resource_key_count: count(
      resources.filter(([key]) => key !== accountKey && !zoneKeys.has(key)),
    ),
    non_wildcard_resource_value_count: count(resources.filter(([, value]) => value !== '*')),
    nested_resource_value_count: count(
      resources.filter(([, value]) => value && typeof value === 'object' && !Array.isArray(value)),
    ),
    global_account_resource_key_count: count(
      resources.filter(([key]) => key === 'com.cloudflare.api.account.*'),
    ),
    global_zone_resource_key_count: count(
      resources.filter(([key]) => key === 'com.cloudflare.api.account.zone.*'),
    ),
    empty_allow_resource_policy_count: count(
      allowed.filter((p) => Object.keys(p.resources).length === 0),
    ),
  };
}
class DomainReadPolicyError extends DeliveryError {
  constructor(diagnostics) {
    super('DOMAIN_READ_ONLY_POLICY_UNPROVEN');
    this.policyDiagnostics = diagnostics;
  }
}
export async function qualifyDomainReadCredential(token, manifest, fetcher = fetch) {
  ensure(
    typeof token === 'string' && token.length > 0 && token.length <= 4096 && !/\s/.test(token),
    'DOMAIN_READ_CREDENTIAL_INVALID',
  );
  const client = createCFClient(token, { fetcher, allowWrites: false });
  const verified = (await client.request(`${ACCOUNT}/tokens/verify`)).result;
  ensure(
    verified?.status === 'active' && /^[a-f\d]{32}$/i.test(verified.id || ''),
    'DOMAIN_READ_TOKEN_INACTIVE',
  );
  const policy = (await client.request(`${ACCOUNT}/tokens/${verified.id}`)).result;
  const diagnostics = domainReadPolicyDiagnostics(policy);
  if (!diagnostics.qualified) throw new DomainReadPolicyError(diagnostics);
  const worker = (
    await client.request(`${ACCOUNT}/workers/scripts/${EXPECTED.WORKER_NAME}/settings`)
  ).result;
  const binding = (name) => (worker?.bindings || []).filter((b) => b.name === name);
  ensure(
    binding('RESOURCE_OWNER_ID').length === 1 &&
      binding('RESOURCE_OWNER_ID')[0].type === 'plain_text' &&
      binding('RESOURCE_OWNER_ID')[0].text === manifest.owner_id &&
      binding('DB').length === 1 &&
      (binding('DB')[0].id || binding('DB')[0].database_id) === manifest.d1.id &&
      binding('BACKUPS').length === 1 &&
      binding('BACKUPS')[0].bucket_name === manifest.bucket,
    'DOMAIN_READ_WORKER_OWNER_UNPROVEN',
  );
  const payload = await client.request(
    `${ACCOUNT}/workers/domains?hostname=${EXPECTED.PUBLIC_HOSTNAME}`,
  );
  ensure(
    Array.isArray(payload.result) &&
      payload.result.length === 1 &&
      payload.result[0].hostname === EXPECTED.PUBLIC_HOSTNAME &&
      payload.result[0].service === EXPECTED.WORKER_NAME &&
      payload.result[0].zone_id === EXPECTED.CF_ZONE_ID_GFW_MOM &&
      ['production', undefined].includes(payload.result[0].environment) &&
      payload.result[0].id === manifest.domains[EXPECTED.PUBLIC_HOSTNAME].id,
    'DOMAIN_READ_FIXED_BINDING_UNPROVEN',
  );
  return {
    result: 'QUALIFIED',
    fixed_worker_owner_verified: true,
    fixed_custom_domain_read_verified: true,
    readonly_policy_verified: true,
  };
}
export async function selectDomainReadCredential(env, manifest, fetcher = fetch) {
  const checks = [];
  for (const source of ['CF_DOMAIN_READ_TOKEN', 'CF_ANALYTICS_READ_TOKEN']) {
    const token = env[source];
    if (!token) {
      checks.push({ source, result: 'NOT_CONFIGURED' });
      continue;
    }
    try {
      ensure(token !== env.CLOUDFLARE_API_TOKEN, 'DEPLOY_TOKEN_MUST_NOT_ENTER_WORKER');
      const result = await qualifyDomainReadCredential(token, manifest, fetcher);
      return { token, source, checks: [...checks, { source, ...result }] };
    } catch (error) {
      checks.push({
        source,
        result: 'NOT_QUALIFIED',
        ...safeError(error),
        ...(error instanceof DomainReadPolicyError
          ? {
              token_active_verified: true,
              own_policy_read_verified: true,
              policy_checks: error.policyDiagnostics,
            }
          : {}),
      });
    }
  }
  return { token: null, source: null, checks };
}
export async function main(env = process.env, fetcher = fetch) {
  requireAction(env, 'qualify shortlink-new domain reader read only');
  const client = createCFClient(env.CLOUDFLARE_API_TOKEN, { fetcher, allowWrites: false });
  const manifest = await readManifest(client);
  ensure(
    manifest?.d1 && manifest.domains?.[EXPECTED.PUBLIC_HOSTNAME],
    'DOMAIN_READER_FIXED_RESOURCES_UNPROVEN',
  );
  const selected = await selectDomainReadCredential(env, manifest, fetcher);
  // Never serialize the selected token. Diagnostics have no Worker-secret or CF-resource writes.
  return {
    result: selected.token ? 'QUALIFIED' : 'PENDING',
    checks: selected.checks,
    worker_secret_modified: false,
  };
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const result = await main();
    console.log(JSON.stringify(result));
    process.exitCode = result.result === 'QUALIFIED' ? 0 : 2;
  } catch (e) {
    console.error(JSON.stringify(safeError(e)));
    process.exitCode = 2;
  }
}
