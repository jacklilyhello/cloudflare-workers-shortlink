import { pathToFileURL } from 'node:url';
import {
  ACCOUNT,
  EXPECTED,
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
  const qualified = qualifyPolicy({ ...policy, name: 'shortlink readonly domain verification' });
  const permissions = (policy.policies || [])
    .filter((p) => p.effect === 'allow')
    .flatMap((p) => (p.permission_groups || []).map((g) => g.name));
  return (
    qualified.read_only_permissions &&
    qualified.fixed_project_scope &&
    permissions.includes('Workers Scripts Read') &&
    permissions.every((name) => ALLOWED_PERMISSIONS.has(name))
  );
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
  ensure(domainReadPolicyQualified(policy), 'DOMAIN_READ_ONLY_POLICY_UNPROVEN');
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
      checks.push({ source, result: 'NOT_QUALIFIED', ...safeError(error) });
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
