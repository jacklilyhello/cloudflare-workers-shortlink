#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync, statSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import {
  ACCOUNT,
  EXPECTED,
  BUCKET,
  DATABASE,
  ensure,
  createCFClient,
  requireAction,
  verifyAccount,
  safeError,
} from './cf-client.mjs';
import {
  prepareResources,
  inspectWorker,
  saveManifest,
  attachDomains,
  workerOwnerMatches,
  query,
} from './deploy-resources.mjs';
import { bootstrapSecurity, verifySecurity, inspectSecurity } from './security-bootstrap.mjs';
import { readManifest } from './deploy-resources.mjs';

export function deploymentConfiguration(manifest, workersHostname) {
  ensure(
    manifest?.d1 && /^[a-f\d]{64}$/i.test(manifest.security?.apps?.admin?.aud || ''),
    'DEPLOYMENT_BINDINGS_INCOMPLETE',
  );
  ensure(
    /^shortlink-new\.[a-z0-9-]+\.workers\.dev$/.test(workersHostname),
    'WORKERS_DEV_HOSTNAME_UNVERIFIED',
  );
  return {
    $schema: '../node_modules/wrangler/config-schema.json',
    name: EXPECTED.WORKER_NAME,
    account_id: EXPECTED.CLOUDFLARE_ACCOUNT_ID,
    main: '../src/index.ts',
    compatibility_date: '2026-07-02',
    workers_dev: true,
    preview_urls: false,
    assets: { directory: '../dist', binding: 'ASSETS', run_worker_first: true },
    d1_databases: [
      {
        binding: 'DB',
        database_name: DATABASE,
        database_id: manifest.d1.id,
        migrations_dir: '../migrations',
      },
    ],
    r2_buckets: [{ binding: 'BACKUPS', bucket_name: BUCKET }],
    vars: {
      APP_ENV: 'test',
      PUBLIC_HOSTNAME: EXPECTED.PUBLIC_HOSTNAME,
      ADMIN_HOSTNAME: EXPECTED.ADMIN_HOSTNAME,
      WORKERS_DEV_HOSTNAME: workersHostname,
      TURNSTILE_SITE_KEY: EXPECTED.TURNSTILE_SITE_KEY,
      CF_ACCESS_TEAM_DOMAIN: EXPECTED.CF_ACCESS_TEAM_DOMAIN,
      CF_ACCESS_AUD: manifest.security.apps.admin.aud,
      ADMIN_EMAILS: EXPECTED.ADMIN_EMAILS,
      RESOURCE_OWNER_ID: manifest.owner_id,
    },
    triggers: { crons: ['*/10 * * * *'] },
    // Persist no request/response data or Authorization headers in Workers logs.
    observability: { enabled: false },
  };
}
function wrangler(args, env) {
  // No OAuth/key fallback: only the Actions secret is supplied. Credentials never become CLI arguments.
  const safeEnv = { ...env, WRANGLER_SEND_METRICS: 'false', NO_COLOR: '1' };
  delete safeEnv.CLOUDFLARE_API_KEY;
  delete safeEnv.CLOUDFLARE_EMAIL;
  try {
    execFileSync('npx', ['--no-install', 'wrangler', ...args], {
      env: safeEnv,
      encoding: 'utf8',
      timeout: 240000,
      maxBuffer: 4 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch {
    ensure(false, 'WRANGLER_COMMAND_FAILED_RAW_LOG_WITHHELD');
  }
}
export async function main(args = process.argv.slice(2), env = process.env) {
  ensure(
    args.length === 1 && ['bootstrap', 'test', 'production'].includes(args[0]),
    'DEPLOY_MODE_INVALID',
  );
  const mode = args[0];
  requireAction(
    env,
    mode === 'bootstrap'
      ? 'initialize shortlink-new test only'
      : mode === 'production'
        ? 'release shortlink-new without production domain cutover'
        : 'deploy shortlink-new test only',
  );
  if (mode === 'production')
    ensure(
      env.PRODUCTION_RELEASE_AUTHORIZED === 'true',
      'PRODUCTION_SEPARATE_AUTHORIZATION_REQUIRED',
    );
  ensure(
    env.TURNSTILE_SECRET_KEY?.length > 0 && !/\s/.test(env.TURNSTILE_SECRET_KEY),
    'TURNSTILE_ACTION_SECRET_MISSING',
  );
  ensure(statSync('dist').isDirectory(), 'BUILT_UI_MISSING');
  const client = createCFClient(env.CLOUDFLARE_API_TOKEN, { allowWrites: true });
  const capability = await verifyAccount(client);
  if (mode === 'bootstrap') {
    // Inspect Access overlap and unsuppressible products before creating any new resources.
    const previous = await readManifest(client);
    await inspectSecurity(client, previous);
  }
  const manifest = await prepareResources(client, { bootstrap: mode === 'bootstrap' });
  if (mode === 'bootstrap') await bootstrapSecurity(client, manifest);
  const security = await verifySecurity(client, manifest, { production: mode === 'production' });
  const subdomain = (await client.request(`${ACCOUNT}/workers/subdomain`)).result.subdomain;
  ensure(/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(subdomain || ''), 'WORKERS_SUBDOMAIN_INVALID');
  const workersHostname = `${EXPECTED.WORKER_NAME}.${subdomain}.workers.dev`;
  const config = deploymentConfiguration(manifest, workersHostname);
  mkdirSync('.local', { recursive: true, mode: 0o700 });
  writeFileSync('.local/wrangler.deploy.json', JSON.stringify(config, null, 2) + '\n', {
    mode: 0o600,
  });
  // Wrangler applies a ledger of reviewed SQL migrations only to the independently owned DB.
  wrangler(
    ['d1', 'migrations', 'apply', DATABASE, '--remote', '--config', '.local/wrangler.deploy.json'],
    env,
  );
  // Never silently re-enable an administrator-disabled domain on ordinary deployments.
  await query(
    client,
    manifest.d1.id,
    'INSERT INTO domains (hostname,enabled,bound,created_at) VALUES (?,1,0,?) ON CONFLICT(hostname) DO NOTHING',
    [EXPECTED.PUBLIC_HOSTNAME, Date.now()],
  );
  await inspectWorker(client, manifest);
  manifest.journal.push({
    step: 'worker-upload',
    state: 'intent',
    sha: env.GITHUB_SHA,
    time: new Date().toISOString(),
  });
  await saveManifest(client, manifest);
  wrangler(['deploy', '--config', '.local/wrangler.deploy.json', '--keep-vars'], env);
  const settings = (
    await client.request(`${ACCOUNT}/workers/scripts/${EXPECTED.WORKER_NAME}/settings`)
  ).result;
  ensure(workerOwnerMatches(settings, manifest), 'DEPLOYED_WORKER_OWNER_MISMATCH');
  manifest.worker_created = true;
  manifest.workers_hostname = workersHostname;
  manifest.last_sha = env.GITHUB_SHA;
  await saveManifest(client, manifest);
  await client.request(`${ACCOUNT}/workers/scripts/${EXPECTED.WORKER_NAME}/secrets`, {
    method: 'PUT',
    json: { name: 'TURNSTILE_SECRET_KEY', type: 'secret_text', text: env.TURNSTILE_SECRET_KEY },
  });
  // Custom domains are attached by the guarded API, never by Wrangler's route auto-replacement.
  if (mode === 'bootstrap') await attachDomains(client, manifest);
  ensure(
    manifest.domains[EXPECTED.PUBLIC_HOSTNAME] && manifest.domains[EXPECTED.ADMIN_HOSTNAME],
    'CUSTOM_DOMAINS_INCOMPLETE',
  );
  if (mode === 'bootstrap') {
    // Binding becomes usable only after guarded Custom Domain/DNS readback; retain administrator enabled state.
    await query(client, manifest.d1.id, 'UPDATE domains SET bound=1 WHERE hostname=?', [
      EXPECTED.PUBLIC_HOSTNAME,
    ]);
  }
  manifest.journal.push({
    step: 'worker-upload',
    state: 'complete',
    sha: env.GITHUB_SHA,
    time: new Date().toISOString(),
  });
  await saveManifest(client, manifest);
  console.log(
    JSON.stringify({
      mode,
      worker: EXPECTED.WORKER_NAME,
      public: `https://${EXPECTED.PUBLIC_HOSTNAME}`,
      admin: `https://${EXPECTED.ADMIN_HOSTNAME}`,
      workers_dev: `https://${workersHostname}`,
      security,
      token_state_and_policy: capability,
      resource_writes: 'endpoint results succeeded; runtime acceptance remains separate',
      production_domain_cutover: false,
    }),
  );
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    await main();
  } catch (e) {
    console.error(JSON.stringify(safeError(e)));
    process.exitCode = 1;
  }
}
