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
import { selectDomainReadCredential } from './domain-read-credential.mjs';
import { verifyGlobalUpgradeBackup, verifyReleaseMigrations } from './deploy-upgrade-guard.mjs';
import {
  readPlan,
  readReleasePreservation,
  takeOverDomains,
  verifyPreservedInfrastructure,
  prepareReleasePreservation,
  CONFIRMATION,
} from './production-cutover.mjs';
import {
  activeWorkerVersion,
  verifyWorkerReleaseVersion,
  rollbackWorkerRelease,
} from './worker-release.mjs';

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
    // Domain identity probes must reach the public front door, including this Worker.
    compatibility_flags: ['global_fetch_strictly_public'],
    workers_dev: false,
    preview_urls: false,
    assets: {
      directory: '../dist',
      binding: 'ASSETS',
      run_worker_first: true,
      html_handling: 'none',
    },
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
      APP_ENV: 'production',
      CLOUDFLARE_ACCOUNT_ID: EXPECTED.CLOUDFLARE_ACCOUNT_ID,
      WORKER_NAME: EXPECTED.WORKER_NAME,
      D1_DATABASE_ID: manifest.d1.id,
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

function verifyReleaseBindings(settings, config) {
  ensure(Array.isArray(settings?.bindings), 'DEPLOYED_WORKER_BINDINGS_UNREADABLE');
  const bindings = new Map(settings.bindings.map((binding) => [binding.name, binding]));
  const secrets = [...bindings.values()]
    .filter((binding) => binding.type === 'secret_text' || binding.type === 'secret_key')
    .map(({ name, type }) => `${type}:${name}`)
    .sort();
  ensure(
    bindings.size === settings.bindings.length &&
      bindings.size === Object.keys(config.vars).length + 3 + secrets.length &&
      bindings.get('ASSETS')?.type === 'assets' &&
      secrets.includes('secret_text:TURNSTILE_SECRET_KEY') &&
      secrets.includes('secret_text:DOMAIN_BINDING_READ_TOKEN') &&
      Object.entries(config.vars).every(([name, text]) => {
        const binding = bindings.get(name);
        return binding?.type === 'plain_text' && binding.text === text;
      }),
    'ORDINARY_RELEASE_WORKER_BINDINGS_DRIFT',
  );
  return JSON.stringify(secrets);
}

async function verifyWorkerEndpoints(client, config) {
  const path = `${ACCOUNT}/workers/scripts/${EXPECTED.WORKER_NAME}`;
  const { result: subdomain } = await client.request(`${path}/subdomain`);
  ensure(
    subdomain.enabled === false && subdomain.previews_enabled === false,
    'PRODUCTION_WORKERS_DEV_OR_PREVIEW_ENABLED',
  );
  const { result } = await client.request(`${path}/schedules`);
  const schedules = Array.isArray(result) ? result : result?.schedules;
  ensure(
    Array.isArray(schedules) &&
      schedules.length === config.triggers.crons.length &&
      config.triggers.crons.every((cron) => schedules.some((schedule) => schedule.cron === cron)),
    'PRODUCTION_WORKER_SCHEDULE_DRIFT',
  );
}

async function deployRelease(client, manifest, plan, config, workersHostname, env) {
  const sha = env.GITHUB_SHA;
  const baselineVersion = env.BASELINE_WORKER_VERSION;
  const attempts = manifest.journal.filter(
    (entry) => entry.step === 'worker-upload' && entry.state === 'intent' && entry.sha === sha,
  );
  ensure(
    attempts.every((entry) => entry.previous_version_id === baselineVersion) &&
      !manifest.journal.some((entry) => entry.step === 'worker-rollback' && entry.sha === sha),
    'RELEASE_VERSION_BASELINE_DRIFT',
  );
  const before = await activeWorkerVersion(client);
  const alreadyDeployed = before.version_id !== baselineVersion;
  const completed =
    manifest.last_sha === sha &&
    manifest.production_release_preservation?.release_sha === sha &&
    manifest.production_release_preservation.verified === true;
  ensure(!completed || alreadyDeployed, 'RELEASE_VERSION_BASELINE_DRIFT');
  if (alreadyDeployed) {
    ensure(attempts.length > 0, 'RELEASE_VERSION_BASELINE_DRIFT');
    await verifyWorkerReleaseVersion(client, before.version_id, sha);
  }
  const settingsBefore = (await inspectWorker(client, manifest)).result;
  const secretsBefore = verifyReleaseBindings(settingsBefore, config);
  await verifyWorkerEndpoints(client, config);
  const ledger = await verifyReleaseMigrations(client, manifest);
  const backup = await verifyGlobalUpgradeBackup(client, manifest);
  const checkpoint = completed
    ? await readReleasePreservation(client, manifest, plan, sha)
    : await prepareReleasePreservation(client, manifest, plan, env);
  ensure(checkpoint, 'RELEASE_CHECKPOINT_UNPROVEN');
  if (!attempts.length) {
    manifest.journal.push({
      step: 'worker-upload',
      state: 'intent',
      sha,
      previous_version_id: baselineVersion,
      time: new Date().toISOString(),
    });
    await saveManifest(client, manifest);
  }
  const current = await activeWorkerVersion(client);
  ensure(current.deployment_id === before.deployment_id, 'RELEASE_VERSION_BASELINE_DRIFT');
  if (!alreadyDeployed) {
    // Wrangler preserves existing secret bindings. Ordinary upgrades never issue secret PUTs.
    wrangler(['deploy', '--config', '.local/wrangler.deploy.json', '--tag', sha], env);
  }
  const active = await activeWorkerVersion(client);
  ensure(active.version_id !== baselineVersion, 'RELEASE_NEW_VERSION_NOT_ACTIVE');
  const version = await verifyWorkerReleaseVersion(client, active.version_id, sha);
  const settingsAfter = (await inspectWorker(client, manifest)).result;
  ensure(
    verifyReleaseBindings(settingsAfter, config) === secretsBefore,
    'RELEASE_SECRET_BINDINGS_CHANGED',
  );
  await verifyWorkerEndpoints(client, config);
  const preservation = await verifyPreservedInfrastructure(client, manifest, plan, checkpoint);
  await verifySecurity(client, manifest, { production: true });
  if (!completed) {
    manifest.workers_hostname = workersHostname;
    manifest.last_sha = sha;
    manifest.production_release_preservation.verified = true;
    manifest.journal.push(
      {
        step: 'worker-upload',
        state: 'complete',
        sha,
        version_id: active.version_id,
        time: new Date().toISOString(),
      },
      {
        step: 'release-preservation',
        state: 'verified',
        sha,
        source_sha: checkpoint.source_sha,
        key: manifest.production_release_preservation.key,
        sha256: checkpoint.sha256,
        time: new Date().toISOString(),
      },
    );
    await saveManifest(client, manifest);
  }
  console.log(
    JSON.stringify({
      mode: 'release',
      worker: config.name,
      previous_version_id: baselineVersion,
      deployment: active,
      version,
      release_migrations: ledger,
      pre_upgrade_backup: backup,
      final_migration_backup_verified: true,
      secret_bindings_preserved: true,
      infrastructure_preservation: preservation,
    }),
  );
}

async function rollbackRelease(client, manifest, plan, env) {
  const sha = env.EXPECTED_RELEASE_SHA;
  const pin = manifest.production_release_preservation;
  ensure(pin?.release_sha === sha, 'ROLLBACK_RELEASE_CHECKPOINT_UNPROVEN');
  const checkpoint = await readReleasePreservation(client, manifest, plan, sha);
  ensure(checkpoint, 'ROLLBACK_RELEASE_CHECKPOINT_UNPROVEN');
  const rollback = await rollbackWorkerRelease(client, manifest, {
    sha,
    baselineVersion: env.BASELINE_WORKER_VERSION,
  });
  const preservation = await verifyPreservedInfrastructure(client, manifest, plan, checkpoint);
  pin.verified = true;
  manifest.last_sha = checkpoint.source_sha;
  manifest.journal.push(
    {
      step: 'worker-rollback',
      state: 'complete',
      sha,
      version_id: rollback.version_id,
      time: new Date().toISOString(),
    },
    {
      step: 'release-preservation',
      state: 'verified',
      sha,
      source_sha: checkpoint.source_sha,
      key: pin.key,
      sha256: pin.sha256,
      time: new Date().toISOString(),
    },
  );
  await saveManifest(client, manifest);
  console.log(
    JSON.stringify({
      mode: 'rollback-release',
      rollback,
      infrastructure_preservation: preservation,
    }),
  );
}

export async function main(args = process.argv.slice(2), env = process.env) {
  ensure(
    args.length === 1 && ['bootstrap', 'test', 'production'].includes(args[0]),
    'DEPLOY_MODE_INVALID',
  );
  const mode = args[0];
  const ordinary = env.CUTOVER_STAGE === 'release' || env.CUTOVER_STAGE === 'rollback-release';
  ensure(mode === 'production', 'TEST_DEPLOYMENT_RETIRED');
  requireAction(
    env,
    mode === 'bootstrap'
      ? 'initialize shortlink-new test only'
      : mode === 'production'
        ? CONFIRMATION
        : 'deploy shortlink-new test only',
  );
  if (mode === 'production')
    ensure(
      env.PRODUCTION_RELEASE_AUTHORIZED === 'true',
      'PRODUCTION_SEPARATE_AUTHORIZATION_REQUIRED',
    );
  if (ordinary) {
    ensure(
      /^[a-f\d]{40}$/.test(env.EXPECTED_RELEASE_SHA || '') &&
        (env.CUTOVER_STAGE === 'rollback-release' || env.EXPECTED_RELEASE_SHA === env.GITHUB_SHA),
      'PRODUCTION_RELEASE_SHA_MISMATCH',
    );
    ensure(
      /^[a-f\d]{8}(?:-[a-f\d]{4}){3}-[a-f\d]{12}$/.test(env.BASELINE_WORKER_VERSION || ''),
      'PRODUCTION_RELEASE_BASELINE_VERSION_INVALID',
    );
  } else {
    ensure(
      env.TURNSTILE_SECRET_KEY?.length > 0 && !/\s/.test(env.TURNSTILE_SECRET_KEY),
      'TURNSTILE_ACTION_SECRET_MISSING',
    );
  }
  ensure(statSync('dist').isDirectory(), 'BUILT_UI_MISSING');
  const client = createCFClient(env.CLOUDFLARE_API_TOKEN, { allowWrites: true });
  const capability = await verifyAccount(client);
  if (mode === 'bootstrap') {
    // Inspect Access overlap and unsuppressible products before creating any new resources.
    const previous = await readManifest(client);
    await inspectSecurity(client, previous);
  }
  const manifest = await prepareResources(client, { productionUpgrade: true });
  ensure(
    manifest.production_cutover?.sync_disabled &&
      manifest.production_cutover.backup?.verified === true,
    'FINAL_MIGRATION_AND_BACKUP_REQUIRED',
  );
  const complete =
    manifest.environment === 'production' && manifest.production_cutover.phase === 'complete';
  ensure(ordinary === complete, 'PRODUCTION_STAGE_DOES_NOT_MATCH_RESOURCE_STATE');
  if (mode === 'bootstrap') await bootstrapSecurity(client, manifest);
  const security = await verifySecurity(client, manifest, { production: mode === 'production' });
  const plan = await readPlan(client, manifest);
  if (env.CUTOVER_STAGE === 'rollback-release') return rollbackRelease(client, manifest, plan, env);
  const subdomain = (await client.request(`${ACCOUNT}/workers/subdomain`)).result.subdomain;
  ensure(/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(subdomain || ''), 'WORKERS_SUBDOMAIN_INVALID');
  const workersHostname = `${EXPECTED.WORKER_NAME}.${subdomain}.workers.dev`;
  const config = deploymentConfiguration(manifest, workersHostname);
  mkdirSync('.local', { recursive: true, mode: 0o700 });
  writeFileSync('.local/wrangler.deploy.json', JSON.stringify(config, null, 2) + '\n', {
    mode: 0o600,
  });
  if (ordinary) return deployRelease(client, manifest, plan, config, workersHostname, env);
  // Wrangler applies a ledger of reviewed SQL migrations only to the independently owned DB.
  const preUpgradeBackup = await verifyGlobalUpgradeBackup(client, manifest);
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
  wrangler(['deploy', '--config', '.local/wrangler.deploy.json'], env);
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
  if (manifest.production_cutover.phase !== 'complete')
    await takeOverDomains(client, manifest, plan);
  ensure(
    manifest.domains[EXPECTED.PUBLIC_HOSTNAME] && manifest.domains[EXPECTED.ADMIN_HOSTNAME],
    'CUSTOM_DOMAINS_INCOMPLETE',
  );
  if (mode === 'bootstrap') {
    // Binding becomes usable only after guarded Custom Domain/DNS readback; retain administrator enabled state.
    await query(
      client,
      manifest.d1.id,
      "UPDATE domains SET bound=1,binding_state='verified',last_checked_at=?,last_verified_at=? WHERE hostname=?",
      [Date.now(), Date.now(), EXPECTED.PUBLIC_HOSTNAME],
    );
  }
  // Only a separately proven read-only credential may enter the runtime. Missing capability
  // is reported explicitly; the deployment credential never becomes a Worker binding.
  const domainReader = await selectDomainReadCredential(env, manifest);
  if (domainReader.token)
    await client.request(`${ACCOUNT}/workers/scripts/${EXPECTED.WORKER_NAME}/secrets`, {
      method: 'PUT',
      json: { name: 'DOMAIN_BINDING_READ_TOKEN', type: 'secret_text', text: domainReader.token },
    });
  const readerSettings = (
    await client.request(`${ACCOUNT}/workers/scripts/${EXPECTED.WORKER_NAME}/settings`)
  ).result;
  ensure(Array.isArray(readerSettings?.bindings), 'DEPLOYED_WORKER_BINDINGS_UNREADABLE');
  const readerBindings = readerSettings.bindings.filter(
    (binding) => binding.name === 'DOMAIN_BINDING_READ_TOKEN',
  );
  const domainReaderBinding = {
    present: readerBindings.length > 0,
    unique: readerBindings.length === 1,
    secret_text: readerBindings.length === 1 && readerBindings[0].type === 'secret_text',
    newly_qualified_credential_installed: !!domainReader.token,
    existing_secret_retained_without_replacement:
      !domainReader.token &&
      readerBindings.length === 1 &&
      readerBindings[0].type === 'secret_text',
    credential_value_withheld: true,
    fresh_qualification_of_retained_secret_performed: false,
  };
  manifest.journal.push({
    step: 'worker-upload',
    state: 'complete',
    sha: env.GITHUB_SHA,
    time: new Date().toISOString(),
  });
  await saveManifest(client, manifest);
  const subdomainState = (
    await client.request(`${ACCOUNT}/workers/scripts/${EXPECTED.WORKER_NAME}/subdomain`)
  ).result;
  ensure(
    subdomainState.enabled === false && subdomainState.previews_enabled === false,
    'PRODUCTION_WORKERS_DEV_OR_PREVIEW_ENABLED',
  );
  const preservation = await verifyPreservedInfrastructure(client, manifest, plan);
  manifest.production_cutover.phase = 'complete';
  await saveManifest(client, manifest);
  console.log(
    JSON.stringify({
      mode,
      worker: EXPECTED.WORKER_NAME,
      public: `https://${EXPECTED.PUBLIC_HOSTNAME}`,
      admin: `https://${EXPECTED.ADMIN_HOSTNAME}`,
      workers_dev: false,
      preview_urls: false,
      security,
      pre_upgrade_backup: preUpgradeBackup,
      domain_binding_read_credentials: domainReader.checks,
      domain_binding_read_secret: domainReaderBinding,
      token_state_and_policy: capability,
      resource_writes: 'endpoint results succeeded; runtime acceptance remains separate',
      production_domain_cutover: true,
      infrastructure_preservation: preservation,
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
