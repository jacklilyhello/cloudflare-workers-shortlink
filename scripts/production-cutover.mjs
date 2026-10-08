import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import {
  ACCOUNT,
  HOST_ZONES,
  EXPECTED,
  createCFClient,
  ensure,
  listAll,
  requireAction,
  safeError,
  verifyAccount,
} from './cf-client.mjs';
import {
  readManifest,
  saveManifest,
  privateSnapshot,
  objectPath,
  verifyD1Owner,
  inspectWorker,
  inspectHost,
  hostPatternMatches,
  query,
} from './deploy-resources.mjs';
import { verifySecurity } from './security-bootstrap.mjs';
import {
  prepareFinalMigration,
  finalMigrate,
  disableLegacySync,
  readFinalMigrationResult,
  LEGACY_MIGRATION_DOMAIN,
} from './migrate-legacy.mjs';

export const CONFIRMATION = 'upgrade owned shortlink-new to production gfw.mom and gfw.lat';
export const PLAN_KEY = 'production-cutover-before-v1';
const PUBLIC = ['gfw.mom', 'gfw.lat'];
const TEST = ['test.gfw.mom', 'test.gfw.lat'];
const LEGACY = `${ACCOUNT}/workers/scripts/${EXPECTED.LEGACY_WORKER_NAME}`;
const NEW = `${ACCOUNT}/workers/scripts/${EXPECTED.WORKER_NAME}`;
const MARKER = 'SHORTLINK_LEGACY_READONLY_20261008';
const GUARD = `\n  // ${MARKER}: preserve legacy redirects; permanently stop legacy mutations.\n  const frozenPath = new URL(request.url).pathname;\n  const frozenAdmin = normalizeAdminPath(typeof ADMIN_PATH === 'string' ? ADMIN_PATH : '');\n  const frozenAPI = normalizeAdminApiPath(typeof ADMIN_API_BASE === 'string' ? ADMIN_API_BASE : '', frozenAdmin + '/api');\n  if (!['GET', 'HEAD'].includes(request.method) || [frozenAPI, frozenAdmin + '/api'].some(base => frozenPath === base || frozenPath.startsWith(base + '/'))) {\n    return new Response('Legacy link mutations are closed', {status: 410, headers: {'Cache-Control': 'no-store'}});\n  }\n`;
const HANDLER = 'async function handleRequest(request) {';
const sha = (v) =>
  createHash('sha256')
    .update(typeof v === 'string' ? v : JSON.stringify(v))
    .digest('hex');
const bindingsSha = (bindings) => sha([...bindings].sort((a, b) => a.name.localeCompare(b.name)));
const web = (d) => PUBLIC.includes(d.name) && ['A', 'AAAA', 'CNAME'].includes(d.type);
async function inventory(client) {
  const zones = {};
  for (const zone of new Set(Object.values(HOST_ZONES))) {
    const identity = (await client.request(zone)).result;
    ensure(
      identity.account?.id === EXPECTED.CLOUDFLARE_ACCOUNT_ID,
      'CUTOVER_ZONE_ACCOUNT_MISMATCH',
    );
    zones[zone] = {
      dns: await listAll(client, `${zone}/dns_records`),
      routes: await listAll(client, `${zone}/workers/routes`),
    };
  }
  return { zones, domains: await listAll(client, `${ACCOUNT}/workers/domains`) };
}
export async function readPlan(client, manifest) {
  const raw = await client.request(objectPath(`delivery/${manifest.owner_id}/${PLAN_KEY}.json`), {
    raw: true,
    maxBytes: 2 * 1024 * 1024,
  });
  const plan = JSON.parse(raw);
  const { sha256, ...data } = plan;
  ensure(
    plan.schema === 1 &&
      plan.owner_id === manifest.owner_id &&
      plan.database_id === manifest.d1.id &&
      plan.account === manifest.account &&
      sha(data) === sha256,
    'CUTOVER_CHECKPOINT_UNPROVEN',
  );
  if (manifest.production_cutover)
    ensure(
      manifest.production_cutover.plan_key === PLAN_KEY &&
        manifest.production_cutover.plan_sha256 === plan.sha256,
      'CUTOVER_CHECKPOINT_DRIFT',
    );
  return plan;
}
export async function prepareCutover(client, manifest) {
  await verifyD1Owner(client, manifest);
  await inspectWorker(client, manifest);
  const existing = await client.optional(
    objectPath(`delivery/${manifest.owner_id}/${PLAN_KEY}.json`),
    { raw: true },
  );
  if (existing !== null) {
    const plan = await readPlan(client, manifest);
    if (!manifest.production_cutover) {
      manifest.production_cutover = {
        schema: 1,
        plan_key: PLAN_KEY,
        plan_sha256: plan.sha256,
        phase: 'prepared',
      };
      await saveManifest(client, manifest);
    }
    return plan;
  }
  const state = await inventory(client);
  const source = await client.request(LEGACY, { raw: true });
  const settings = (await client.request(`${LEGACY}/settings`)).result;
  ensure(
    source.split(HANDLER).length === 2 &&
      !source.includes(MARKER) &&
      source.includes('addEventListener("fetch"'),
    'LEGACY_SOURCE_SHAPE_UNREVIEWED',
  );
  ensure(
    settings.bindings?.some(
      (b) => b.name === 'LINKS' && b.namespace_id === EXPECTED.LEGACY_KV_NAMESPACE_ID,
    ),
    'LEGACY_BINDING_UNPROVEN',
  );
  const widget = (
    await client.request(`${ACCOUNT}/challenges/widgets/${EXPECTED.TURNSTILE_SITE_KEY}`)
  ).result;
  ensure(
    PUBLIC.every((host) =>
      widget.domains?.some((domain) => host === domain || host.endsWith(`.${domain}`)),
    ),
    'PRODUCTION_TURNSTILE_HOSTNAME_MISSING',
  );
  const targets = PUBLIC.map((host) => {
    const custom = state.domains.filter((d) => d.hostname === host);
    ensure(
      custom.length === 1 &&
        custom[0].service === EXPECTED.LEGACY_WORKER_NAME &&
        custom[0].zone_id === HOST_ZONES[host].split('/').at(-1) &&
        custom[0].environment === 'production',
      'LEGACY_DOMAIN_TAKEOVER_UNPROVEN',
    );
    const zone = state.zones[HOST_ZONES[host]];
    const routes = zone.routes.filter((r) => hostPatternMatches(r.pattern, host));
    ensure(
      routes.every(
        (r) =>
          r.script === EXPECTED.LEGACY_WORKER_NAME &&
          String(r.pattern)
            .replace(/^https?:\/\//, '')
            .split('/')[0] === host,
      ),
      'CUTOVER_BROAD_OR_FOREIGN_ROUTE',
    );
    return {
      hostname: host,
      zone: HOST_ZONES[host],
      custom: custom[0],
      dns: zone.dns.filter((d) => d.name === host && ['A', 'AAAA', 'CNAME'].includes(d.type)),
      routes,
    };
  });
  const data = {
    schema: 1,
    owner_id: manifest.owner_id,
    account: manifest.account,
    database_id: manifest.d1.id,
    created_at: Date.now(),
    targets,
    before: state,
    legacy_source: source,
    legacy_source_sha256: sha(source),
    legacy_readonly_sha256: sha(source.replace(HANDLER, HANDLER + GUARD)),
    legacy_settings: Object.fromEntries(
      [
        'compatibility_date',
        'compatibility_flags',
        'usage_model',
        'limits',
        'logpush',
        'tail_consumers',
        'placement',
        'observability',
      ]
        .filter((key) => settings[key] !== undefined)
        .map((key) => [key, settings[key]]),
    ),
    legacy_binding_types: [...new Set(settings.bindings.map((binding) => binding.type))],
    legacy_bindings_sha256: bindingsSha(settings.bindings),
    legacy_settings_sha256: sha(settings),
    old_custom_entries: state.domains.filter((d) => d.service === EXPECTED.LEGACY_WORKER_NAME),
    turnstile_domains: widget.domains,
  };
  await privateSnapshot(
    client,
    manifest,
    PLAN_KEY,
    { ...data, sha256: sha(data) },
    { preserveExisting: true },
  );
  const plan = await readPlan(client, manifest);
  manifest.production_cutover ||= {
    schema: 1,
    plan_key: PLAN_KEY,
    plan_sha256: plan.sha256,
    phase: 'prepared',
  };
  await saveManifest(client, manifest);
  return plan;
}
function capabilities(plan) {
  const records = [
    { path: LEGACY, method: 'PUT', body_sha256: plan.legacy_readonly_sha256 },
    {
      path: `${LEGACY}/subdomain`,
      method: 'POST',
      body_sha256: sha({ enabled: false, previews_enabled: false }),
    },
  ];
  for (const t of plan.targets) {
    records.push({
      path: `${ACCOUNT}/workers/domains/${t.custom.id}`,
      method: 'DELETE',
      hostname: t.hostname,
    });
    for (const d of t.dns)
      records.push({
        path: `${t.zone}/dns_records/${d.id}`,
        method: 'DELETE',
        hostname: t.hostname,
      });
    for (const r of t.routes)
      records.push({
        path: `${t.zone}/workers/routes/${r.id}`,
        method: 'DELETE',
        hostname: t.hostname,
      });
  }
  return records;
}
export async function stopLegacyWrites(client, manifest, plan) {
  await verifySecurity(client, manifest, { production: true });
  await verifyD1Owner(client, manifest);
  const source = await client.request(LEGACY, { raw: true });
  const settings = (await client.request(`${LEGACY}/settings`)).result;
  ensure(bindingsSha(settings.bindings) === plan.legacy_bindings_sha256, 'LEGACY_BINDINGS_DRIFT');
  client.bindCutoverWrites(capabilities(plan));
  if (sha(source) !== plan.legacy_readonly_sha256) {
    ensure(sha(source) === plan.legacy_source_sha256, 'LEGACY_SOURCE_CHANGED_AFTER_PLAN');
    const metadata = {
      body_part: 'worker.js',
      bindings: [],
      compatibility_date: plan.legacy_settings.compatibility_date,
      compatibility_flags: plan.legacy_settings.compatibility_flags || [],
      keep_bindings: plan.legacy_binding_types,
    };
    for (const key of [
      'usage_model',
      'limits',
      'logpush',
      'tail_consumers',
      'placement',
      'observability',
    ])
      if (plan.legacy_settings[key] !== undefined) metadata[key] = plan.legacy_settings[key];
    const body = new FormData();
    body.set(
      'metadata',
      new Blob([JSON.stringify(metadata)], { type: 'application/json' }),
      'metadata.json',
    );
    body.set(
      'worker.js',
      new Blob([plan.legacy_source.replace(HANDLER, HANDLER + GUARD)], {
        type: 'application/javascript',
      }),
      'worker.js',
    );
    manifest.production_cutover.legacy_upload = {
      state: 'intent',
      source_sha256: plan.legacy_readonly_sha256,
    };
    await saveManifest(client, manifest);
    await client.request(LEGACY, { method: 'PUT', body });
  }
  const readback = await client.request(LEGACY, { raw: true });
  ensure(sha(readback) === plan.legacy_readonly_sha256, 'LEGACY_STOP_WRITE_READBACK_MISMATCH');
  const subdomain = (await client.request(`${LEGACY}/subdomain`)).result;
  if (subdomain.enabled || subdomain.previews_enabled)
    await client.request(`${LEGACY}/subdomain`, {
      method: 'POST',
      json: { enabled: false, previews_enabled: false },
    });
  const disabled = (await client.request(`${LEGACY}/subdomain`)).result;
  ensure(
    disabled.enabled === false && disabled.previews_enabled === false,
    'LEGACY_SUBDOMAIN_STILL_ENABLED',
  );
  const after = (await client.request(`${LEGACY}/settings`)).result;
  ensure(
    bindingsSha(after.bindings) === plan.legacy_bindings_sha256,
    'LEGACY_BINDINGS_NOT_PRESERVED',
  );
  manifest.production_cutover.legacy_stopped_at ||= Date.now();
  manifest.production_cutover.legacy_upload = {
    state: 'complete',
    source_sha256: plan.legacy_readonly_sha256,
  };
  manifest.production_cutover.phase = 'legacy-stopped';
  await saveManifest(client, manifest);
  await privateSnapshot(
    client,
    manifest,
    'production-legacy-stopped-v1',
    {
      owner_id: manifest.owner_id,
      legacy_entrypoints_stopped: true,
      stopped_at: manifest.production_cutover.legacy_stopped_at,
      plan_sha256: plan.sha256,
      source_sha256: plan.legacy_readonly_sha256,
    },
    { preserveExisting: true },
  );
  return {
    stopped_at: manifest.production_cutover.legacy_stopped_at,
    source_sha256: plan.legacy_readonly_sha256,
    workers_dev: false,
    previews: false,
    all_legacy_custom_entries_guarded: plan.old_custom_entries.map((d) => d.hostname),
  };
}
export async function verifyLegacyStopped(client, manifest, plan) {
  const source = await client.request(LEGACY, { raw: true });
  const settings = (await client.request(`${LEGACY}/settings`)).result;
  ensure(bindingsSha(settings.bindings) === plan.legacy_bindings_sha256, 'LEGACY_BINDINGS_DRIFT');
  const subdomain = (await client.request(`${LEGACY}/subdomain`)).result;
  ensure(
    manifest.production_cutover?.legacy_stopped_at &&
      sha(source) === plan.legacy_readonly_sha256 &&
      subdomain.enabled === false &&
      subdomain.previews_enabled === false,
    'LEGACY_STOP_REQUIRED',
  );
}
export async function takeOverDomains(client, manifest, plan) {
  await verifyLegacyStopped(client, manifest, plan);
  ensure(
    manifest.production_cutover.sync_disabled &&
      manifest.production_cutover.backup?.verified === true,
    'FINAL_MIGRATION_AND_BACKUP_REQUIRED',
  );
  client.bindCutoverWrites(capabilities(plan));
  for (const t of plan.targets) {
    let current = await listAll(client, `${ACCOUNT}/workers/domains`);
    const old = current.find((d) => d.id === t.custom.id);
    if (old) {
      ensure(
        old.hostname === t.hostname &&
          old.service === EXPECTED.LEGACY_WORKER_NAME &&
          old.zone_id === t.custom.zone_id,
        'CUTOVER_DOMAIN_DRIFT',
      );
      manifest.production_cutover.phase = `detach-${t.hostname}`;
      await saveManifest(client, manifest);
      await client.request(`${ACCOUNT}/workers/domains/${old.id}`, { method: 'DELETE' });
    }
    for (const route of t.routes) {
      const now = (await listAll(client, `${t.zone}/workers/routes`)).find(
        (r) => r.id === route.id,
      );
      if (now) {
        ensure(sha(now) === sha(route), 'CUTOVER_ROUTE_DRIFT');
        await client.request(`${t.zone}/workers/routes/${route.id}`, { method: 'DELETE' });
      }
    }
    current = await listAll(client, `${ACCOUNT}/workers/domains`);
    const custom = current.filter((d) => d.hostname === t.hostname);
    ensure(custom.length <= 1, 'DUPLICATE_CUSTOM_DOMAIN');
    if (!custom.length) {
      const dns = await listAll(client, `${t.zone}/dns_records`);
      for (const record of dns.filter(
        (d) => d.name === t.hostname && ['A', 'AAAA', 'CNAME'].includes(d.type),
      )) {
        const before = t.dns.find((d) => d.id === record.id);
        ensure(
          before &&
            record.type === before.type &&
            record.content === before.content &&
            record.proxied === before.proxied,
          'UNPLANNED_WEB_DNS',
        );
        await client.request(`${t.zone}/dns_records/${record.id}`, { method: 'DELETE' });
      }
      manifest.domain_intents ||= {};
      manifest.domain_intents[t.hostname] = {
        zone_id: t.custom.zone_id,
        service: EXPECTED.WORKER_NAME,
        owner_id: manifest.owner_id,
      };
      await saveManifest(client, manifest);
      const attached = (
        await client.request(`${ACCOUNT}/workers/domains`, {
          method: 'PUT',
          json: { hostname: t.hostname, service: EXPECTED.WORKER_NAME, zone_id: t.custom.zone_id },
        })
      ).result;
      ensure(
        attached.hostname === t.hostname &&
          attached.service === EXPECTED.WORKER_NAME &&
          attached.zone_id === t.custom.zone_id &&
          attached.environment === 'production',
        'CUTOVER_DOMAIN_READBACK_MISMATCH',
      );
      manifest.domains[t.hostname] = { id: attached.id, zone_id: attached.zone_id };
      await saveManifest(client, manifest);
    }
    await inspectHost(client, t.hostname, manifest, { recover: true });
    await query(
      client,
      manifest.d1.id,
      "INSERT INTO domains(hostname,enabled,bound,created_at,binding_state,last_checked_at,last_verified_at) VALUES(?,1,1,?,'verified',?,?) ON CONFLICT(hostname) DO UPDATE SET enabled=1,bound=1,binding_state='verified',binding_error=NULL,last_checked_at=excluded.last_checked_at,last_verified_at=excluded.last_verified_at",
      [t.hostname, Date.now(), Date.now(), Date.now()],
    );
  }
  await query(client, manifest.d1.id, 'UPDATE domains SET enabled=0 WHERE hostname IN (?,?)', TEST);
  manifest.environment = 'production';
  manifest.production_cutover.phase = 'domains-attached';
  await saveManifest(client, manifest);
  await verifyPreservedInfrastructure(client, manifest, plan);
}
export async function verifyPreservedInfrastructure(client, manifest, plan) {
  const current = await inventory(client);
  const sorted = (rows) => rows.sort((a, b) => String(a.id).localeCompare(String(b.id)));
  for (const [zone, state] of Object.entries(plan.before.zones)) {
    const normalize = (d) => ({
      id: d.id,
      name: d.name,
      type: d.type,
      content: d.content,
      proxied: d.proxied,
      ttl: d.ttl,
      priority: d.priority,
    });
    ensure(
      sha(sorted(state.dns.filter((d) => !web(d)).map(normalize))) ===
        sha(sorted(current.zones[zone].dns.filter((d) => !web(d)).map(normalize))),
      'UNRELATED_DNS_CHANGED',
    );
    const except = new Set(plan.targets.flatMap((t) => t.routes.map((r) => r.id)));
    ensure(
      sha(sorted(state.routes.filter((r) => !except.has(r.id)))) ===
        sha(sorted(current.zones[zone].routes.filter((r) => !except.has(r.id)))),
      'UNRELATED_ROUTES_CHANGED',
    );
  }
  const normalize = (d) => ({
    id: d.id,
    hostname: d.hostname,
    service: d.service,
    zone_id: d.zone_id,
    environment: d.environment,
  });
  ensure(
    sha(sorted(plan.before.domains.filter((d) => !PUBLIC.includes(d.hostname)).map(normalize))) ===
      sha(sorted(current.domains.filter((d) => !PUBLIC.includes(d.hostname)).map(normalize))),
    'UNRELATED_CUSTOM_DOMAINS_CHANGED',
  );
  await verifyLegacyStopped(client, manifest, plan);
  return { unrelated_dns_routes_and_domains_preserved: true, legacy_worker_and_kv_preserved: true };
}
export async function inspectMigration(client, manifest) {
  const stoppedAt = manifest.production_cutover?.legacy_stopped_at;
  ensure(Number.isSafeInteger(stoppedAt) && stoppedAt > 0, 'LEGACY_STOP_REQUIRED');
  const unreadReason = 'legacy_value_exceeds_read_limit_value_fingerprint_unverified';
  const params = [EXPECTED.LEGACY_KV_NAMESPACE_ID, LEGACY_MIGRATION_DOMAIN, stoppedAt];
  const sql = {
    runs: "SELECT r.id,r.state,r.processed,r.imported,r.unchanged,r.skipped,r.conflicts,r.unknown,r.started_at,r.updated_at,r.completed_at,r.digest,r.last_error_code,CASE WHEN r.cursor<>'' THEN 1 ELSE 0 END AS cursor_present,(SELECT COUNT(*) FROM legacy_migration_items i WHERE i.run_id=r.id AND i.status IN ('unknown','conflict')) AS actual_anomaly_observations,(SELECT COUNT(DISTINCT i.key_hash) FROM legacy_migration_items i WHERE i.run_id=r.id AND i.status IN ('unknown','conflict') AND i.reason<>?) AS actual_abnormal_keys,(SELECT COUNT(DISTINCT i.key_hash) FROM legacy_migration_items i WHERE i.run_id=r.id AND i.reason=?) AS actual_unread_keys FROM legacy_migration_runs r WHERE r.namespace_id=? AND r.domain=? AND r.started_at<=? ORDER BY r.started_at DESC,r.id DESC LIMIT 20",
    reasons:
      "SELECT i.status,i.reason,COUNT(DISTINCT i.key_hash) AS distinct_keys,COUNT(DISTINCT i.key_hash||':'||i.value_hash) AS distinct_values,COUNT(DISTINCT i.run_id) AS observed_runs FROM legacy_migration_items i JOIN legacy_migration_runs r ON r.id=i.run_id WHERE r.namespace_id=? AND r.domain=? AND r.started_at<=? AND i.status IN ('unknown','conflict') GROUP BY i.status,i.reason ORDER BY distinct_keys DESC,i.status,i.reason LIMIT 8",
    historical:
      "SELECT COUNT(*) AS distinct_anomaly_observations,COUNT(DISTINCT key_hash) AS distinct_anomaly_keys,COUNT(DISTINCT CASE WHEN reason<>? THEN key_hash END) AS distinct_abnormal_keys,COUNT(DISTINCT CASE WHEN reason=? THEN key_hash END) AS distinct_unread_keys,(SELECT COUNT(*) FROM (SELECT i.status,i.reason FROM legacy_migration_items i JOIN legacy_migration_runs r ON r.id=i.run_id WHERE r.namespace_id=? AND r.domain=? AND r.started_at<=? AND i.status IN ('unknown','conflict') GROUP BY i.status,i.reason)) AS reason_groups FROM (SELECT DISTINCT i.key_hash,i.value_hash,i.status,i.reason FROM legacy_migration_items i JOIN legacy_migration_runs r ON r.id=i.run_id WHERE r.namespace_id=? AND r.domain=? AND r.started_at<=? AND i.status IN ('unknown','conflict'))",
    resolved:
      "WITH historical AS (SELECT DISTINCT i.key_hash FROM legacy_migration_items i JOIN legacy_migration_runs r ON r.id=i.run_id WHERE r.namespace_id=? AND r.domain=? AND r.started_at<=? AND i.status IN ('unknown','conflict')),latest AS (SELECT id FROM legacy_migration_runs WHERE namespace_id=? AND domain=? AND state='complete' AND completed_at<=? ORDER BY completed_at DESC,id DESC LIMIT 1) SELECT (SELECT id FROM latest) AS latest_complete_run_id,COUNT(*) AS historical_anomaly_keys,COALESCE(SUM(EXISTS(SELECT 1 FROM legacy_migration_items i WHERE i.run_id=(SELECT id FROM latest) AND i.key_hash=h.key_hash AND i.status IN ('unknown','conflict'))),0) AS still_anomalous_in_latest_complete,COALESCE(SUM(EXISTS(SELECT 1 FROM legacy_migration_items i WHERE i.run_id=(SELECT id FROM latest) AND i.key_hash=h.key_hash AND i.status NOT IN ('unknown','conflict')) AND NOT EXISTS(SELECT 1 FROM legacy_migration_items i WHERE i.run_id=(SELECT id FROM latest) AND i.key_hash=h.key_hash AND i.status IN ('unknown','conflict'))),0) AS resolved_in_latest_complete,COALESCE(SUM(NOT EXISTS(SELECT 1 FROM legacy_migration_items i WHERE i.run_id=(SELECT id FROM latest) AND i.key_hash=h.key_hash)),0) AS absent_in_latest_complete FROM historical h",
  };
  const allowed = new Set(Object.values(sql));
  const target = `${ACCOUNT}/d1/database/${manifest.d1.id}/query`;
  const readonly = {
    request: (path, options = {}) => {
      ensure(
        path === target && options.method === 'POST' && allowed.has(options.json?.sql),
        'MIGRATION_INSPECT_FIXED_READ_REQUIRED',
      );
      return client.request(path, options);
    },
  };
  const select = async (statement, values) =>
    (await query(readonly, manifest.d1.id, statement, values))[0].results;
  const runs = await select(sql.runs, [unreadReason, unreadReason, ...params]);
  const reasons = await select(sql.reasons, params);
  const historical = (
    await select(sql.historical, [unreadReason, unreadReason, ...params, ...params])
  )[0];
  const resolved = (await select(sql.resolved, [...params, ...params]))[0];
  ensure(
    runs.length <= 20 && reasons.length <= 8 && historical && resolved,
    'MIGRATION_INSPECT_RESPONSE_INVALID',
  );
  // Reasons are fixed classifier codes, never legacy keys or values. Retain
  // only safe metadata even if an older record contains an unexpected code.
  const safeReason = (value) =>
    /^[a-z0-9_]{1,160}$/.test(value || '') ? value : 'unreviewed_reason';
  const safeCode = (value) =>
    value === null ? null : /^[A-Z_]{1,120}$/.test(value || '') ? value : 'UNREVIEWED_ERROR';
  return {
    read_only: true,
    writes_performed: false,
    observed_at: Date.now(),
    stopped_at: stoppedAt,
    namespace_id: EXPECTED.LEGACY_KV_NAMESPACE_ID,
    domain: LEGACY_MIGRATION_DOMAIN,
    historical,
    latest_complete_comparison: resolved,
    reason_groups_truncated: historical.reason_groups > reasons.length,
    historical_anomalies_by_reason: reasons.map((row) => ({
      ...row,
      reason: safeReason(row.reason),
    })),
    recent_runs: runs.map((row) => ({ ...row, last_error_code: safeCode(row.last_error_code) })),
    diagnostic_rows: runs.length + reasons.length + 2,
    interpretation:
      'all-history anomalies include historical classifications; this readback does not expand owner waivers',
  };
}
export async function main(env = process.env) {
  requireAction(env, CONFIRMATION);
  ensure(env.PRODUCTION_RELEASE_AUTHORIZED === 'true', 'PRODUCTION_AUTHORIZATION_REQUIRED');
  const client = createCFClient(env.CLOUDFLARE_API_TOKEN, { allowWrites: true });
  await verifyAccount(client);
  const manifest = await readManifest(client);
  ensure(manifest?.d1 && manifest.worker_created, 'EXISTING_RESOURCES_REQUIRED');
  await verifyD1Owner(client, manifest);
  const stage = env.CUTOVER_STAGE;
  if (stage === 'prepare') {
    const plan = await prepareCutover(client, manifest);
    return {
      stage,
      owner_id: manifest.owner_id,
      database_id: manifest.d1.id,
      plan_sha256: plan.sha256,
      targets: plan.targets.map((t) => ({
        hostname: t.hostname,
        old_custom_domain_id: t.custom.id,
        web_dns_ids: t.dns.map((d) => d.id),
        route_ids: t.routes.map((r) => r.id),
      })),
      turnstile_domains_covered: true,
    };
  }
  const plan = await readPlan(client, manifest);
  if (stage === 'stop-legacy')
    return { stage, ...(await stopLegacyWrites(client, manifest, plan)) };
  await verifyLegacyStopped(client, manifest, plan);
  if (stage === 'inspect-migration')
    return { stage, ...(await inspectMigration(client, manifest)) };
  const finalKey = manifest.production_cutover.final_checkpoint_key;
  if (stage === 'final-scan') {
    let key = finalKey;
    if (!key) {
      const baseline = await prepareFinalMigration(client, manifest, {
        stoppedAt: manifest.production_cutover.legacy_stopped_at,
        shutdownEvidence: {
          legacy_entrypoints_stopped: true,
          checkpoint_key: 'production-legacy-stopped-v1',
        },
      });
      key = baseline.checkpointKey;
      manifest.production_cutover.final_checkpoint_key = key;
      await saveManifest(client, manifest);
    }
    return {
      stage,
      ...(await finalMigrate({ client, manifest, checkpointKey: key, maxPages: 10 })),
    };
  }
  if (stage === 'disable-sync') {
    ensure(manifest.production_cutover.backup?.verified === true, 'FINAL_BACKUP_REQUIRED');
    const result = await disableLegacySync({
      client,
      manifest,
      checkpointKey: finalKey,
      backupProof: manifest.production_cutover.backup,
    });
    manifest.production_cutover.sync_disabled = true;
    await saveManifest(client, manifest);
    return { stage, ...result };
  }
  if (stage === 'backup') {
    const { ensureProductionBackup } = await import('./production-backup.mjs');
    const finalResult = await readFinalMigrationResult(client, manifest, {
      checkpointKey: finalKey,
    });
    const result = await ensureProductionBackup(client, manifest, { finalResult });
    if (result.state === 'complete') {
      manifest.production_cutover.backup = { ...result, verified: true };
      await saveManifest(client, manifest);
    }
    return { stage, ...result };
  }
  if (stage === 'verify') {
    const preservation = await verifyPreservedInfrastructure(client, manifest, plan);
    await verifyD1Owner(client, manifest);
    await inspectWorker(client, manifest);
    const domains = [];
    for (const host of PUBLIC) {
      const state = await inspectHost(client, host, manifest);
      ensure(
        state.custom?.service === EXPECTED.WORKER_NAME && state.custom.environment === 'production',
        'FORMAL_DOMAIN_NOT_ATTACHED',
      );
      domains.push({
        hostname: host,
        custom_domain_id: state.custom.id,
        service: state.custom.service,
        service_environment: state.custom.environment,
      });
    }
    const rows = (
      await query(
        client,
        manifest.d1.id,
        'SELECT hostname,enabled,bound,binding_state FROM domains WHERE hostname IN (?,?,?,?) ORDER BY hostname',
        [...PUBLIC, ...TEST],
      )
    )[0].results;
    ensure(
      PUBLIC.every((h) =>
        rows.some(
          (r) =>
            r.hostname === h && r.enabled === 1 && r.bound === 1 && r.binding_state === 'verified',
        ),
      ) && TEST.every((h) => rows.some((r) => r.hostname === h && r.enabled === 0)),
      'PUBLIC_DOMAIN_RUNTIME_STATE_INVALID',
    );
    const settings = (await client.request(`${NEW}/settings`)).result;
    const binding = (name) => settings.bindings.filter((b) => b.name === name);
    const readerBindings = binding('DOMAIN_BINDING_READ_TOKEN');
    const domainReaderBinding = {
      present: readerBindings.length > 0,
      unique: readerBindings.length === 1,
      secret_text: readerBindings.length === 1 && readerBindings[0].type === 'secret_text',
      credential_value_withheld: true,
      fresh_qualification_of_retained_secret_performed: false,
    };
    ensure(
      binding('APP_ENV').length === 1 &&
        binding('APP_ENV')[0].text === 'production' &&
        binding('PUBLIC_HOSTNAME').length === 1 &&
        binding('PUBLIC_HOSTNAME')[0].text === 'gfw.mom' &&
        binding('ADMIN_EMAILS').length === 1 &&
        binding('ADMIN_EMAILS')[0].text === EXPECTED.ADMIN_EMAILS,
      'PRODUCTION_WORKER_VARIABLES_INVALID',
    );
    const subdomain = (await client.request(`${NEW}/subdomain`)).result;
    ensure(
      subdomain.enabled === false && subdomain.previews_enabled === false,
      'WORKERS_DEV_OR_PREVIEW_ENABLED',
    );
    const schedules = (await client.request(`${NEW}/schedules`)).result;
    ensure(
      Array.isArray(schedules) && schedules.some((s) => s.cron === '*/10 * * * *'),
      'WORKER_MAINTENANCE_CRON_MISSING',
    );
    const migration = (
      await query(
        client,
        manifest.d1.id,
        "SELECT key,value FROM settings WHERE key IN ('migration_enabled','backup_enabled') ORDER BY key",
      )
    )[0].results;
    ensure(
      migration.some((r) => r.key === 'migration_enabled' && r.value === '0'),
      'LEGACY_SYNC_NOT_DISABLED',
    );
    const final = await readFinalMigrationResult(client, manifest, { checkpointKey: finalKey });
    ensure(
      final.final_scan_complete && final.lease_released && final.new_anomalies === 0,
      'FINAL_MIGRATION_NOT_COMPLETE',
    );
    const { verifyFinalMigrationBackup } = await import('./deploy-upgrade-guard.mjs');
    const backup = await verifyFinalMigrationBackup(client, manifest, {
      finalResult: final,
      backupId: manifest.production_cutover.backup?.backup_id,
    });
    const security = await verifySecurity(client, manifest, { production: true });
    return {
      stage,
      production_configuration_verified: true,
      domains,
      test_domain_records: rows.filter((r) => TEST.includes(r.hostname)),
      test_cf_resources_preserved: true,
      workers_dev: false,
      preview_urls: false,
      worker_maintenance_cron: '*/10 * * * *',
      settings: migration,
      security,
      domain_binding_read_secret: domainReaderBinding,
      final_migration: final,
      backup,
      ...preservation,
      business_requests_and_browser_tests_executed: false,
    };
  }
  ensure(false, 'CUTOVER_STAGE_INVALID');
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const result = await main();
    console.log(JSON.stringify(result));
    if (result.state === 'failed_final_backup') process.exitCode = 2;
  } catch (error) {
    console.error(JSON.stringify(safeError(error)));
    process.exitCode = 1;
  }
}
