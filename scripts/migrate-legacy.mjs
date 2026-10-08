#!/usr/bin/env node
import { createHash, randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { isNewSlug, isSafeLegacySlug } from '../src/legacy-slug.mjs';
import {
  ACCOUNT,
  EXPECTED,
  REPOSITORY,
  ensure,
  fail,
  createCFClient,
  requireAction,
  verifyAccount,
  safeError,
  DeliveryError,
} from './cf-client.mjs';
import {
  readManifest,
  verifyD1Owner,
  query,
  privateSnapshot,
  objectPath,
} from './deploy-resources.mjs';

const hash = (value, algorithm = 'sha256') => createHash(algorithm).update(value).digest('hex');
const MAX_VALUE_BYTES = 16 * 1024;
const OVERSIZED_VALUE = Symbol('unread oversized legacy value');
const OVERSIZED_REASON = 'legacy_value_exceeds_read_limit_value_fingerprint_unverified';
// This is provenance and deterministic import identity, not the current serving domain.
// Changing the public front door must never create a second logical legacy import.
export const LEGACY_MIGRATION_DOMAIN = 'test.gfw.mom';
const FINAL_BASELINE_KEY = 'final-migration-baseline-v1';
const FINAL_PROGRESS_KEY = 'final-migration-progress-v1';
const UUID = /^[a-f\d]{8}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{12}$/i;
const urlSafe = (value) => {
  if (
    typeof value !== 'string' ||
    Buffer.byteLength(value) > MAX_VALUE_BYTES ||
    /[\u0000-\u0020\u007f\\]/.test(value) ||
    /%(?![A-Fa-f0-9]{2})/.test(value) ||
    /[\ud800-\udfff]/u.test(value)
  )
    return false;
  const authority = /^https?:\/\/([^/?#]+)/i.exec(value);
  if (!authority || authority[1].includes('@')) return false;
  try {
    const u = new URL(value);
    return (
      ['http:', 'https:'].includes(u.protocol) && Boolean(u.hostname) && !u.username && !u.password
    );
  } catch {
    return false;
  }
};
export async function classifyLegacy(key, value, readValue) {
  if (key.startsWith('SYS_CONFIG_')) return { kind: 'skipped', reason: 'system_configuration' };
  if (value === OVERSIZED_VALUE) return { kind: 'unknown', reason: OVERSIZED_REASON };
  // A URL-valued 128-hex key is a real mapping; length alone never identifies an index.
  if (urlSafe(value))
    return isSafeLegacySlug(key)
      ? { kind: 'link', url: value }
      : { kind: 'unknown', reason: 'unsafe_or_reserved_legacy_slug_requires_review' };
  if (/^[a-f\d]{128}$/i.test(key)) {
    if (
      typeof value === 'string' &&
      /^[A-Za-z0-9_-]{1,512}$/.test(value) &&
      value.startsWith('SYS_CONFIG_')
    )
      return { kind: 'unknown', reason: 'hash_index_configuration_target_excluded' };
  }
  if (/^[a-f\d]{128}$/i.test(key) && isSafeLegacySlug(value)) {
    const target = await readValue(value);
    if (target === OVERSIZED_VALUE)
      return {
        kind: 'unknown',
        reason: 'hash_index_target_exceeds_read_limit_relationship_unverified',
      };
    if (urlSafe(target) && hash(target, 'sha512').toLowerCase() === key.toLowerCase())
      return { kind: 'skipped', reason: 'verified_sha512_reverse_index' };
    return { kind: 'unknown', reason: 'hash_index_relationship_unverified' };
  }
  return { kind: 'unknown', reason: 'unrecognized_legacy_value' };
}
function keyPath(key) {
  ensure(
    typeof key === 'string' &&
      key.length > 0 &&
      Buffer.byteLength(key) <= 512 &&
      !['.', '..'].includes(key) &&
      !/[\r\n\0]/.test(key),
    'LEGACY_KV_KEY_INVALID',
  );
  return `${ACCOUNT}/storage/kv/namespaces/${EXPECTED.LEGACY_KV_NAMESPACE_ID}/values/${encodeURIComponent(key).replace(/\./g, '%2E')}`;
}
export async function importLink(db, domain, key, value, metadata, now) {
  const deleted = (await db('SELECT slug FROM deleted_links WHERE slug=?', [key]))[0].results?.[0];
  if (deleted) return { status: 'skipped', reason: 'administrator_deleted_slug_never_reimported' };
  // Preserve the historical deterministic ID; slug occupancy is now global.
  const id = `legacy:${hash(`${domain}\0${key}`)}`;
  const created =
    Number.isSafeInteger(metadata?.createdAt) &&
    metadata.createdAt > 0 &&
    metadata.createdAt <= 8640000000000000
      ? metadata.createdAt
      : null;
  const inserted = await db(
    "INSERT INTO links (id,domain,slug,url,created_at,enabled,confirm_enabled,confirm_text,query_mode,source,creator) SELECT ?,?,?,?,?,1,0,'','preserve','migration','legacy-kv' WHERE NOT EXISTS (SELECT 1 FROM deleted_links WHERE slug=?) ON CONFLICT(slug) DO NOTHING",
    [id, domain, key, value, created, key],
  );
  const rows = await db('SELECT id,url,source,creator,created_at FROM links WHERE slug = ?', [key]);
  const row = rows[0].results?.[0];
  if (!row) {
    const removed = (await db('SELECT slug FROM deleted_links WHERE slug=?', [key]))[0]
      .results?.[0];
    if (removed)
      return { status: 'skipped', reason: 'administrator_deleted_slug_never_reimported' };
    fail('MIGRATED_ROW_READBACK_MISSING');
  }
  if (row.url !== value)
    return { status: 'conflict', reason: 'existing_mapping_differs_never_overwritten' };
  if (!isNewSlug(key) && row.source !== 'migration')
    return { status: 'conflict', reason: 'existing_mapping_source_not_routable_never_overwritten' };
  return {
    status: inserted[0].meta?.changes > 0 ? 'imported' : 'unchanged',
    reason:
      row.created_at === null
        ? 'mapping_verified_creation_time_unknown'
        : row.created_at === created
          ? 'mapping_and_creation_time_verified'
          : 'mapping_verified_existing_creation_time_preserved',
  };
}
async function saveItem(db, runId, keyHash, valueHash, status, reason, domain, key, now) {
  await db(
    'INSERT INTO legacy_migration_items (run_id,key_hash,value_hash,status,reason) VALUES (?,?,?,?,?) ON CONFLICT(run_id,key_hash,value_hash) DO NOTHING',
    [runId, keyHash, valueHash, status, reason],
  );
  // The administrator sees fingerprints and a safe reason; no Token/configuration gets imported.
  if (status !== 'unknown')
    await db(
      'INSERT INTO migration_records (source_key_hash,domain,slug,status,value_hash,reason,updated_at) VALUES (?,?,?,?,?,?,?) ON CONFLICT(source_key_hash) DO UPDATE SET status = excluded.status, value_hash = excluded.value_hash, reason = excluded.reason, updated_at = excluded.updated_at',
      [
        keyHash,
        domain,
        ['imported', 'unchanged', 'conflict'].includes(status) ? key : null,
        status,
        valueHash,
        reason,
        now,
      ],
    );
}
async function summarizeRun(db, runId, cursor, complete, now) {
  const total = (
    await db(
      "SELECT COUNT(*) AS processed, SUM(status='imported') AS imported, SUM(status='unchanged') AS unchanged, SUM(status='skipped') AS skipped, SUM(status='conflict') AS conflicts, SUM(status='unknown') AS unknown, SUM(reason=?) AS unverified_value_fingerprints FROM legacy_migration_items WHERE run_id = ?",
      [OVERSIZED_REASON, runId],
    )
  )[0].results[0];
  const aggregate = createHash('sha256');
  let after = '';
  let afterValue = '';
  for (;;) {
    const items = (
      await db(
        'SELECT key_hash,value_hash,status FROM legacy_migration_items WHERE run_id = ? AND (key_hash > ? OR (key_hash = ? AND value_hash > ?)) ORDER BY key_hash,value_hash LIMIT 500',
        [runId, after, after, afterValue],
      )
    )[0].results;
    if (!items.length) break;
    for (const item of items)
      aggregate.update(`${item.key_hash}\0${item.value_hash}\0${item.status}\n`);
    after = items.at(-1).key_hash;
    afterValue = items.at(-1).value_hash;
  }
  const digest = aggregate.digest('hex');
  await db(
    'UPDATE legacy_migration_runs SET cursor=?,state=?,processed=?,imported=?,unchanged=?,skipped=?,conflicts=?,unknown=?,digest=?,updated_at=?,completed_at=?,last_error_code=NULL,retry_at=NULL WHERE id=?',
    [
      cursor,
      complete ? 'complete' : 'running',
      total.processed || 0,
      total.imported || 0,
      total.unchanged || 0,
      total.skipped || 0,
      total.conflicts || 0,
      total.unknown || 0,
      digest,
      now,
      complete ? now : null,
      runId,
    ],
  );
  return {
    run_id: runId,
    state: complete ? 'complete' : 'running',
    processed_observations: total.processed || 0,
    imported: total.imported || 0,
    unchanged: total.unchanged || 0,
    skipped: total.skipped || 0,
    conflicts: total.conflicts || 0,
    unknown: total.unknown || 0,
    unverified_value_fingerprints: total.unverified_value_fingerprints || 0,
    verification_digest_sha256: digest,
    verification_digest_scope: total.unverified_value_fingerprints
      ? 'observations_including_unverified_value_markers'
      : 'hashed_observations',
  };
}
export async function migrate({
  client,
  manifest,
  resume = '',
  maxPages = 100,
  now = () => Date.now(),
  onPage = async () => true,
  initialRunId = '',
}) {
  ensure(
    Number.isInteger(maxPages) && maxPages >= 1 && maxPages <= 1000,
    'MIGRATION_PAGE_LIMIT_INVALID',
  );
  const domain = LEGACY_MIGRATION_DOMAIN;
  const db = (sql, params) => query(client, manifest.d1.id, sql, params);
  const registered = (
    await db('SELECT hostname,bound FROM domains WHERE hostname = ?', [domain])
  )[0].results?.[0];
  ensure(registered?.hostname === domain && registered.bound === 1, 'MIGRATION_DOMAIN_NOT_BOUND');
  ensure(!initialRunId || (!resume && UUID.test(initialRunId)), 'MIGRATION_RUN_ID_INVALID');
  let runId = resume || initialRunId || randomUUID();
  let cursor = '';
  if (resume) {
    ensure(/^[a-f\d-]{36}$/i.test(resume), 'MIGRATION_RUN_ID_INVALID');
    const run = (await db('SELECT * FROM legacy_migration_runs WHERE id = ?', [resume]))[0]
      .results?.[0];
    ensure(
      run &&
        run.namespace_id === EXPECTED.LEGACY_KV_NAMESPACE_ID &&
        run.domain === domain &&
        run.state !== 'complete',
      'MIGRATION_RUN_NOT_RESUMABLE',
    );
    cursor = run.cursor;
  } else
    await db(
      "INSERT INTO legacy_migration_runs (id,namespace_id,domain,cursor,state,digest,started_at,updated_at) VALUES (?,?,?,'','running','',?,?)",
      [runId, EXPECTED.LEGACY_KV_NAMESPACE_ID, domain, now(), now()],
    );
  const seenCursors = new Set([cursor]);
  let summary;
  const readValue = async (key) => {
    // Also covers indirect hash-index reads: excluded configuration must never be fetched.
    if (key.startsWith('SYS_CONFIG_')) return null;
    try {
      return await client.optional(keyPath(key), { raw: true, maxBytes: MAX_VALUE_BYTES });
    } catch (error) {
      // Only a successful KV-value response exceeding the read budget is reviewable data.
      // Authentication, rate limits, network failures and unreadable error responses stay fatal.
      if (
        error instanceof DeliveryError &&
        error.code === 'RESPONSE_TOO_LARGE' &&
        error.status >= 200 &&
        error.status < 300
      )
        return OVERSIZED_VALUE;
      throw error;
    }
  };
  for (let page = 0; page < maxPages; page++) {
    if (!(await onPage(runId))) break;
    const url = new URL(
      `https://api.cloudflare.com/client/v4${ACCOUNT}/storage/kv/namespaces/${EXPECTED.LEGACY_KV_NAMESPACE_ID}/keys`,
    );
    url.searchParams.set('limit', '100');
    if (cursor) url.searchParams.set('cursor', cursor);
    const list = await client.request(
      url.href.slice('https://api.cloudflare.com/client/v4'.length),
    );
    ensure(Array.isArray(list.result), 'LEGACY_KEY_LIST_INVALID');
    for (const k of list.result) {
      ensure(typeof k.name === 'string', 'LEGACY_KEY_LIST_INVALID');
      const keyHash = hash(k.name);
      const value = k.name.startsWith('SYS_CONFIG_') ? null : await readValue(k.name);
      // A domain-separated marker preserves replay identity without claiming an unread content hash.
      // Changes between oversized values cannot be distinguished within one run and remain unknown.
      const valueHash =
        value === OVERSIZED_VALUE
          ? hash(`legacy-migration/unread-value/v1\0${keyHash}\0${MAX_VALUE_BYTES}`)
          : hash(value === null ? '<system-or-missing>' : value);
      const seen =
        (
          await db(
            'SELECT status FROM legacy_migration_items WHERE run_id=? AND key_hash=? AND value_hash=?',
            [runId, keyHash, valueHash],
          )
        )[0].results || [];
      if (seen.length) continue; // Replaying a partially completed page cannot overwrite or double count.
      const classification = await classifyLegacy(k.name, value, readValue);
      const result =
        classification.kind === 'link'
          ? await importLink(db, domain, k.name, value, k.metadata, now())
          : { status: classification.kind, reason: classification.reason };
      await saveItem(
        db,
        runId,
        keyHash,
        valueHash,
        result.status,
        result.reason,
        domain,
        k.name,
        now(),
      );
    }
    const next = list.result_info?.cursor || '';
    if (next) {
      ensure(!seenCursors.has(next), 'LEGACY_CURSOR_REPEATED');
      seenCursors.add(next);
    }
    cursor = next;
    summary = await summarizeRun(db, runId, cursor, !cursor, now());
    if (!cursor) break;
  }
  if (!summary) summary = await summarizeRun(db, runId, cursor, false, now());
  return {
    ...summary,
    source: 'legacy KV reads only',
    destination: 'owned new D1 global short-code namespace',
    snapshot: false,
    production_cutover: false,
    next_action:
      summary.state !== 'complete'
        ? 'resume this run_id'
        : 'start another full scan for incremental additions/changes',
    fully_verified:
      summary.state === 'complete' && summary.conflicts === 0 && summary.unknown === 0,
  };
}
export function requireAutomaticMigration(env) {
  ensure(
    env.GITHUB_ACTIONS === 'true' &&
      env.GITHUB_REPOSITORY === REPOSITORY &&
      env.GITHUB_REF === 'refs/heads/main' &&
      ['schedule', 'workflow_dispatch'].includes(env.GITHUB_EVENT_NAME),
    'AUTOMATIC_MAIN_DATA_ACTION_REQUIRED',
  );
  if (env.GITHUB_EVENT_NAME === 'workflow_dispatch')
    ensure(
      env.CONFIRM_TARGET === 'automatically sync owned test D1 from read-only legacy KV',
      'TARGET_CONFIRMATION_REQUIRED',
    );
  for (const [key, value] of Object.entries(EXPECTED))
    ensure(env[key] === value, 'FIXED_TARGET_MISMATCH');
  ensure(
    typeof env.CLOUDFLARE_API_TOKEN === 'string' &&
      env.CLOUDFLARE_API_TOKEN.length > 0 &&
      !/\s/.test(env.CLOUDFLARE_API_TOKEN),
    'DEPLOY_CREDENTIAL_MISSING',
  );
}
export function migrationFailureCode(error) {
  if (error instanceof DeliveryError) {
    if (error.code === 'PERMISSION_DENIED' || error.status === 401 || error.status === 403)
      return 'MIGRATION_PERMISSION_DENIED';
    if (error.status === 404) return 'MIGRATION_RESOURCE_MISSING';
    if (error.code === 'NETWORK_OR_REDIRECT_BLOCKED') return 'MIGRATION_NETWORK_UNAVAILABLE';
    if (error.code === 'WRITE_RESULT_UNKNOWN_RECONCILE_REQUIRED')
      return 'MIGRATION_WRITE_RESULT_UNKNOWN';
    if (error.status === 429) return 'MIGRATION_RATE_LIMITED';
    if (error.status >= 500) return 'MIGRATION_PROVIDER_UNAVAILABLE';
    return /^[A-Z_]+$/.test(error.code) ? error.code : 'MIGRATION_FAILED';
  }
  return 'MIGRATION_FAILED';
}
// No resource/config/deployment writes exist in this task. The only allowed
// mutating API endpoint is the manifest-owned D1 query endpoint.
export function dataOnlyClient(client, id) {
  const target = `${ACCOUNT}/d1/database/${id}/query`;
  return {
    optional: (path, options = {}) => {
      ensure(!options.method || options.method === 'GET', 'AUTOMATIC_NON_DATA_WRITE_FORBIDDEN');
      return client.optional(path, options);
    },
    request: (path, options = {}) => {
      if (options.method && options.method !== 'GET')
        ensure(
          path === target && options.method === 'POST' && typeof options.json?.sql === 'string',
          'AUTOMATIC_NON_DATA_WRITE_FORBIDDEN',
        );
      return client.request(path, options);
    },
  };
}
export async function automaticMigrate({
  client,
  manifest,
  now = () => Date.now(),
  manualRetry = false,
  maxPages = 10,
  finalScan = false,
  resumeOverride = null,
  initialRunId = '',
  onRun = async () => {},
}) {
  if (finalScan)
    ensure(
      Number.isInteger(maxPages) && maxPages >= 1 && maxPages <= 10,
      'FINAL_MIGRATION_PAGE_LIMIT_INVALID',
    );
  const db = (sql, params = []) => query(client, manifest.d1.id, sql, params);
  const config = Object.fromEntries(
    (
      await db(
        "SELECT key,value FROM settings WHERE key IN ('migration_enabled','migration_interval_hours')",
      )
    )[0].results.map((row) => [row.key, row.value]),
  );
  ensure(
    ['0', '1'].includes(config.migration_enabled) &&
      /^\d+$/.test(config.migration_interval_hours) &&
      Number(config.migration_interval_hours) >= 1 &&
      Number(config.migration_interval_hours) <= 720,
    'MIGRATION_SCHEDULE_INVALID',
  );
  if (config.migration_enabled !== '1') return { state: 'paused', writes_performed: false };
  let lock = (await db("SELECT * FROM automation_locks WHERE name='legacy-migration'"))[0]
    .results?.[0];
  ensure(lock, 'MIGRATION_AUTOMATION_NOT_INITIALIZED');
  const latest =
    (
      await db("SELECT MAX(completed_at) AS time FROM legacy_migration_runs WHERE state='complete'")
    )[0].results?.[0]?.time ?? null;
  const resume =
    resumeOverride ??
    (
      await db(
        "SELECT id FROM legacy_migration_runs WHERE namespace_id=? AND domain=? AND state!='complete' ORDER BY started_at,id LIMIT 1",
        [EXPECTED.LEGACY_KV_NAMESPACE_ID, LEGACY_MIGRATION_DOMAIN],
      )
    )[0].results?.[0]?.id ??
    '';
  if (lock.lease_until > now()) return { state: 'locked', writes_performed: false };
  if (!manualRetry && ((lock.attempts >= 6 && lock.last_error_code) || lock.retry_at > now()))
    return {
      state: lock.attempts >= 6 ? 'failed' : 'retrying',
      error_code: lock.last_error_code,
      retry_at: lock.retry_at,
      writes_performed: false,
    };
  if (
    !finalScan &&
    !resume &&
    latest !== null &&
    now() < latest + Number(config.migration_interval_hours) * 3600000
  )
    return {
      state: 'not_due',
      next_due_at: latest + Number(config.migration_interval_hours) * 3600000,
      writes_performed: false,
    };
  let lease = Math.max(Math.abs(lock.lease_until) + 1, now() + 3600000);
  const claimed = await db(
    "UPDATE automation_locks SET lease_until=?,last_error_code=NULL,retry_at=NULL WHERE name='legacy-migration' AND lease_until=? RETURNING *",
    [lease, lock.lease_until],
  );
  if (!claimed[0].results?.length) return { state: 'locked', writes_performed: false };
  let runId = resume;
  try {
    const result = await migrate({
      client,
      manifest,
      resume,
      maxPages,
      initialRunId,
      now,
      onPage: async (id) => {
        runId = id;
        await onRun(id);
        const nextLease = Math.max(lease + 1, now() + 3600000);
        const renewed = (
          await db(
            "UPDATE automation_locks SET lease_until=?,run_id=? WHERE name='legacy-migration' AND lease_until=? AND lease_until>? RETURNING name",
            [nextLease, id, lease, now()],
          )
        )[0].results?.length;
        ensure(renewed, 'MIGRATION_LEASE_LOST');
        lease = nextLease;
        return (
          (await db("SELECT value FROM settings WHERE key='migration_enabled'"))[0].results?.[0]
            ?.value === '1'
        );
      },
    });
    await db(
      "UPDATE automation_locks SET run_id=?,last_success_at=CASE WHEN ?='complete' THEN ? ELSE last_success_at END,last_error_code=NULL,attempts=0,retry_at=NULL WHERE name='legacy-migration' AND lease_until=?",
      [result.run_id, result.state, now(), lease],
    );
    return {
      ...result,
      automatic: true,
      anomalies_require_review: result.conflicts + result.unknown,
    };
  } catch (error) {
    const code = migrationFailureCode(error),
      attempts = manualRetry ? 1 : lock.attempts + 1;
    const delay = ['MIGRATION_PERMISSION_DENIED', 'MIGRATION_RESOURCE_MISSING'].includes(code)
      ? 6 * 3600000
      : Math.min(6 * 3600000, 1800000 * 2 ** Math.min(attempts - 1, 6));
    const retry = attempts >= 6 ? null : now() + delay;
    await db(
      "UPDATE automation_locks SET run_id=?,last_error_code=?,attempts=?,retry_at=? WHERE name='legacy-migration' AND lease_until=?",
      [runId || null, code, attempts, retry, lease],
    );
    if (runId)
      await db(
        "UPDATE legacy_migration_runs SET state='failed',last_error_code=?,attempts=attempts+1,retry_at=?,updated_at=? WHERE id=? AND state!='complete' AND EXISTS (SELECT 1 FROM automation_locks WHERE name='legacy-migration' AND lease_until=? AND lease_until>?)",
        [code, retry, now(), runId, lease, now()],
      );
    throw error;
  } finally {
    await db(
      "UPDATE automation_locks SET lease_until=-ABS(lease_until) WHERE name='legacy-migration' AND lease_until=?",
      [lease],
    );
  }
}
export async function automaticMain(env = process.env) {
  requireAutomaticMigration(env);
  const base = createCFClient(env.CLOUDFLARE_API_TOKEN, { allowWrites: true });
  await verifyAccount(base);
  const manifest = await readManifest(base);
  ensure(manifest?.d1, 'RESOURCE_BOOTSTRAP_REQUIRED');
  const client = dataOnlyClient(base, manifest.d1.id);
  await verifyD1Owner(client, manifest);
  const result = await automaticMigrate({
    client,
    manifest,
    manualRetry: env.GITHUB_EVENT_NAME === 'workflow_dispatch',
  });
  console.log(JSON.stringify(result));
}
async function readFinalCheckpoint(client, manifest, key) {
  ensure(
    [FINAL_BASELINE_KEY, FINAL_PROGRESS_KEY].includes(key),
    'FINAL_MIGRATION_CHECKPOINT_INVALID',
  );
  const raw = await client.optional(objectPath(`delivery/${manifest.owner_id}/${key}.json`), {
    raw: true,
  });
  if (raw === null) return null;
  let saved;
  try {
    saved = JSON.parse(raw);
  } catch {
    fail('FINAL_MIGRATION_CHECKPOINT_INVALID');
  }
  ensure(
    saved?.owner_id === manifest.owner_id &&
      saved.database_id === manifest.d1.id &&
      saved.namespace_id === EXPECTED.LEGACY_KV_NAMESPACE_ID &&
      saved.domain === LEGACY_MIGRATION_DOMAIN,
    'FINAL_MIGRATION_CHECKPOINT_OWNERSHIP_UNPROVEN',
  );
  ensure(saved.schema === 1, 'FINAL_MIGRATION_CHECKPOINT_INVALID');
  if (key === FINAL_BASELINE_KEY)
    ensure(
      Number.isSafeInteger(saved.stopped_at) &&
        saved.stopped_at > 0 &&
        /^[a-z0-9-]+$/.test(saved.shutdown_checkpoint_key) &&
        /^[a-f\d]{64}$/.test(saved.shutdown_sha256) &&
        Array.isArray(saved.observations) &&
        saved.observations.every(
          (row) =>
            /^[a-f\d]{64}$/.test(row.key_hash) &&
            /^[a-f\d]{64}$/.test(row.value_hash) &&
            ['unknown', 'conflict'].includes(row.status) &&
            typeof row.reason === 'string',
        ),
      'FINAL_MIGRATION_BASELINE_INVALID',
    );
  else
    ensure(
      UUID.test(saved.final_run_id) &&
        Number.isSafeInteger(saved.created_at) &&
        saved.created_at >= saved.stopped_at,
      'FINAL_MIGRATION_CHECKPOINT_INVALID',
    );
  return saved;
}
const anomalyIdentity = (row) => `${row.key_hash}\0${row.value_hash}\0${row.status}\0${row.reason}`;
export async function prepareFinalMigration(
  client,
  manifest,
  { stoppedAt, shutdownEvidence, now = Date.now } = {},
) {
  await verifyD1Owner(client, manifest);
  const existing = await readFinalCheckpoint(client, manifest, FINAL_BASELINE_KEY);
  if (existing)
    return {
      checkpointKey: FINAL_BASELINE_KEY,
      stopped_at: existing.stopped_at,
      baseline: existing.counts,
    };
  ensure(
    Number.isSafeInteger(stoppedAt) &&
      stoppedAt > 0 &&
      stoppedAt <= now() &&
      shutdownEvidence?.legacy_entrypoints_stopped === true &&
      typeof shutdownEvidence.checkpoint_key === 'string' &&
      /^[a-z0-9-]+$/.test(shutdownEvidence.checkpoint_key),
    'LEGACY_INGRESS_SHUTDOWN_PROOF_REQUIRED',
  );
  const ingressRaw = await client.optional(
    objectPath(`delivery/${manifest.owner_id}/${shutdownEvidence.checkpoint_key}.json`),
    { raw: true },
  );
  ensure(ingressRaw !== null, 'LEGACY_INGRESS_SHUTDOWN_PROOF_REQUIRED');
  let ingress;
  try {
    ingress = JSON.parse(ingressRaw);
  } catch {
    fail('LEGACY_INGRESS_SHUTDOWN_PROOF_INVALID');
  }
  ensure(
    ingress.owner_id === manifest.owner_id &&
      ingress.legacy_entrypoints_stopped === true &&
      ingress.stopped_at === stoppedAt,
    'LEGACY_INGRESS_SHUTDOWN_PROOF_INVALID',
  );
  const rows = (
    await query(
      client,
      manifest.d1.id,
      "SELECT DISTINCT i.key_hash,i.value_hash,i.status,i.reason FROM legacy_migration_items i JOIN legacy_migration_runs r ON r.id=i.run_id WHERE r.namespace_id=? AND r.domain=? AND r.started_at<=? AND i.status IN ('unknown','conflict') ORDER BY i.key_hash,i.value_hash,i.status,i.reason",
      [EXPECTED.LEGACY_KV_NAMESPACE_ID, LEGACY_MIGRATION_DOMAIN, stoppedAt],
    )
  )[0].results;
  ensure(
    rows.every(
      (row) =>
        /^[a-f\d]{64}$/.test(row.key_hash) &&
        /^[a-f\d]{64}$/.test(row.value_hash) &&
        typeof row.reason === 'string',
    ),
    'FINAL_MIGRATION_BASELINE_INVALID',
  );
  const unread = new Set(
    rows.filter((row) => row.reason === OVERSIZED_REASON).map((row) => row.key_hash),
  );
  const abnormal = new Set(
    rows.filter((row) => row.reason !== OVERSIZED_REASON).map((row) => row.key_hash),
  );
  // The owner accepted these existing identities only. This maximum cannot
  // make a newly observed error part of the immutable waiver after scanning starts.
  ensure(abnormal.size <= 18 && unread.size <= 2, 'FINAL_MIGRATION_BASELINE_EXCEEDS_OWNER_WAIVER');
  const saved = {
    schema: 1,
    owner_id: manifest.owner_id,
    database_id: manifest.d1.id,
    namespace_id: EXPECTED.LEGACY_KV_NAMESPACE_ID,
    domain: LEGACY_MIGRATION_DOMAIN,
    stopped_at: stoppedAt,
    captured_at: now(),
    shutdown_checkpoint_key: shutdownEvidence.checkpoint_key,
    shutdown_sha256: hash(ingressRaw),
    counts: { abnormal: abnormal.size, unread: unread.size, observations: rows.length },
    observations: rows,
  };
  await privateSnapshot(client, manifest, FINAL_BASELINE_KEY, saved, { preserveExisting: true });
  const readback = await readFinalCheckpoint(client, manifest, FINAL_BASELINE_KEY);
  ensure(
    readback?.shutdown_sha256 === saved.shutdown_sha256 &&
      JSON.stringify(readback.observations) === JSON.stringify(rows),
    'FINAL_MIGRATION_BASELINE_DRIFT',
  );
  return { checkpointKey: FINAL_BASELINE_KEY, stopped_at: stoppedAt, baseline: saved.counts };
}
export async function readFinalMigrationResult(
  client,
  manifest,
  { checkpointKey = FINAL_BASELINE_KEY, now = Date.now } = {},
) {
  const baseline = await readFinalCheckpoint(client, manifest, checkpointKey);
  const progress = await readFinalCheckpoint(client, manifest, FINAL_PROGRESS_KEY);
  ensure(baseline && progress && UUID.test(progress.final_run_id), 'FINAL_MIGRATION_NOT_STARTED');
  const run = (
    await query(client, manifest.d1.id, 'SELECT * FROM legacy_migration_runs WHERE id=?', [
      progress.final_run_id,
    ])
  )[0].results?.[0];
  ensure(
    run &&
      run.namespace_id === baseline.namespace_id &&
      run.domain === baseline.domain &&
      run.started_at >= baseline.stopped_at,
    'FINAL_MIGRATION_RUN_UNPROVEN',
  );
  const observations = (
    await query(
      client,
      manifest.d1.id,
      "SELECT key_hash,value_hash,status,reason FROM legacy_migration_items WHERE run_id=? AND status IN ('unknown','conflict') ORDER BY key_hash,value_hash,status,reason",
      [run.id],
    )
  )[0].results;
  const accepted = new Set(baseline.observations.map(anomalyIdentity));
  const known = observations.filter((row) => accepted.has(anomalyIdentity(row)));
  const fresh = observations.filter((row) => !accepted.has(anomalyIdentity(row)));
  const lock = (
    await query(
      client,
      manifest.d1.id,
      "SELECT run_id,lease_until,last_error_code FROM automation_locks WHERE name='legacy-migration'",
    )
  )[0].results?.[0];
  ensure(lock, 'MIGRATION_AUTOMATION_NOT_INITIALIZED');
  return {
    run_id: run.id,
    domain: run.domain,
    namespace_id: run.namespace_id,
    state: run.state,
    cursor_present: Boolean(run.cursor),
    started_at: run.started_at,
    completed_at: run.completed_at,
    attempts: run.attempts,
    retry_at: run.retry_at,
    last_error_code: run.last_error_code,
    processed_observations: run.processed,
    imported: run.imported,
    unchanged: run.unchanged,
    skipped: run.skipped,
    conflicts: run.conflicts,
    unknown: run.unknown,
    verification_digest_sha256: run.digest,
    unverified_value_fingerprints: observations.filter((row) => row.reason === OVERSIZED_REASON)
      .length,
    known_waived_observations: known.length,
    known_waived_abnormal: known.filter((row) => row.reason !== OVERSIZED_REASON).length,
    known_waived_unread: known.filter((row) => row.reason === OVERSIZED_REASON).length,
    new_anomalies: fresh.length,
    lease_released: lock.lease_until <= 0 && lock.run_id === run.id,
    lease_active: lock.lease_until > now(),
    lease_expires_at: lock.lease_until > 0 ? lock.lease_until : null,
    lease_run_id: lock.run_id,
    final_scan_complete:
      run.state === 'complete' &&
      !run.cursor &&
      Number.isSafeInteger(run.completed_at) &&
      run.completed_at >= baseline.stopped_at,
    fully_verified: run.state === 'complete' && run.conflicts === 0 && run.unknown === 0,
    owner_accepted_existing_exceptions: true,
    checkpoint_key: checkpointKey,
  };
}
export async function finalMigrate({
  client,
  manifest,
  checkpointKey = FINAL_BASELINE_KEY,
  now = Date.now,
  maxPages = 10,
}) {
  await verifyD1Owner(client, manifest);
  const baseline = await readFinalCheckpoint(client, manifest, checkpointKey);
  ensure(baseline, 'FINAL_MIGRATION_BASELINE_REQUIRED');
  const ingressRaw = await client.optional(
    objectPath(`delivery/${manifest.owner_id}/${baseline.shutdown_checkpoint_key}.json`),
    { raw: true },
  );
  ensure(
    ingressRaw !== null && hash(ingressRaw) === baseline.shutdown_sha256,
    'LEGACY_INGRESS_SHUTDOWN_PROOF_DRIFT',
  );
  let progress = await readFinalCheckpoint(client, manifest, FINAL_PROGRESS_KEY);
  if (!progress) {
    const pending = (
      await query(
        client,
        manifest.d1.id,
        "SELECT id FROM legacy_migration_runs WHERE namespace_id=? AND domain=? AND state!='complete' ORDER BY started_at,id LIMIT 1",
        [EXPECTED.LEGACY_KV_NAMESPACE_ID, LEGACY_MIGRATION_DOMAIN],
      )
    )[0].results?.[0];
    if (pending) {
      const result = await automaticMigrate({
        client,
        manifest,
        now,
        manualRetry: true,
        finalScan: true,
        resumeOverride: pending.id,
        maxPages,
      });
      const run = (
        await query(
          client,
          manifest.d1.id,
          'SELECT id,namespace_id,domain,state,cursor,started_at,completed_at,processed,imported,unchanged,skipped,conflicts,unknown,last_error_code FROM legacy_migration_runs WHERE id=?',
          [pending.id],
        )
      )[0].results?.[0];
      ensure(
        run?.namespace_id === EXPECTED.LEGACY_KV_NAMESPACE_ID &&
          run.domain === LEGACY_MIGRATION_DOMAIN,
        'MIGRATION_RUN_READBACK_UNPROVEN',
      );
      const lock = (
        await query(
          client,
          manifest.d1.id,
          "SELECT run_id,lease_until FROM automation_locks WHERE name='legacy-migration'",
        )
      )[0].results?.[0];
      ensure(lock, 'MIGRATION_AUTOMATION_NOT_INITIALIZED');
      return {
        ...result,
        run_id: run.id,
        run_state: run.state,
        cursor_present: Boolean(run.cursor),
        started_at: run.started_at,
        completed_at: run.completed_at,
        processed_observations: run.processed,
        imported: run.imported,
        unchanged: run.unchanged,
        skipped: run.skipped,
        conflicts: run.conflicts,
        unknown: run.unknown,
        last_error_code: run.last_error_code,
        lease_released: lock.lease_until <= 0 && lock.run_id === run.id,
        lease_active: lock.lease_until > now(),
        lease_expires_at: lock.lease_until > 0 ? lock.lease_until : null,
        lease_run_id: lock.run_id,
        phase: 'draining_existing_run',
        final_scan_complete: false,
        next_action:
          result.state === 'paused'
            ? 'review the disabled migration setting; no scan was forced'
            : result.state === 'locked'
              ? 'wait for the current lease and review shared Cloudflare Actions before continuing'
              : run.state === 'complete'
                ? 'dispatch final scan again to start a complete post-shutdown scan'
                : 'resume this exact existing run_id with the same bounded page budget',
      };
    }
    progress = {
      schema: 1,
      owner_id: manifest.owner_id,
      database_id: manifest.d1.id,
      namespace_id: EXPECTED.LEGACY_KV_NAMESPACE_ID,
      domain: LEGACY_MIGRATION_DOMAIN,
      final_run_id: randomUUID(),
      stopped_at: baseline.stopped_at,
      created_at: now(),
    };
    await privateSnapshot(client, manifest, FINAL_PROGRESS_KEY, progress, {
      preserveExisting: true,
    });
    progress = await readFinalCheckpoint(client, manifest, FINAL_PROGRESS_KEY);
  }
  ensure(UUID.test(progress.final_run_id), 'FINAL_MIGRATION_CHECKPOINT_INVALID');
  const existing = (
    await query(client, manifest.d1.id, 'SELECT state FROM legacy_migration_runs WHERE id=?', [
      progress.final_run_id,
    ])
  )[0].results?.[0];
  if (existing?.state !== 'complete') {
    const result = await automaticMigrate({
      client,
      manifest,
      now,
      manualRetry: true,
      finalScan: true,
      maxPages,
      resumeOverride: existing ? progress.final_run_id : '',
      initialRunId: existing ? '' : progress.final_run_id,
    });
    if (!result.run_id) {
      const lock = (
        await query(
          client,
          manifest.d1.id,
          "SELECT run_id,lease_until FROM automation_locks WHERE name='legacy-migration'",
        )
      )[0].results?.[0];
      ensure(lock, 'MIGRATION_AUTOMATION_NOT_INITIALIZED');
      return {
        ...result,
        planned_run_id: progress.final_run_id,
        lease_active: lock.lease_until > now(),
        lease_expires_at: lock.lease_until > 0 ? lock.lease_until : null,
        lease_run_id: lock.run_id,
        phase: 'final_scan',
        final_scan_complete: false,
        next_action:
          result.state === 'paused'
            ? 'review the disabled migration setting; no scan was forced'
            : 'wait for the current lease and review shared Cloudflare Actions before continuing',
      };
    }
  }
  const result = await readFinalMigrationResult(client, manifest, { checkpointKey, now });
  await privateSnapshot(client, manifest, `final-migration-result-${result.run_id}`, result);
  return {
    ...result,
    phase: 'final_scan',
    next_action:
      result.new_anomalies > 0
        ? 'review the newly observed anomalies; existing owner waivers do not cover them'
        : !result.lease_released
          ? 'review the actual lease checkpoint before backup or synchronization shutdown'
          : result.final_scan_complete
            ? 'verify a fresh backup containing this run, then disable legacy synchronization'
            : 'resume this exact run_id with the same bounded page budget',
  };
}
export async function disableLegacySync({
  client,
  manifest,
  checkpointKey = FINAL_BASELINE_KEY,
  backupProof,
  now = Date.now,
}) {
  await verifyD1Owner(client, manifest);
  const result = await readFinalMigrationResult(client, manifest, { checkpointKey, now });
  ensure(
    result.final_scan_complete && result.lease_released && result.new_anomalies === 0,
    'FINAL_MIGRATION_INCOMPLETE_OR_NEW_ANOMALIES',
  );
  ensure(
    backupProof?.final_run_id === result.run_id &&
      backupProof.final_digest === result.verification_digest_sha256 &&
      backupProof.private_object_read_and_verified === true &&
      UUID.test(backupProof.backup_id),
    'FINAL_MIGRATION_BACKUP_REQUIRED',
  );
  const backupRaw = await client.optional(
    objectPath(
      `delivery/${manifest.owner_id}/final-migration-backup-${backupProof.backup_id}.json`,
    ),
    { raw: true },
  );
  let savedBackup;
  try {
    savedBackup = JSON.parse(backupRaw);
  } catch {
    fail('FINAL_MIGRATION_BACKUP_REQUIRED');
  }
  ensure(
    savedBackup?.owner_id === manifest.owner_id &&
      savedBackup.database_id === manifest.d1.id &&
      savedBackup.backup_id === backupProof.backup_id &&
      savedBackup.final_run_id === result.run_id &&
      savedBackup.final_digest === result.verification_digest_sha256 &&
      savedBackup.sha256 === backupProof.sha256 &&
      savedBackup.contains_final_increment === true &&
      savedBackup.private_object_read_and_verified === true,
    'FINAL_MIGRATION_BACKUP_CHECKPOINT_UNPROVEN',
  );
  await query(
    client,
    manifest.d1.id,
    "UPDATE settings SET value='0' WHERE key='migration_enabled' AND EXISTS(SELECT 1 FROM legacy_migration_runs WHERE id=? AND state='complete' AND cursor='') AND NOT EXISTS(SELECT 1 FROM automation_locks WHERE name='legacy-migration' AND lease_until>?) AND NOT EXISTS(SELECT 1 FROM legacy_migration_runs WHERE namespace_id=? AND domain=? AND state!='complete')",
    [result.run_id, 0, EXPECTED.LEGACY_KV_NAMESPACE_ID, LEGACY_MIGRATION_DOMAIN],
  );
  const setting = (
    await query(client, manifest.d1.id, "SELECT value FROM settings WHERE key='migration_enabled'")
  )[0].results?.[0];
  ensure(setting?.value === '0', 'MIGRATION_DISABLE_READBACK_FAILED');
  const stopped = {
    ...result,
    migration_enabled: '0',
    backup_id: backupProof.backup_id,
    disabled_at: now(),
  };
  await privateSnapshot(client, manifest, 'legacy-sync-disabled-v1', stopped, {
    preserveExisting: true,
  });
  return stopped;
}
export async function main(env = process.env) {
  requireAction(env, 'read old KV and migrate owned test D1 only');
  const client = createCFClient(env.CLOUDFLARE_API_TOKEN, { allowWrites: true });
  await verifyAccount(client);
  const manifest = await readManifest(client);
  ensure(manifest?.d1, 'RESOURCE_BOOTSTRAP_REQUIRED');
  await verifyD1Owner(client, manifest);
  const result = await migrate({
    client,
    manifest,
    resume: env.MIGRATION_RESUME_RUN || '',
    maxPages: Number(env.MIGRATION_MAX_PAGES || 100),
  });
  await privateSnapshot(client, manifest, `migration-${result.run_id}`, result);
  console.log(JSON.stringify(result)); // Fingerprint totals only; no KV keys, URLs, SQL or credential output/artifacts.
  if (!result.fully_verified) process.exitCode = 2;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (process.env.MIGRATION_AUTOMATIC === 'true') await automaticMain();
    else await main();
  } catch (e) {
    console.error(JSON.stringify(safeError(e)));
    process.exitCode = 1;
  }
}
