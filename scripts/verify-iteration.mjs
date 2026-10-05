#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import {
  ACCOUNT,
  EXPECTED,
  OWNER_KEY,
  DeliveryError,
  ensure,
  requireAction,
  createCFClient,
  safeError,
} from './cf-client.mjs';
import {
  objectPath,
  readManifest,
  query,
  verifyD1Owner,
  inspectWorker,
} from './deploy-resources.mjs';

export const CONFIRMATION = 'verify shortlink-new test iteration read only';
export const MAX_BYTES = 32 * 1024 * 1024;
const UUID = /^[a-f\d]{8}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{12}$/i;
export const SELECTS = {
  owner: 'SELECT project, owner_id, account_id, worker FROM delivery_ownership WHERE singleton = 1',
  schema:
    "SELECT type,name FROM sqlite_master WHERE (type='index' AND name='links_global_slug') OR (type='table' AND name IN ('deleted_links','automation_locks')) ORDER BY name",
  settings:
    "SELECT key,value FROM settings WHERE key IN ('backup_enabled','backup_interval_hours','backup_retention_days','analytics_retention_days','audit_retention_days','migration_enabled','migration_interval_hours') ORDER BY key",
  counts:
    "SELECT (SELECT COUNT(*) FROM links) AS links,(SELECT COUNT(*) FROM deleted_links) AS tombstones,(SELECT COUNT(*) FROM domains WHERE bound=1 AND enabled=1 AND binding_state='verified') AS active_domains,(SELECT COUNT(*) FROM legacy_migration_runs) AS migration_runs,(SELECT COUNT(*) FROM legacy_migration_items) AS migration_observations,(SELECT COUNT(*) FROM backup_jobs WHERE status='complete' AND retired_at IS NULL) AS retained_complete_backups",
  migration:
    "SELECT id,state,processed,imported,unchanged,skipped,conflicts,unknown,started_at,updated_at,completed_at,attempts,retry_at,last_error_code,CASE WHEN cursor<>'' THEN 1 ELSE 0 END AS cursor_present FROM legacy_migration_runs ORDER BY started_at DESC,id DESC LIMIT 1",
  automation:
    "SELECT lease_until,last_success_at,attempts,retry_at,last_error_code FROM automation_locks WHERE name='legacy-migration'",
  scheduled:
    "SELECT b.id,b.created_at,b.status,b.completed_at,b.attempts,b.retry_at,b.last_error_code FROM backup_jobs b JOIN audit a ON a.entity_id=b.id AND a.action='backup.create' AND a.actor='system:scheduled' WHERE b.retired_at IS NULL ORDER BY b.created_at DESC,b.id DESC LIMIT 1",
  completed:
    "SELECT b.id,b.created_at,b.status,b.completed_at,b.size,b.records,b.snapshot_digest,b.object_digest,CASE WHEN a.actor='system:scheduled' THEN 'system:scheduled' ELSE 'administrator' END AS actor FROM backup_jobs b LEFT JOIN audit a ON a.entity_id=b.id AND a.action='backup.create' WHERE b.status='complete' AND b.retired_at IS NULL AND b.snapshot_digest IS NOT NULL AND b.object_digest IS NOT NULL ORDER BY b.completed_at DESC,b.id DESC LIMIT 1",
};
const SQL = new Set(Object.values(SELECTS));
const TABLES = new Set([
  'domains',
  'links',
  'tokens',
  'token_domains',
  'settings',
  'audit',
  'daily_stats',
  'migration_records',
  'delivery_ownership',
  'legacy_migration_runs',
  'legacy_migration_items',
  'deleted_links',
  'automation_locks',
]);
const sha = (value) => createHash('sha256').update(value).digest('hex');
const count = (value) => {
  ensure(Number.isSafeInteger(value) && value >= 0, 'ITERATION_RESPONSE_INVALID');
  return value;
};
const time = (value) => (value === null ? null : count(value));
const code = (value) => {
  ensure(
    value === null || (typeof value === 'string' && /^[A-Z_]{1,100}$/.test(value)),
    'ITERATION_RESPONSE_INVALID',
  );
  return value;
};

export function readClient(token, fetcher = fetch) {
  const base = createCFClient(token, { fetcher, allowWrites: true });
  let database = null,
    backup = null;
  const request = async (path, options = {}) => {
    const method = options.method || 'GET';
    const manifest = path === objectPath(OWNER_KEY) && method === 'GET';
    const resource =
      database &&
      method === 'GET' &&
      (path === `${ACCOUNT}/d1/database/${database}` ||
        path === `${ACCOUNT}/workers/scripts/${EXPECTED.WORKER_NAME}/settings`);
    const select =
      database &&
      path === `${ACCOUNT}/d1/database/${database}/query` &&
      method === 'POST' &&
      SQL.has(options.json?.sql) &&
      Array.isArray(options.json?.params) &&
      options.json.params.length === 0 &&
      Object.keys(options.json).length === 2;
    const metadata =
      backup &&
      method === 'GET' &&
      path ===
        `${ACCOUNT}/r2/buckets/shortlink-new-backups/objects?prefix=${encodeURIComponent(`backups/${backup}.ndjson`)}&per_page=2`;
    const object = backup && method === 'GET' && path === objectPath(`backups/${backup}.ndjson`);
    ensure(manifest || resource || select || metadata || object, 'ITERATION_READ_SCOPE_FORBIDDEN');
    return base.request(path, {
      ...options,
      maxBytes: object ? MAX_BYTES : manifest ? 256 * 1024 : 64 * 1024,
    });
  };
  return {
    request,
    optional: async (path, options) => {
      try {
        return await request(path, options);
      } catch (error) {
        if (error instanceof DeliveryError && error.code === 'NOT_FOUND') return null;
        throw error;
      }
    },
    bindD1: (id) => {
      ensure(UUID.test(id), 'D1_OWNERSHIP_UNPROVEN');
      database = id;
    },
    bindBackup: (id) => {
      ensure(UUID.test(id), 'ITERATION_BACKUP_ID_INVALID');
      backup = id;
    },
  };
}

export function verifyBackupBytes(raw, job, manifest) {
  ensure(typeof raw === 'string' && raw.endsWith('\n'), 'ITERATION_BACKUP_FORMAT_INVALID');
  const bytes = Buffer.from(raw, 'utf8');
  ensure(
    bytes.length === job.size && bytes.length > 0 && bytes.length <= MAX_BYTES,
    'ITERATION_BACKUP_SIZE_MISMATCH',
  );
  const fingerprints = [];
  for (let offset = 0; offset < bytes.length; offset += 5 * 1024 * 1024) {
    const part = bytes.subarray(offset, offset + 5 * 1024 * 1024);
    fingerprints.push(`${part.length}:${sha(part)}\n`);
  }
  const digest = sha(fingerprints.join(''));
  ensure(
    /^[a-f0-9]{64}$/.test(job.snapshot_digest) &&
      job.snapshot_digest === job.object_digest &&
      job.object_digest === digest,
    'ITERATION_BACKUP_DIGEST_MISMATCH',
  );
  const lines = raw.slice(0, -1).split('\n'),
    counts = {},
    owners = [],
    slugs = new Set(),
    deleted = new Set();
  ensure(lines.length === job.records, 'ITERATION_BACKUP_RECORDS_MISMATCH');
  for (const line of lines) {
    let row;
    try {
      row = JSON.parse(line);
    } catch {
      ensure(false, 'ITERATION_BACKUP_FORMAT_INVALID');
    }
    ensure(
      row &&
        TABLES.has(row.table) &&
        row.data &&
        typeof row.data === 'object' &&
        !Array.isArray(row.data) &&
        Object.values(row.data).every(
          (value) =>
            value === null ||
            typeof value === 'string' ||
            (typeof value === 'number' && Number.isFinite(value)),
        ),
      'ITERATION_BACKUP_SCHEMA_INVALID',
    );
    counts[row.table] = (counts[row.table] || 0) + 1;
    if (row.table === 'delivery_ownership') owners.push(row.data);
    if (row.table === 'links') {
      ensure(
        typeof row.data.id === 'string' &&
          typeof row.data.slug === 'string' &&
          typeof row.data.url === 'string' &&
          !slugs.has(row.data.slug),
        'ITERATION_BACKUP_LINK_INVALID',
      );
      slugs.add(row.data.slug);
    }
    if (row.table === 'deleted_links') {
      ensure(
        typeof row.data.slug === 'string' && !Object.hasOwn(row.data, 'url'),
        'ITERATION_BACKUP_TOMBSTONE_INVALID',
      );
      deleted.add(row.data.slug);
    }
  }
  ensure(
    owners.length === 1 &&
      owners[0].singleton === 1 &&
      owners[0].project === manifest.project &&
      owners[0].owner_id === manifest.owner_id &&
      owners[0].account_id === manifest.account &&
      owners[0].worker === manifest.worker,
    'ITERATION_BACKUP_OWNER_MISMATCH',
  );
  ensure(
    counts.automation_locks === 1 &&
      counts.domains >= 1 &&
      counts.settings >= 1 &&
      [...deleted].every((slug) => !slugs.has(slug)),
    'ITERATION_BACKUP_SCHEMA_INVALID',
  );
  return {
    size: bytes.length,
    records: lines.length,
    table_counts: counts,
    sha256: sha(bytes),
    digest_algorithm: 'sha256-chunk-manifest-v1',
    snapshot_digest: digest,
    object_digest: digest,
    bytes_verified: true,
    owner_verified: true,
    global_shortcodes_verified: true,
    cloud_restore_executed: false,
  };
}

export async function main(
  args = process.argv.slice(2),
  env = process.env,
  { fetcher = fetch, now = () => Date.now() } = {},
) {
  ensure(args.length === 0, 'ITERATION_ARGUMENTS_FORBIDDEN');
  requireAction(env, CONFIRMATION);
  const client = readClient(env.CLOUDFLARE_API_TOKEN, fetcher),
    manifest = await readManifest(client);
  ensure(manifest?.d1, 'BOOTSTRAP_REQUIRED');
  client.bindD1(manifest.d1.id);
  await verifyD1Owner(client, manifest);
  ensure(await inspectWorker(client, manifest), 'OWNED_WORKER_MISSING');
  const select = async (sql) => (await query(client, manifest.d1.id, sql))[0].results;
  const schema = await select(SELECTS.schema);
  ensure(
    schema.length === 3 &&
      schema.some((row) => row.name === 'links_global_slug') &&
      schema.some((row) => row.name === 'deleted_links') &&
      schema.some((row) => row.name === 'automation_locks'),
    'ITERATION_SCHEMA_NOT_UPGRADED',
  );
  const settingsRows = await select(SELECTS.settings);
  const settingKeys = [
    'backup_enabled',
    'backup_interval_hours',
    'backup_retention_days',
    'analytics_retention_days',
    'audit_retention_days',
    'migration_enabled',
    'migration_interval_hours',
  ];
  ensure(
    settingsRows.length === settingKeys.length &&
      new Set(settingsRows.map((row) => row.key)).size === settingKeys.length &&
      settingsRows.every((row) => settingKeys.includes(row.key)),
    'ITERATION_SETTINGS_INVALID',
  );
  const settings = Object.fromEntries(settingsRows.map((row) => [row.key, row.value]));
  for (const key of ['backup_enabled', 'migration_enabled'])
    ensure(['0', '1'].includes(settings[key]), 'ITERATION_SETTINGS_INVALID');
  for (const key of ['backup_interval_hours', 'migration_interval_hours'])
    ensure(
      /^\d+$/.test(settings[key]) && Number(settings[key]) >= 1 && Number(settings[key]) <= 720,
      'ITERATION_SETTINGS_INVALID',
    );
  for (const key of ['backup_retention_days', 'analytics_retention_days', 'audit_retention_days'])
    ensure(
      /^\d+$/.test(settings[key]) && Number(settings[key]) <= 3650,
      'ITERATION_SETTINGS_INVALID',
    );
  const totals = (await select(SELECTS.counts))[0];
  ensure(totals, 'ITERATION_RESPONSE_INVALID');
  const counters = Object.fromEntries(
    [
      'links',
      'tombstones',
      'active_domains',
      'migration_runs',
      'migration_observations',
      'retained_complete_backups',
    ].map((key) => [key, count(totals[key])]),
  );
  const migrate = (await select(SELECTS.migration))[0],
    lock = (await select(SELECTS.automation))[0];
  ensure(lock, 'ITERATION_RESPONSE_INVALID');
  let migration = null;
  if (migrate) {
    ensure(
      UUID.test(migrate.id) &&
        ['running', 'complete', 'failed'].includes(migrate.state) &&
        [0, 1].includes(migrate.cursor_present),
      'ITERATION_RESPONSE_INVALID',
    );
    migration = {
      id: migrate.id,
      state: migrate.state,
      cursor_present: !!migrate.cursor_present,
      last_error_code: code(migrate.last_error_code),
    };
    for (const key of [
      'processed',
      'imported',
      'unchanged',
      'skipped',
      'conflicts',
      'unknown',
      'attempts',
    ])
      migration[key] = count(migrate[key]);
    for (const key of ['started_at', 'updated_at', 'completed_at', 'retry_at'])
      migration[key] = time(migrate[key]);
  }
  const automation = {
    last_success_at: time(lock.last_success_at),
    attempts: count(lock.attempts),
    retry_at: time(lock.retry_at),
    last_error_code: code(lock.last_error_code),
    lease_active: lock.lease_until > now(),
  };
  const scheduled = (await select(SELECTS.scheduled))[0],
    job = (await select(SELECTS.completed))[0];
  let scheduledBackup = null,
    backup = null;
  if (scheduled) {
    ensure(
      UUID.test(scheduled.id) &&
        ['pending', 'uploading', 'complete', 'failed'].includes(scheduled.status),
      'ITERATION_RESPONSE_INVALID',
    );
    scheduledBackup = {
      id: scheduled.id,
      status: scheduled.status,
      created_at: time(scheduled.created_at),
      completed_at: time(scheduled.completed_at),
      attempts: count(scheduled.attempts),
      retry_at: time(scheduled.retry_at),
      last_error_code: code(scheduled.last_error_code),
      actor: 'system:scheduled',
    };
  }
  if (job) {
    ensure(
      UUID.test(job.id) &&
        job.status === 'complete' &&
        job.completed_at >= job.created_at &&
        job.completed_at <= now() &&
        ['system:scheduled', 'administrator'].includes(job.actor),
      'ITERATION_BACKUP_JOB_INVALID',
    );
    count(job.records);
    count(job.size);
    ensure(job.size > 0 && job.size <= MAX_BYTES, 'ITERATION_BACKUP_SIZE_MISMATCH');
    client.bindBackup(job.id);
    const path = `${ACCOUNT}/r2/buckets/shortlink-new-backups/objects?prefix=${encodeURIComponent(`backups/${job.id}.ndjson`)}&per_page=2`;
    const metadata = await client.request(path);
    ensure(
      Array.isArray(metadata.result) && metadata.result_info?.is_truncated !== true,
      'ITERATION_BACKUP_METADATA_MISMATCH',
    );
    const objects = metadata.result.filter((row) => row.key === `backups/${job.id}.ndjson`);
    ensure(
      objects.length === 1 &&
        objects[0].size === job.size &&
        typeof objects[0].etag === 'string' &&
        objects[0].etag.length > 0 &&
        objects[0].custom_metadata?.created_at === String(job.created_at) &&
        objects[0].custom_metadata?.schema_version === '1' &&
        objects[0].custom_metadata?.consistency === 'atomic-d1-snapshot',
      'ITERATION_BACKUP_METADATA_MISMATCH',
    );
    const raw = await client.request(objectPath(`backups/${job.id}.ndjson`), { raw: true });
    backup = {
      id: job.id,
      created_at: time(job.created_at),
      completed_at: time(job.completed_at),
      actor: job.actor,
      metadata_verified: true,
      ...verifyBackupBytes(raw, job, manifest),
    };
  }
  const automaticVerified = !!(
    backup &&
    scheduledBackup &&
    backup.id === scheduledBackup.id &&
    backup.actor === 'system:scheduled'
  );
  return {
    checked_at: new Date(now()).toISOString(),
    read_only: true,
    ownership_verified: true,
    schema_verified: true,
    settings,
    counters,
    migration,
    automation,
    scheduled_backup: scheduledBackup,
    completed_backup: backup,
    automatic_backup_verified: automaticVerified,
    exit_code: automaticVerified ? 0 : 2,
  };
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const report = await main();
    console.log(JSON.stringify(report));
    process.exitCode = report.exit_code;
  } catch (error) {
    console.error(JSON.stringify(safeError(error)));
    process.exitCode = 1;
  }
}
