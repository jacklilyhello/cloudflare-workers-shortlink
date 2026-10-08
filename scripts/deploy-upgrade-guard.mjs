import { createHash } from 'node:crypto';
import { ACCOUNT, BUCKET, ensure } from './cf-client.mjs';
import { objectPath, privateSnapshot, query } from './deploy-resources.mjs';
import { verifyBackupBytes } from './verify-iteration.mjs';

const SNAPSHOT_TABLES = new Set([
  'domains',
  'tokens',
  'token_domains',
  'links',
  'settings',
  'audit',
  'daily_stats',
  'migration_records',
  'legacy_migration_runs',
  'legacy_migration_items',
  'delivery_ownership',
  'deleted_links',
  'automation_locks',
]);
const UUID = /^[a-f\d]{8}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{12}$/i;
const MAX_BYTES = 64 * 1024 * 1024;
export function validateUpgradeBackup(raw, job, manifest) {
  ensure(
    typeof raw === 'string' && Buffer.byteLength(raw) === job.size && raw.endsWith('\n'),
    'PRE_UPGRADE_BACKUP_SIZE_MISMATCH',
  );
  const lines = raw.slice(0, -1).split('\n');
  ensure(
    lines.length === job.records && lines.every(Boolean),
    'PRE_UPGRADE_BACKUP_RECORDS_MISMATCH',
  );
  let linkRecords = 0;
  const owners = [];
  const slugs = new Set();
  for (const line of lines) {
    let row;
    try {
      row = JSON.parse(line);
    } catch {
      ensure(false, 'PRE_UPGRADE_BACKUP_INVALID_JSON');
    }
    ensure(
      row &&
        SNAPSHOT_TABLES.has(row.table) &&
        row.data &&
        typeof row.data === 'object' &&
        !Array.isArray(row.data),
      'PRE_UPGRADE_BACKUP_SCHEMA_UNREVIEWED',
    );
    if (row.table === 'links') {
      ensure(
        typeof row.data.id === 'string' &&
          typeof row.data.slug === 'string' &&
          typeof row.data.url === 'string',
        'PRE_UPGRADE_BACKUP_LINK_INVALID',
      );
      ensure(!slugs.has(row.data.slug), 'GLOBAL_SHORTCODE_CONFLICT_PRESERVED');
      slugs.add(row.data.slug);
      linkRecords++;
    }
    if (row.table === 'delivery_ownership') owners.push(row.data);
  }
  ensure(
    owners.length === 1 &&
      owners[0].singleton === 1 &&
      owners[0].owner_id === manifest.owner_id &&
      owners[0].account_id === manifest.account &&
      owners[0].worker === manifest.worker &&
      owners[0].project === manifest.project,
    'PRE_UPGRADE_BACKUP_OWNERSHIP_UNPROVEN',
  );
  ensure(linkRecords > 0, 'PRE_UPGRADE_BACKUP_LINKS_MISSING');
  return {
    sha256: createHash('sha256').update(raw).digest('hex'),
    records: lines.length,
    link_records: linkRecords,
    size: job.size,
  };
}
export async function verifyGlobalUpgradeBackup(
  client,
  manifest,
  { now = Date.now, finalResult = null } = {},
) {
  if (finalResult) return verifyFinalMigrationBackup(client, manifest, { now, finalResult });
  const schema = await query(
    client,
    manifest.d1.id,
    "SELECT type,name FROM sqlite_master WHERE (type='index' AND name='links_global_slug') OR (type='table' AND name='links')",
  );
  if (schema[0].results.some((r) => r.name === 'links_global_slug'))
    return { required: false, global_namespace_already_upgraded: true };
  if (!schema[0].results.some((r) => r.name === 'links'))
    return { required: false, empty_initial_database: true };
  const count = await query(client, manifest.d1.id, 'SELECT COUNT(*) AS count FROM links');
  if (count[0].results[0].count === 0) return { required: false, no_existing_mappings: true };
  const conflicts = await query(
    client,
    manifest.d1.id,
    'SELECT COUNT(*) AS count FROM (SELECT slug FROM links GROUP BY slug COLLATE BINARY HAVING COUNT(*)>1)',
  );
  ensure(conflicts[0].results[0].count === 0, 'GLOBAL_SHORTCODE_CONFLICT_PRESERVED');
  const jobs = await query(
    client,
    manifest.d1.id,
    "SELECT id,created_at,completed_at,size,records FROM backup_jobs WHERE status='complete' AND retired_at IS NULL ORDER BY completed_at DESC LIMIT 1",
  );
  const job = jobs[0].results[0];
  const time = now();
  ensure(
    job &&
      UUID.test(job.id) &&
      Number.isSafeInteger(job.created_at) &&
      Number.isSafeInteger(job.completed_at) &&
      job.completed_at >= job.created_at &&
      job.created_at >= time - 86400000 &&
      job.completed_at <= time &&
      Number.isSafeInteger(job.size) &&
      job.size > 0 &&
      job.size <= MAX_BYTES &&
      Number.isSafeInteger(job.records) &&
      job.records > 0,
    'PRE_UPGRADE_RECENT_COMPLETE_BACKUP_REQUIRED',
  );
  const objectKey = `backups/${job.id}.ndjson`;
  const metadata = await client.request(
    `${ACCOUNT}/r2/buckets/${BUCKET}/objects?prefix=${encodeURIComponent(objectKey)}&per_page=2`,
  );
  const objects = Array.isArray(metadata.result)
    ? metadata.result.filter((o) => o.key === objectKey)
    : [];
  ensure(
    metadata.result_info?.is_truncated !== true &&
      objects.length === 1 &&
      objects[0].size === job.size &&
      typeof objects[0].etag === 'string' &&
      objects[0].etag.length > 0 &&
      objects[0].custom_metadata?.created_at === String(job.created_at) &&
      objects[0].custom_metadata?.schema_version === '1' &&
      objects[0].custom_metadata?.consistency === 'atomic-d1-snapshot',
    'PRE_UPGRADE_BACKUP_METADATA_MISMATCH',
  );
  const raw = await client.request(objectPath(`backups/${job.id}.ndjson`), {
    raw: true,
    maxBytes: MAX_BYTES,
  });
  const proof = validateUpgradeBackup(raw, job, manifest);
  ensure(
    proof.link_records === count[0].results[0].count,
    'PRE_UPGRADE_BACKUP_MAPPING_COUNT_DRIFT',
  );
  const key = `pre-global-upgrade-backup-${job.id}`;
  const existing = await client.optional(objectPath(`delivery/${manifest.owner_id}/${key}.json`), {
    raw: true,
  });
  if (existing !== null) {
    let saved;
    try {
      saved = JSON.parse(existing);
    } catch {
      ensure(false, 'PRE_UPGRADE_BACKUP_CHECKPOINT_INVALID');
    }
    ensure(
      saved.owner_id === manifest.owner_id &&
        saved.database_id === manifest.d1.id &&
        saved.backup_id === job.id &&
        saved.sha256 === proof.sha256 &&
        saved.size === proof.size &&
        saved.records === proof.records,
      'PRE_UPGRADE_BACKUP_CHECKPOINT_DRIFT',
    );
  } else {
    await privateSnapshot(
      client,
      manifest,
      key,
      {
        owner_id: manifest.owner_id,
        database_id: manifest.d1.id,
        backup_id: job.id,
        created_at: job.created_at,
        completed_at: job.completed_at,
        checked_at: time,
        ...proof,
      },
      { preserveExisting: true },
    );
  }
  return {
    required: true,
    backup_id: job.id,
    ...proof,
    private_object_read_and_verified: true,
    original_checkpoint_preserved: true,
    object_metadata_verified: true,
  };
}
export async function verifyFinalMigrationBackup(
  client,
  manifest,
  { now = Date.now, finalResult, backupId = '' } = {},
) {
  ensure(
    finalResult?.final_scan_complete === true &&
      finalResult.lease_released === true &&
      UUID.test(finalResult.run_id) &&
      Number.isSafeInteger(finalResult.completed_at) &&
      /^[a-f\d]{64}$/.test(finalResult.verification_digest_sha256),
    'FINAL_MIGRATION_COMPLETE_PROOF_REQUIRED',
  );
  ensure(!backupId || UUID.test(backupId), 'FINAL_BACKUP_ID_INVALID');
  const jobs = await query(
    client,
    manifest.d1.id,
    "SELECT id,created_at,completed_at,size,records,snapshot_digest,object_digest FROM backup_jobs WHERE status='complete' AND retired_at IS NULL AND created_at>=? AND (?='' OR id=?) ORDER BY completed_at DESC,id DESC LIMIT 1",
    [finalResult.completed_at, backupId, backupId],
  );
  const job = jobs[0].results?.[0];
  ensure(
    job &&
      UUID.test(job.id) &&
      Number.isSafeInteger(job.created_at) &&
      job.created_at >= finalResult.completed_at &&
      Number.isSafeInteger(job.completed_at) &&
      job.completed_at >= job.created_at &&
      job.completed_at <= now() &&
      Number.isSafeInteger(job.size) &&
      job.size > 0 &&
      job.size <= 32 * 1024 * 1024 &&
      Number.isSafeInteger(job.records) &&
      job.records > 0,
    'FINAL_MIGRATION_FRESH_COMPLETE_BACKUP_REQUIRED',
  );
  const objectKey = `backups/${job.id}.ndjson`;
  const metadata = await client.request(
    `${ACCOUNT}/r2/buckets/${BUCKET}/objects?prefix=${encodeURIComponent(objectKey)}&per_page=2`,
  );
  const objects = Array.isArray(metadata.result)
    ? metadata.result.filter((row) => row.key === objectKey)
    : [];
  ensure(
    metadata.result_info?.is_truncated !== true &&
      objects.length === 1 &&
      objects[0].size === job.size &&
      typeof objects[0].etag === 'string' &&
      objects[0].etag.length > 0 &&
      objects[0].custom_metadata?.created_at === String(job.created_at) &&
      objects[0].custom_metadata?.schema_version === '1' &&
      objects[0].custom_metadata?.consistency === 'atomic-d1-snapshot',
    'FINAL_BACKUP_METADATA_MISMATCH',
  );
  const raw = await client.request(objectPath(objectKey), {
    raw: true,
    maxBytes: 32 * 1024 * 1024,
  });
  const proof = verifyBackupBytes(raw, job, manifest);
  const rows = raw
    .slice(0, -1)
    .split('\n')
    .map((line) => JSON.parse(line));
  const runs = rows
    .filter((row) => row.table === 'legacy_migration_runs' && row.data.id === finalResult.run_id)
    .map((row) => row.data);
  ensure(
    runs.length === 1 &&
      runs[0].state === 'complete' &&
      runs[0].cursor === '' &&
      runs[0].digest === finalResult.verification_digest_sha256 &&
      runs[0].completed_at === finalResult.completed_at &&
      runs[0].processed === finalResult.processed_observations &&
      runs[0].namespace_id === finalResult.namespace_id &&
      runs[0].domain === finalResult.domain,
    'FINAL_BACKUP_MIGRATION_RUN_MISMATCH',
  );
  const items = rows
    .filter(
      (row) => row.table === 'legacy_migration_items' && row.data.run_id === finalResult.run_id,
    )
    .map((row) => row.data);
  items.sort((a, b) =>
    a.key_hash < b.key_hash
      ? -1
      : a.key_hash > b.key_hash
        ? 1
        : a.value_hash < b.value_hash
          ? -1
          : a.value_hash > b.value_hash
            ? 1
            : 0,
  );
  const digest = createHash('sha256');
  for (const item of items) digest.update(`${item.key_hash}\0${item.value_hash}\0${item.status}\n`);
  ensure(
    items.length === finalResult.processed_observations &&
      digest.digest('hex') === finalResult.verification_digest_sha256,
    'FINAL_BACKUP_MIGRATION_OBSERVATIONS_MISMATCH',
  );
  const links = new Map(
    rows
      .filter((row) => row.table === 'links')
      .map((row) => [createHash('sha256').update(row.data.slug).digest('hex'), row.data]),
  );
  const deleted = new Set(
    rows
      .filter((row) => row.table === 'deleted_links')
      .map((row) => createHash('sha256').update(row.data.slug).digest('hex')),
  );
  for (const item of items.filter((row) => ['imported', 'unchanged'].includes(row.status))) {
    const link = links.get(item.key_hash);
    ensure(
      (link && createHash('sha256').update(link.url).digest('hex') === item.value_hash) ||
        deleted.has(item.key_hash),
      'FINAL_BACKUP_IMPORTED_MAPPING_MISSING',
    );
  }
  const saved = {
    owner_id: manifest.owner_id,
    database_id: manifest.d1.id,
    backup_id: job.id,
    object_key: objectKey,
    object_etag: objects[0].etag,
    created_at: job.created_at,
    completed_at: job.completed_at,
    final_run_id: finalResult.run_id,
    final_digest: finalResult.verification_digest_sha256,
    final_observations: items.length,
    checked_at: now(),
    ...proof,
    private_object_read_and_verified: true,
    contains_final_increment: true,
    cloud_restore_executed: false,
  };
  await privateSnapshot(client, manifest, `final-migration-backup-${job.id}`, saved, {
    preserveExisting: true,
  });
  return saved;
}
