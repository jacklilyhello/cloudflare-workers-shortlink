import type { Env } from './types';

export const SETTING_DEFAULTS: Record<string, string> = {
  anonymous_rate_per_minute: '10',
  domain_rate_per_minute: '120',
  analytics_retention_days: '90',
  audit_retention_days: '365',
  backup_retention_days: '30',
  backup_interval_hours: '24',
  error_403: '没有访问权限',
  error_404: '找不到这个链接',
  error_disabled: '这个链接已停用或过期',
  error_500: '服务暂时不可用，请稍后再试',
};
export async function settings(env: Env): Promise<Record<string, string>> {
  const result = await env.DB.prepare('SELECT key,value FROM settings').all<{
    key: string;
    value: string;
  }>();
  return {
    ...SETTING_DEFAULTS,
    ...Object.fromEntries(result.results.map((r) => [r.key, r.value])),
  };
}
export function auditStatement(
  env: Env,
  actor: string,
  action: string,
  entity: string,
  detail: object = {},
) {
  // Audit data never contains target URLs, token plaintext, access JWTs, or raw IPs.
  return env.DB.prepare(
    'INSERT INTO audit(id,actor,action,entity_id,detail,created_at) VALUES(?,?,?,?,?,?)',
  ).bind(crypto.randomUUID(), actor, action, entity, JSON.stringify(detail), Date.now());
}
const SNAPSHOT_TABLES: Record<string, string[]> = {
  domains: ['hostname', 'enabled', 'bound', 'created_at'],
  links: [
    'id',
    'domain',
    'slug',
    'url',
    'created_at',
    'expires_at',
    'enabled',
    'confirm_enabled',
    'confirm_text',
    'query_mode',
    'source',
    'creator',
    'token_id',
    'idempotency_key',
    'request_hash',
  ],
  tokens: ['id', 'label', 'digest', 'created_at', 'expires_at', 'revoked_at', 'rate_per_minute'],
  token_domains: ['token_id', 'domain'],
  settings: ['key', 'value'],
  audit: ['id', 'actor', 'action', 'entity_id', 'detail', 'created_at'],
  daily_stats: ['day', 'domain', 'slug', 'country', 'device', 'referrer', 'count'],
  migration_records: [
    'source_key_hash',
    'domain',
    'slug',
    'status',
    'value_hash',
    'reason',
    'updated_at',
  ],
  delivery_ownership: ['singleton', 'project', 'owner_id', 'account_id', 'worker', 'created_at'],
  legacy_migration_runs: [
    'id',
    'namespace_id',
    'domain',
    'cursor',
    'state',
    'processed',
    'imported',
    'unchanged',
    'skipped',
    'conflicts',
    'unknown',
    'digest',
    'started_at',
    'updated_at',
  ],
  legacy_migration_items: ['run_id', 'key_hash', 'value_hash', 'status', 'reason'],
};
export async function startBackup(env: Env, actor: string): Promise<string> {
  if (!env.BACKUPS) throw new Error('BACKUP_NOT_CONFIGURED');
  // D1 batch is one transaction. Concurrent changes cannot split this snapshot.
  const active = await env.DB.prepare(
    "SELECT id FROM backup_jobs WHERE status IN ('pending','uploading') LIMIT 1",
  ).first<{ id: string }>();
  if (active) return active.id;
  const id = crypto.randomUUID();
  const statements = [
    env.DB.prepare("INSERT INTO backup_jobs(id,created_at,status) VALUES(?,?,'pending')").bind(
      id,
      Date.now(),
    ),
    auditStatement(env, actor, 'backup.create', id),
  ];
  for (const [table, fields] of Object.entries(SNAPSHOT_TABLES)) {
    const pairs = fields.map((f) => `'${f}',${f}`).join(',');
    statements.push(
      env.DB.prepare(
        `INSERT INTO backup_rows(backup_id,payload) SELECT ?,json_object('table','${table}','data',json_object(${pairs})) FROM ${table}`,
      ).bind(id),
    );
  }
  try {
    await env.DB.batch(statements);
  } catch (error) {
    const winner = await env.DB.prepare(
      "SELECT id FROM backup_jobs WHERE status IN ('pending','uploading') LIMIT 1",
    ).first<{ id: string }>();
    if (winner) return winner.id;
    throw error;
  }
  return id;
}
interface BackupJob {
  id: string;
  created_at: number;
  status: string;
  upload_id: string | null;
  upload_started_at: number | null;
  after_row: number;
  row_offset: number;
  part_number: number;
  parts: string;
  size: number;
  records: number;
  lease_until: number;
}
class BackupLeaseLost extends Error {}
const BACKUP_LEASE_MS = 120000;
export async function advanceBackup(env: Env): Promise<void> {
  if (!env.BACKUPS) return;
  const bucket = env.BACKUPS;
  const job = await env.DB.prepare(
    "UPDATE backup_jobs SET lease_until=MAX(ABS(lease_until)+1,?) WHERE id=(SELECT id FROM backup_jobs WHERE status IN ('pending','uploading') ORDER BY created_at LIMIT 1) AND lease_until<? RETURNING *",
  )
    .bind(Date.now() + BACKUP_LEASE_MS, Date.now())
    .first<BackupJob>();
  if (!job) return;
  let lease = job.lease_until;
  const active = "status IN ('pending','uploading')";
  const renew = async () => {
    const time = Date.now();
    const owned = await env.DB.prepare(
      `UPDATE backup_jobs SET lease_until=MAX(lease_until+1,?) WHERE id=? AND lease_until=? AND lease_until>? AND ${active} RETURNING lease_until`,
    )
      .bind(time + BACKUP_LEASE_MS, job.id, lease, time)
      .first<{ lease_until: number }>();
    if (!owned) throw new BackupLeaseLost();
    lease = owned.lease_until;
  };
  const commit = async (sql: string, values: unknown[]) => {
    const result = await env.DB.prepare(
      `${sql} WHERE id=? AND lease_until=? AND lease_until>? AND ${active}`,
    )
      .bind(...values, job.id, lease, Date.now())
      .run();
    if (result.meta.changes !== 1) throw new BackupLeaseLost();
  };
  const snapshotTotals = async () => {
    const totals = await env.DB.prepare(
      'SELECT COUNT(*) AS records,COALESCE(SUM(length(CAST(payload AS BLOB))+1),0) AS size FROM backup_rows WHERE backup_id=?',
    )
      .bind(job.id)
      .first<{ records: number; size: number }>();
    await renew();
    if (!totals || !totals.records) throw new Error('BACKUP_SNAPSHOT_MISSING');
    return totals;
  };
  const finish = async (object: R2Object) => {
    const totals = await snapshotTotals();
    if (
      object.customMetadata?.created_at !== String(job.created_at) ||
      object.customMetadata.consistency !== 'atomic-d1-snapshot' ||
      object.customMetadata.schema_version !== '1' ||
      object.size !== totals.size
    )
      throw new Error('BACKUP_OBJECT_MISMATCH');
    const time = Date.now();
    // Both statements share one D1 transaction. Cleanup requires this exact
    // lease's successful status change, so a stale HEAD result cannot delete rows.
    const results = await env.DB.batch([
      env.DB.prepare(
        `UPDATE backup_jobs SET status='complete',completed_at=?,size=?,records=? WHERE id=? AND lease_until=? AND lease_until>? AND ${active}`,
      ).bind(time, totals.size, totals.records, job.id, lease, time),
      env.DB.prepare(
        "DELETE FROM backup_rows WHERE backup_id=? AND changes()=1 AND EXISTS (SELECT 1 FROM backup_jobs WHERE id=? AND lease_until=? AND status='complete')",
      ).bind(job.id, job.id, lease),
    ]);
    if (results[0].meta.changes !== 1) throw new BackupLeaseLost();
  };
  const resetUpload = async (upload: R2MultipartUpload) => {
    await renew();
    // Detach under the lease before aborting. A later owner can only create a
    // different upload ID; this abort can never target that owner's new session.
    await commit(
      'UPDATE backup_jobs SET upload_id=NULL,upload_started_at=NULL,after_row=0,row_offset=0,part_number=1,parts=?,size=0,records=0',
      ['[]'],
    );
    job.upload_id = null;
    job.after_row = 0;
    job.row_offset = 0;
    job.part_number = 1;
    job.parts = '[]';
    job.size = 0;
    job.records = 0;
    await renew();
    await upload.abort().catch(() => undefined);
    await renew();
  };
  try {
    const key = `backups/${job.id}.ndjson`;
    await renew();
    const existing = await bucket.head(key);
    await renew();
    if (existing) {
      await finish(existing);
      return;
    }
    let upload: R2MultipartUpload;
    // R2 expires unfinished uploads after seven days. Retain the atomic snapshot
    // and restart before that deadline instead of leaving a permanently stuck job.
    if (
      job.upload_id &&
      job.upload_started_at &&
      Date.now() - job.upload_started_at > 6 * 86400000
    ) {
      await resetUpload(bucket.resumeMultipartUpload(key, job.upload_id));
    }
    if (!job.upload_id) {
      await renew();
      upload = await bucket.createMultipartUpload(key, {
        httpMetadata: { contentType: 'application/x-ndjson' },
        customMetadata: {
          schema_version: '1',
          created_at: String(job.created_at),
          consistency: 'atomic-d1-snapshot',
        },
      });
      // If creation returns after lease loss, stop all R2 writes. Its unattached
      // upload expires automatically; ambiguous attachment results stay recoverable.
      await renew();
      await commit("UPDATE backup_jobs SET upload_id=?,upload_started_at=?,status='uploading'", [
        upload.uploadId,
        Date.now(),
      ]);
      job.upload_id = upload.uploadId;
    } else upload = bucket.resumeMultipartUpload(key, job.upload_id);
    const parts: R2UploadedPart[] = JSON.parse(job.parts);
    const encoder = new TextEncoder();
    let cursor = job.after_row,
      rowOffset = job.row_offset,
      bytes = 0,
      count = 0,
      complete = false;
    const chunks: Uint8Array[] = [];
    // A single invocation uploads one 5 MiB part, with bounded memory and DB reads.
    for (let page = 0; page < 100 && bytes < 5 * 1024 * 1024; page++) {
      const rows = await env.DB.prepare(
        'SELECT id,payload FROM backup_rows WHERE backup_id=? AND id>? ORDER BY id LIMIT 500',
      )
        .bind(job.id, cursor)
        .all<{ id: number; payload: string }>();
      if (!rows.results.length) {
        complete = true;
        break;
      }
      for (const row of rows.results) {
        const whole = encoder.encode(`${row.payload}\n`);
        const data = whole.subarray(
          rowOffset,
          rowOffset + Math.min(whole.length - rowOffset, 5 * 1024 * 1024 - bytes),
        );
        chunks.push(data);
        bytes += data.length;
        if (rowOffset + data.length === whole.length) {
          cursor = row.id;
          count++;
          rowOffset = 0;
        } else rowOffset += data.length;
        if (bytes >= 5 * 1024 * 1024) break;
      }
    }
    if (bytes < 5 * 1024 * 1024 && !complete) return;
    if (bytes) {
      const body = new Uint8Array(bytes);
      let offset = 0;
      for (const chunk of chunks) {
        body.set(chunk, offset);
        offset += chunk.length;
      }
      await renew();
      const part = await upload.uploadPart(job.part_number, body);
      await renew();
      parts.push(part);
      // Reuploading the same part after a checkpoint failure is safe; no row is skipped.
      await commit(
        'UPDATE backup_jobs SET after_row=?,row_offset=?,part_number=?,parts=?,size=?,records=?',
        [
          cursor,
          rowOffset,
          job.part_number + 1,
          JSON.stringify(parts),
          job.size + bytes,
          job.records + count,
        ],
      );
    }
    if (complete) {
      await renew();
      try {
        await upload.complete(parts);
      } catch {
        await renew();
        const completed = await bucket.head(key);
        await renew();
        if (completed) await finish(completed);
        else await resetUpload(upload);
        return;
      }
      await renew();
      const completed = await bucket.head(key);
      await renew();
      if (!completed) throw new Error('BACKUP_OBJECT_MISSING');
      await finish(completed);
    }
  } catch (error) {
    if (error instanceof BackupLeaseLost) return;
    // An in-flight R2 call can fail after another owner completes or replaces its
    // session. Its stale caller must not turn that winner's success into failure.
    const owned = await env.DB.prepare(
      `SELECT id FROM backup_jobs WHERE id=? AND lease_until=? AND lease_until>? AND ${active}`,
    )
      .bind(job.id, lease, Date.now())
      .first();
    if (owned) throw error;
  } finally {
    // A negative deadline releases the lease but preserves its generation, even
    // when two invocations start in the same millisecond.
    await env.DB.prepare(
      'UPDATE backup_jobs SET lease_until=-ABS(lease_until) WHERE id=? AND lease_until=?',
    )
      .bind(job.id, lease)
      .run();
  }
}
export async function maintenance(env: Env): Promise<void> {
  const config = await settings(env);
  await advanceBackup(env);
  const latest = await env.DB.prepare('SELECT MAX(created_at) AS time FROM backup_jobs').first<{
    time: number | null;
  }>();
  if (!latest?.time || Date.now() - latest.time >= Number(config.backup_interval_hours) * 3600000) {
    await startBackup(env, 'system:scheduled');
    await advanceBackup(env);
  }
  const now = Date.now();
  // Retention only applies to aggregate statistics, audit, rate windows and this
  // project's private backup prefix. Link mappings, token history and slugs survive.
  await env.DB.batch([
    env.DB.prepare('DELETE FROM daily_stats WHERE day<?').bind(
      new Date(now - Number(config.analytics_retention_days) * 86400000).toISOString().slice(0, 10),
    ),
    env.DB.prepare('DELETE FROM audit WHERE created_at<?').bind(
      now - Number(config.audit_retention_days) * 86400000,
    ),
    env.DB.prepare('DELETE FROM rate_windows WHERE window<?').bind(Math.floor(now / 60000) - 10),
  ]);
  const cutoff = now - Number(config.backup_retention_days) * 86400000;
  const expired = await env.DB.prepare(
    "SELECT id FROM backup_jobs WHERE status='complete' AND (retired_at IS NOT NULL OR created_at<?) ORDER BY retention_checked_at,created_at,id LIMIT 20",
  )
    .bind(cutoff)
    .all<{ id: string }>();
  let retentionFailed = false;
  for (const row of expired.results) {
    // Keep a minimal hidden marker: a late multipart completion can recreate this
    // exact key after deletion. Rotate rechecks so no retired key loses tracking.
    const retired = await env.DB.prepare(
      "UPDATE backup_jobs SET retired_at=COALESCE(retired_at,?),retention_checked_at=?,upload_id=NULL,upload_started_at=NULL,after_row=0,row_offset=0,part_number=1,parts='[]',size=0,records=0,lease_until=0 WHERE id=? AND status='complete' AND (retired_at IS NOT NULL OR created_at<?)",
    )
      .bind(now, now, row.id, cutoff)
      .run();
    if (retired.meta.changes !== 1) continue;
    try {
      if (!env.BACKUPS) throw new Error('BACKUP_NOT_CONFIGURED');
      await env.BACKUPS.delete(`backups/${row.id}.ndjson`);
    } catch {
      // The marker survives failure, and its attempt time allows the next keys
      // to progress before this exact key is retried in a later rotation.
      retentionFailed = true;
    }
  }
  if (retentionFailed) throw new Error('BACKUP_RETENTION_RETRY_REQUIRED');
}
