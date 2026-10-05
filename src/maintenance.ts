import type { Env } from './types';

export const SETTING_DEFAULTS: Record<string, string> = {
  anonymous_rate_per_minute: '10',
  domain_rate_per_minute: '120',
  analytics_retention_days: '90',
  audit_retention_days: '365',
  backup_retention_days: '30',
  backup_interval_hours: '24',
  backup_enabled: '1',
  migration_enabled: '1',
  migration_interval_hours: '24',
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
  domains: [
    'hostname',
    'enabled',
    'bound',
    'created_at',
    'binding_state',
    'last_verified_at',
    'binding_error',
    'last_checked_at',
  ],
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
    'completed_at',
    'attempts',
    'last_error_code',
    'retry_at',
  ],
  legacy_migration_items: ['run_id', 'key_hash', 'value_hash', 'status', 'reason'],
  deleted_links: [
    'slug',
    'link_id',
    'deleted_at',
    'token_id',
    'domain',
    'idempotency_key',
    'request_hash',
  ],
  automation_locks: [
    'name',
    'lease_until',
    'run_id',
    'last_success_at',
    'last_error_code',
    'attempts',
    'retry_at',
  ],
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
  attempts: number;
  verification_part: number;
}
class BackupLeaseLost extends Error {}
const BACKUP_LEASE_MS = 120000;
async function sha256(value: BufferSource): Promise<string> {
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', value)), (byte) =>
    byte.toString(16).padStart(2, '0'),
  ).join('');
}

export async function getBackupStatus(env: Env) {
  const config = await settings(env);
  const active = await env.DB.prepare(
    "SELECT status,attempts,retry_at,last_error_code FROM backup_jobs WHERE status IN ('pending','uploading') ORDER BY created_at LIMIT 1",
  ).first<{
    status: string;
    attempts: number;
    retry_at: number | null;
    last_error_code: string | null;
  }>();
  const last = await env.DB.prepare(
    "SELECT MAX(completed_at) AS time FROM backup_jobs WHERE status='complete'",
  ).first<{ time: number | null }>();
  const failed = await env.DB.prepare(
    "SELECT last_error_code,attempts,COALESCE(last_attempt_at,created_at) AS time FROM backup_jobs WHERE status='failed' AND COALESCE(last_attempt_at,created_at)>? ORDER BY COALESCE(last_attempt_at,created_at) DESC LIMIT 1",
  )
    .bind(last?.time ?? 0)
    .first<{ last_error_code: string | null; attempts: number; time: number }>();
  const retention = await env.DB.prepare(
    'SELECT retention_last_error,retention_attempts,retention_retry_at FROM backup_jobs WHERE retired_at IS NOT NULL AND retention_last_error IS NOT NULL ORDER BY retention_retry_at,retention_checked_at DESC LIMIT 1',
  ).first<{
    retention_last_error: string;
    retention_attempts: number;
    retention_retry_at: number | null;
  }>();
  const enabled = config.backup_enabled === '1';
  const recentFailure = active ? null : failed;
  const failureCode =
    active?.last_error_code ??
    retention?.retention_last_error ??
    recentFailure?.last_error_code ??
    (recentFailure ? 'BACKUP_TASK_FAILED' : null);
  const normalDue = (last?.time ?? 0) + Number(config.backup_interval_hours) * 3600000;
  const backupDue = active
    ? Math.max(Date.now(), active.retry_at ?? Date.now())
    : Math.max(Date.now(), normalDue);
  const due = retention
    ? Math.min(backupDue, Math.max(Date.now(), retention.retention_retry_at ?? Date.now()))
    : backupDue;
  return {
    enabled,
    interval_hours: Number(config.backup_interval_hours),
    retention_days: Number(config.backup_retention_days),
    last_success_at: last?.time ?? null,
    next_due_at: enabled ? due : null,
    state: !enabled
      ? 'paused'
      : (active?.retry_at && active.retry_at > Date.now()) || retention
        ? 'retrying'
        : (active?.status ?? (failed ? 'failed' : 'idle')),
    last_error_code: failureCode,
    retry_count: active?.last_error_code
      ? active.attempts
      : (retention?.retention_attempts ?? recentFailure?.attempts ?? active?.attempts ?? 0),
    digest_algorithm: 'sha256-chunk-manifest-v1',
  };
}

export async function getMigrationStatus(env: Env) {
  const config = await settings(env);
  const lock = await env.DB.prepare(
    "SELECT * FROM automation_locks WHERE name='legacy-migration'",
  ).first<{
    lease_until: number;
    last_success_at: number | null;
    last_error_code: string | null;
    attempts: number;
    retry_at: number | null;
  }>();
  const last = await env.DB.prepare(
    "SELECT MAX(completed_at) AS time FROM legacy_migration_runs WHERE state='complete'",
  ).first<{ time: number | null }>();
  const enabled = config.migration_enabled === '1',
    lastSuccess = last?.time ?? null;
  const due =
    lastSuccess === null
      ? Date.now()
      : lastSuccess + Number(config.migration_interval_hours) * 3600000;
  const incomplete = await env.DB.prepare(
    "SELECT id FROM legacy_migration_runs WHERE state!='complete' LIMIT 1",
  ).first();
  return {
    enabled,
    interval_hours: Number(config.migration_interval_hours),
    last_success_at: lastSuccess,
    next_due_at:
      enabled && !(lock?.attempts && lock.attempts >= 6 && lock.last_error_code)
        ? (lock?.retry_at ?? (incomplete ? Date.now() : Math.max(Date.now(), due)))
        : null,
    state: !enabled
      ? 'paused'
      : lock && lock.lease_until > Date.now()
        ? 'running'
        : lock?.last_error_code
          ? lock.attempts >= 6
            ? 'failed'
            : 'retrying'
          : incomplete
            ? 'pending'
            : 'idle',
    last_error_code: lock?.last_error_code ?? null,
    retry_count: lock?.attempts ?? 0,
  };
}
export async function advanceBackup(env: Env): Promise<void> {
  if (!env.BACKUPS) return;
  const bucket = env.BACKUPS;
  const job = await env.DB.prepare(
    "UPDATE backup_jobs SET lease_until=MAX(ABS(lease_until)+1,?),started_at=COALESCE(started_at,?),last_attempt_at=? WHERE id=(SELECT id FROM backup_jobs WHERE status IN ('pending','uploading') AND (retry_at IS NULL OR retry_at<=?) ORDER BY created_at LIMIT 1) AND lease_until<? RETURNING *",
  )
    .bind(Date.now() + BACKUP_LEASE_MS, Date.now(), Date.now(), Date.now(), Date.now())
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
    // Verify bytes rather than trusting HEAD/metadata. The digest is SHA-256 of
    // a length-delimited ordered manifest of independently verified part hashes.
    // Each range is bounded to 5 MiB, with a durable checkpoint for large objects.
    const checkpoint = await env.DB.prepare(
      'SELECT parts,verification_part,verification_etag FROM backup_jobs WHERE id=?',
    )
      .bind(job.id)
      .first<{ parts: string; verification_part: number; verification_etag: string | null }>();
    await renew();
    // A resumed verification checkpoint belongs to this exact object version.
    // R2 can receive a delayed older multipart completion between invocations.
    if (checkpoint!.verification_etag !== object.etag) {
      await commit('UPDATE backup_jobs SET verification_part=0,verification_etag=?', [object.etag]);
      checkpoint!.verification_part = 0;
    }
    let fingerprints = JSON.parse(checkpoint!.parts) as {
      partNumber: number;
      etag: string;
      sha256: string;
      size: number;
    }[];
    // An active snapshot may predate digest checkpoints, or the multipart
    // completion may have returned after a checkpoint write became ambiguous.
    // Reconstruct only missing fingerprints from the retained atomic snapshot.
    if (!fingerprints.length || fingerprints.some((p) => !p.sha256)) {
      const hashes: { sha256: string; size: number }[] = [];
      let after = 0,
        chunk = new Uint8Array(5 * 1024 * 1024),
        used = 0;
      for (;;) {
        const rows = await env.DB.prepare(
          'SELECT id,payload FROM backup_rows WHERE backup_id=? AND id>? ORDER BY id LIMIT 500',
        )
          .bind(job.id, after)
          .all<{ id: number; payload: string }>();
        await renew();
        if (!rows.results.length) break;
        for (const row of rows.results) {
          const bytes = new TextEncoder().encode(`${row.payload}\n`);
          for (let start = 0; start < bytes.length;) {
            const size = Math.min(bytes.length - start, chunk.length - used);
            chunk.set(bytes.subarray(start, start + size), used);
            used += size;
            start += size;
            if (used === chunk.length) {
              hashes.push({ size: used, sha256: await sha256(chunk) });
              used = 0;
              await renew();
            }
          }
          after = row.id;
        }
      }
      if (used) hashes.push({ size: used, sha256: await sha256(chunk.subarray(0, used)) });
      if (fingerprints.length && fingerprints.length !== hashes.length)
        throw new Error('BACKUP_DIGEST_CHECKPOINT_MISMATCH');
      fingerprints = hashes.map((value, index) => ({
        ...fingerprints[index],
        partNumber: index + 1,
        etag: fingerprints[index]?.etag ?? object.etag,
        ...value,
      }));
      await commit('UPDATE backup_jobs SET parts=?', [JSON.stringify(fingerprints)]);
    }
    if (
      fingerprints.some(
        (p) => !/^[a-f0-9]{64}$/.test(p.sha256) || !Number.isSafeInteger(p.size) || p.size < 1,
      )
    )
      throw new Error('BACKUP_DIGEST_CHECKPOINT_MISSING');
    let offset = fingerprints
      .slice(0, checkpoint!.verification_part)
      .reduce((sum, p) => sum + p.size, 0);
    const end = Math.min(fingerprints.length, checkpoint!.verification_part + 20);
    for (let part = checkpoint!.verification_part; part < end; part++) {
      await renew();
      const value = await bucket.get(`backups/${job.id}.ndjson`, {
        range: { offset, length: fingerprints[part].size },
      });
      await renew();
      if (!value || value.etag !== object.etag) throw new Error('BACKUP_OBJECT_CHANGED');
      const bytes = await value.arrayBuffer();
      await renew();
      if (
        bytes.byteLength !== fingerprints[part].size ||
        (await sha256(bytes)) !== fingerprints[part].sha256
      )
        throw new Error('BACKUP_OBJECT_DIGEST_MISMATCH');
      offset += bytes.byteLength;
      await commit('UPDATE backup_jobs SET verification_part=?', [part + 1]);
    }
    if (end < fingerprints.length) return;
    if (offset !== totals.size) throw new Error('BACKUP_OBJECT_MISMATCH');
    const digest = await sha256(
      new TextEncoder().encode(fingerprints.map((p) => `${p.size}:${p.sha256}\n`).join('')),
    );
    await renew();
    const time = Date.now();
    // Both statements share one D1 transaction. Cleanup requires this exact
    // lease's successful status change, so a stale HEAD result cannot delete rows.
    const results = await env.DB.batch([
      env.DB.prepare(
        `UPDATE backup_jobs SET status='complete',completed_at=?,size=?,records=?,snapshot_digest=?,object_digest=?,duration_ms=?-COALESCE(started_at,created_at),retry_at=NULL,last_error_code=NULL WHERE id=? AND lease_until=? AND lease_until>? AND ${active}`,
      ).bind(time, totals.size, totals.records, digest, digest, time, job.id, lease, time),
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
      'UPDATE backup_jobs SET upload_id=NULL,upload_started_at=NULL,after_row=0,row_offset=0,part_number=1,parts=?,size=0,records=0,verification_part=0,verification_etag=NULL',
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
    const parts: (R2UploadedPart & { sha256: string; size: number })[] = JSON.parse(job.parts);
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
      parts.push({ ...part, sha256: await sha256(body), size: bytes });
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
    if (owned) {
      const code =
        error instanceof Error && /^BACKUP_[A-Z_]+$/.test(error.message)
          ? error.message
          : 'BACKUP_STORAGE_OR_DATABASE_UNAVAILABLE';
      const attempts = job.attempts + 1;
      await commit('UPDATE backup_jobs SET attempts=?,last_error_code=?,retry_at=?', [
        attempts,
        code,
        Date.now() + Math.min(6 * 3600000, 600000 * 2 ** Math.min(attempts - 1, 6)),
      ]);
      throw new Error(code);
    }
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
  let backupFailure: unknown;
  if (config.backup_enabled === '1') {
    try {
      await advanceBackup(env);
    } catch (error) {
      backupFailure = error;
    }
  }
  const latest = await env.DB.prepare(
    "SELECT MAX(completed_at) AS time FROM backup_jobs WHERE status='complete'",
  ).first<{
    time: number | null;
  }>();
  if (
    !backupFailure &&
    config.backup_enabled === '1' &&
    (!latest?.time || Date.now() - latest.time >= Number(config.backup_interval_hours) * 3600000)
  ) {
    try {
      await startBackup(env, 'system:scheduled');
      await advanceBackup(env);
    } catch (error) {
      backupFailure = error;
    }
  }
  const now = Date.now();
  // Retention only applies to aggregate statistics, audit, rate windows and this
  // project's private backup prefix. Link mappings, token history and slugs survive.
  const cleanup = [
    env.DB.prepare('DELETE FROM rate_windows WHERE window<?').bind(Math.floor(now / 60000) - 10),
  ];
  if (Number(config.analytics_retention_days) > 0)
    cleanup.push(
      env.DB.prepare('DELETE FROM daily_stats WHERE day<?').bind(
        new Date(now - Number(config.analytics_retention_days) * 86400000)
          .toISOString()
          .slice(0, 10),
      ),
    );
  if (Number(config.audit_retention_days) > 0)
    cleanup.push(
      env.DB.prepare('DELETE FROM audit WHERE created_at<?').bind(
        now - Number(config.audit_retention_days) * 86400000,
      ),
    );
  await env.DB.batch(cleanup);
  const cutoff = now - Number(config.backup_retention_days) * 86400000;
  const expired = await env.DB.prepare(
    "SELECT id FROM backup_jobs WHERE status='complete' AND (retired_at IS NOT NULL OR (? > 0 AND COALESCE(completed_at,created_at)<?)) AND (retention_retry_at IS NULL OR retention_retry_at<=?) ORDER BY retention_checked_at,created_at,id LIMIT 20",
  )
    .bind(Number(config.backup_retention_days), cutoff, now)
    .all<{ id: string }>();
  let retentionFailed = false;
  for (const row of expired.results) {
    // Keep a minimal hidden marker: a late multipart completion can recreate this
    // exact key after deletion. Rotate rechecks so no retired key loses tracking.
    const retired = await env.DB.prepare(
      "UPDATE backup_jobs SET retired_at=COALESCE(retired_at,?),retention_checked_at=?,upload_id=NULL,upload_started_at=NULL,after_row=0,row_offset=0,part_number=1,parts='[]',size=0,records=0,lease_until=0 WHERE id=? AND status='complete' AND (retired_at IS NOT NULL OR (? > 0 AND COALESCE(completed_at,created_at)<?))",
    )
      .bind(now, now, row.id, Number(config.backup_retention_days), cutoff)
      .run();
    if (retired.meta.changes !== 1) continue;
    try {
      if (!env.BACKUPS) throw new Error('BACKUP_NOT_CONFIGURED');
      await env.BACKUPS.delete(`backups/${row.id}.ndjson`);
      await env.DB.prepare(
        'UPDATE backup_jobs SET retention_last_error=NULL,retention_retry_at=NULL,retention_attempts=0 WHERE id=? AND retired_at IS NOT NULL',
      )
        .bind(row.id)
        .run();
    } catch {
      // The marker survives failure, and its attempt time allows the next keys
      // to progress before this exact key is retried in a later rotation.
      retentionFailed = true;
      await env.DB.prepare(
        "UPDATE backup_jobs SET retention_last_error='BACKUP_RETENTION_STORAGE_UNAVAILABLE',retention_retry_at=?+MIN(21600000,600000*(1 << MIN(retention_attempts,6))),retention_attempts=retention_attempts+1 WHERE id=? AND retired_at IS NOT NULL",
      )
        .bind(now, row.id)
        .run();
    }
  }
  if (retentionFailed) throw new Error('BACKUP_RETENTION_RETRY_REQUIRED');
  if (backupFailure)
    throw new Error(
      backupFailure instanceof Error && /^BACKUP_[A-Z_]+$/.test(backupFailure.message)
        ? backupFailure.message
        : 'BACKUP_STORAGE_OR_DATABASE_UNAVAILABLE',
    );
}
