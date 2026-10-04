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
}
export async function advanceBackup(env: Env): Promise<void> {
  if (!env.BACKUPS) return;
  const lease = Date.now() + 120000;
  const job = await env.DB.prepare(
    "UPDATE backup_jobs SET lease_until=? WHERE id=(SELECT id FROM backup_jobs WHERE status IN ('pending','uploading') ORDER BY created_at LIMIT 1) AND lease_until<? RETURNING *",
  )
    .bind(lease, Date.now())
    .first<BackupJob>();
  if (!job) return;
  try {
    const key = `backups/${job.id}.ndjson`;
    const existing = await env.BACKUPS.head(key);
    if (
      existing?.customMetadata?.created_at === String(job.created_at) &&
      existing.customMetadata.consistency === 'atomic-d1-snapshot'
    ) {
      await env.DB.batch([
        env.DB.prepare("UPDATE backup_jobs SET status='complete',completed_at=? WHERE id=?").bind(
          Date.now(),
          job.id,
        ),
        env.DB.prepare('DELETE FROM backup_rows WHERE backup_id=?').bind(job.id),
      ]);
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
      await env.BACKUPS.resumeMultipartUpload(key, job.upload_id)
        .abort()
        .catch(() => undefined);
      await env.DB.prepare(
        'UPDATE backup_jobs SET upload_id=NULL,upload_started_at=NULL,after_row=0,row_offset=0,part_number=1,parts=?,size=0,records=0 WHERE id=?',
      )
        .bind('[]', job.id)
        .run();
      job.upload_id = null;
      job.after_row = 0;
      job.row_offset = 0;
      job.part_number = 1;
      job.parts = '[]';
      job.size = 0;
      job.records = 0;
    }
    if (!job.upload_id) {
      upload = await env.BACKUPS.createMultipartUpload(key, {
        httpMetadata: { contentType: 'application/x-ndjson' },
        customMetadata: {
          schema_version: '1',
          created_at: String(job.created_at),
          consistency: 'atomic-d1-snapshot',
        },
      });
      await env.DB.prepare(
        "UPDATE backup_jobs SET upload_id=?,upload_started_at=?,status='uploading' WHERE id=?",
      )
        .bind(upload.uploadId, Date.now(), job.id)
        .run();
    } else upload = env.BACKUPS.resumeMultipartUpload(key, job.upload_id);
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
      const part = await upload.uploadPart(job.part_number, body);
      parts.push(part);
      // Reuploading the same part after a checkpoint failure is safe; no row is skipped.
      await env.DB.prepare(
        'UPDATE backup_jobs SET after_row=?,row_offset=?,part_number=?,parts=?,size=size+?,records=records+? WHERE id=?',
      )
        .bind(cursor, rowOffset, job.part_number + 1, JSON.stringify(parts), bytes, count, job.id)
        .run();
    }
    if (complete) {
      await upload.complete(parts);
      await env.DB.batch([
        env.DB.prepare("UPDATE backup_jobs SET status='complete',completed_at=? WHERE id=?").bind(
          Date.now(),
          job.id,
        ),
        env.DB.prepare('DELETE FROM backup_rows WHERE backup_id=?').bind(job.id),
      ]);
    }
  } finally {
    await env.DB.prepare('UPDATE backup_jobs SET lease_until=0 WHERE id=? AND lease_until=?')
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
  const expired = await env.DB.prepare(
    "SELECT id FROM backup_jobs WHERE status='complete' AND created_at<? LIMIT 20",
  )
    .bind(now - Number(config.backup_retention_days) * 86400000)
    .all<{ id: string }>();
  for (const row of expired.results) {
    await env.BACKUPS?.delete(`backups/${row.id}.ndjson`);
    await env.DB.prepare('DELETE FROM backup_jobs WHERE id=?').bind(row.id).run();
  }
}
