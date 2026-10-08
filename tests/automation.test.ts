import { readFile, readdir } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  advanceBackup,
  getBackupStatus,
  getMigrationStatus,
  maintenance,
  startBackup,
} from '../src/maintenance';
import type { Env } from '../src/types';

let mf: Miniflare, env: Env, now: number;
const schema: string[] = [];
beforeAll(async () => {
  mf = new Miniflare(
    convertV4MiniflareOptions({
      modules: true,
      script: 'export default {fetch(){return new Response("fixture")}}',
      d1Databases: ['DB'],
      r2Buckets: ['BACKUPS'],
    }),
  );
  env = {
    DB: (await mf.getD1Database('DB')) as unknown as D1Database,
    BACKUPS: (await mf.getR2Bucket('BACKUPS')) as unknown as R2Bucket,
    PUBLIC_HOSTNAME: 'gfw.mom',
    ADMIN_HOSTNAME: 'link-admin.lily.lat',
    APP_ENV: 'production',
    ADMIN_EMAILS: 'admin@example.test',
    TURNSTILE_SITE_KEY: 'fixture-public',
    TURNSTILE_SECRET_KEY: 'fixture-private',
  };
  for (const name of (await readdir(new URL('../migrations/', import.meta.url)))
    .filter((name) => name.endsWith('.sql'))
    .sort()) {
    const sql = await readFile(new URL(`../migrations/${name}`, import.meta.url), 'utf8');
    schema.push(sql);
    await env.DB.batch(
      sql
        .split(';')
        .filter((value) => value.trim())
        .map((value) => env.DB.prepare(value)),
    );
  }
});
beforeEach(async () => {
  now = Date.now();
  vi.spyOn(Date, 'now').mockImplementation(() => now);
  await env.DB.batch(
    [
      'DELETE FROM backup_rows',
      'DELETE FROM backup_jobs',
      'DELETE FROM audit',
      'DELETE FROM daily_stats',
      'DELETE FROM rate_windows',
      'DELETE FROM links',
      'DELETE FROM deleted_links',
      'DELETE FROM legacy_migration_items',
      'DELETE FROM legacy_migration_runs',
      'UPDATE automation_locks SET lease_until=0,last_success_at=NULL,last_error_code=NULL,attempts=0,retry_at=NULL,run_id=NULL',
      "UPDATE settings SET value='1' WHERE key IN ('backup_enabled','migration_enabled')",
      "UPDATE settings SET value='24' WHERE key IN ('backup_interval_hours','migration_interval_hours')",
      "UPDATE settings SET value='30' WHERE key='backup_retention_days'",
      "UPDATE settings SET value='90' WHERE key='analytics_retention_days'",
      "UPDATE settings SET value='365' WHERE key='audit_retention_days'",
      "INSERT INTO domains(hostname,enabled,bound,created_at,binding_state,last_verified_at,last_checked_at) VALUES('gfw.mom',1,1,1,'verified',1,1) ON CONFLICT(hostname) DO NOTHING",
    ].map((sql) => env.DB.prepare(sql)),
  );
});
afterEach(() => vi.restoreAllMocks());
afterAll(async () => mf.dispose());

describe('automatic backup scheduling and durable object verification', () => {
  it('shows a newer failed job without overwriting the previous success, and clears historical failure after another success', async () => {
    const success = now - 100000;
    await env.DB.prepare(
      "INSERT INTO backup_jobs(id,created_at,status,completed_at) VALUES('success',?,'complete',?)",
    )
      .bind(success, success)
      .run();
    await env.DB.prepare(
      "INSERT INTO backup_jobs(id,created_at,status,last_attempt_at,last_error_code,attempts) VALUES('failed',?,'failed',?,'BACKUP_OBJECT_MISMATCH',3)",
    )
      .bind(now, now)
      .run();
    expect(await getBackupStatus(env)).toMatchObject({
      state: 'failed',
      last_success_at: success,
      last_error_code: 'BACKUP_OBJECT_MISMATCH',
      retry_count: 3,
    });
    await env.DB.prepare(
      "INSERT INTO backup_jobs(id,created_at,status,completed_at) VALUES('later',?,'complete',?)",
    )
      .bind(now + 1, now + 1)
      .run();
    expect(await getBackupStatus(env)).toMatchObject({
      state: 'idle',
      last_success_at: now + 1,
      last_error_code: null,
      retry_count: 0,
    });
  });

  it('reports retired-object cleanup failures with bounded retry timing, then clears the error while keeping the safety marker', async () => {
    const success = now - 2 * 86400000;
    await env.DB.batch([
      env.DB.prepare("UPDATE settings SET value='720' WHERE key='backup_interval_hours'"),
      env.DB.prepare("UPDATE settings SET value='1' WHERE key='backup_retention_days'"),
      env.DB.prepare(
        "INSERT INTO backup_jobs(id,created_at,status,completed_at) VALUES('retention-error',?,'complete',?)",
      ).bind(success, success),
    ]);
    await env.BACKUPS!.put('backups/retention-error.ndjson', 'fixture');
    let attempts = 0;
    const bucket = {
      delete: async () => {
        attempts++;
        throw new Error('private provider detail');
      },
    } as unknown as R2Bucket;
    await expect(maintenance({ ...env, BACKUPS: bucket })).rejects.toThrow(
      'BACKUP_RETENTION_RETRY_REQUIRED',
    );
    expect(await getBackupStatus(env)).toMatchObject({
      state: 'retrying',
      last_success_at: success,
      last_error_code: 'BACKUP_RETENTION_STORAGE_UNAVAILABLE',
      retry_count: 1,
      next_due_at: now + 600000,
    });
    await maintenance({ ...env, BACKUPS: bucket });
    expect(attempts).toBe(1);
    now += 600000;
    await expect(maintenance({ ...env, BACKUPS: bucket })).rejects.toThrow(
      'BACKUP_RETENTION_RETRY_REQUIRED',
    );
    expect(attempts).toBe(2);
    expect(await getBackupStatus(env)).toMatchObject({
      state: 'retrying',
      last_success_at: success,
      retry_count: 2,
      next_due_at: now + 1200000,
    });
    now += 1200000;
    await maintenance(env);
    expect(await getBackupStatus(env)).toMatchObject({
      state: 'idle',
      last_success_at: success,
      last_error_code: null,
      retry_count: 0,
    });
    expect(
      await env.DB.prepare(
        "SELECT retired_at,retention_last_error,retention_attempts,retention_retry_at FROM backup_jobs WHERE id='retention-error'",
      ).first(),
    ).toMatchObject({
      retention_last_error: null,
      retention_attempts: 0,
      retention_retry_at: null,
    });
    expect(await env.BACKUPS!.get('backups/retention-error.ndjson')).toBeNull();
    expect(
      await env.DB.prepare("SELECT retired_at FROM backup_jobs WHERE id='retention-error'").first(
        'retired_at',
      ),
    ).not.toBeNull();
  });

  it('creates and verifies an R2 object by automatic maintenance, observes interval and pauses without another snapshot', async () => {
    await maintenance(env);
    const job = await env.DB.prepare('SELECT * FROM backup_jobs').first<{
      id: string;
      status: string;
      object_digest: string;
      snapshot_digest: string;
      completed_at: number;
      duration_ms: number;
    }>();
    expect(job).toMatchObject({ status: 'complete', completed_at: now });
    expect(job!.snapshot_digest).toMatch(/^[a-f0-9]{64}$/);
    expect(job!.object_digest).toBe(job!.snapshot_digest);
    expect(await env.BACKUPS!.get(`backups/${job!.id}.ndjson`)).not.toBeNull();
    expect(await getBackupStatus(env)).toMatchObject({
      enabled: true,
      last_success_at: now,
      next_due_at: now + 86400000,
      state: 'idle',
      digest_algorithm: 'sha256-chunk-manifest-v1',
    });
    now += 3600000;
    await maintenance(env);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM backup_jobs').first('n')).toBe(1);
    await env.DB.prepare("UPDATE settings SET value='0' WHERE key='backup_enabled'").run();
    now += 86400000;
    await maintenance(env);
    expect(await getBackupStatus(env)).toMatchObject({
      enabled: false,
      state: 'paused',
      next_due_at: null,
    });
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM backup_jobs').first('n')).toBe(1);
    await env.DB.prepare("UPDATE settings SET value='1' WHERE key='backup_enabled'").run();
    await maintenance(env);
    expect(
      await env.DB.prepare("SELECT COUNT(*) AS n FROM backup_jobs WHERE status='complete'").first(
        'n',
      ),
    ).toBe(2);
  });

  it('retention zero preserves old aggregate/audit/object data; positive backup retention starts at successful completion', async () => {
    await env.DB.batch([
      env.DB.prepare(
        "UPDATE settings SET value='0' WHERE key IN ('analytics_retention_days','audit_retention_days','backup_retention_days','backup_enabled')",
      ),
      env.DB.prepare(
        "INSERT INTO daily_stats VALUES('2000-01-01','gfw.mom','fixture','SG','desktop','direct',1)",
      ),
      env.DB.prepare("INSERT INTO audit VALUES('old','fixture','fixture','fixture','{}',1)"),
      env.DB.prepare(
        "INSERT INTO backup_jobs(id,created_at,status,completed_at) VALUES('old',1,'complete',1)",
      ),
      env.DB.prepare(
        "INSERT INTO backup_jobs(id,created_at,status,completed_at) VALUES('fresh',1,'complete',?)",
      ).bind(now),
    ]);
    await env.BACKUPS!.put('backups/old.ndjson', 'old');
    await env.BACKUPS!.put('backups/fresh.ndjson', 'fresh');
    await maintenance(env);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM daily_stats').first('n')).toBe(1);
    expect(await env.DB.prepare("SELECT id FROM audit WHERE id='old'").first()).not.toBeNull();
    expect(await env.BACKUPS!.get('backups/old.ndjson')).not.toBeNull();
    await env.DB.prepare("UPDATE settings SET value='30' WHERE key='backup_retention_days'").run();
    await maintenance(env);
    expect(await env.BACKUPS!.get('backups/old.ndjson')).toBeNull();
    expect(await env.BACKUPS!.get('backups/fresh.ndjson')).not.toBeNull();
  });

  it('reports failures and backed-off retries without advancing last success, and recovers the same atomic snapshot', async () => {
    const id = await startBackup(env, 'fixture');
    const bucket = {
      head: () => Promise.reject(new Error('opaque provider error')),
    } as unknown as R2Bucket;
    await expect(advanceBackup({ ...env, BACKUPS: bucket })).rejects.toThrow(
      'BACKUP_STORAGE_OR_DATABASE_UNAVAILABLE',
    );
    expect(await getBackupStatus(env)).toMatchObject({
      state: 'retrying',
      last_success_at: null,
      retry_count: 1,
      last_error_code: 'BACKUP_STORAGE_OR_DATABASE_UNAVAILABLE',
      next_due_at: now + 600000,
    });
    await advanceBackup(env);
    expect(
      await env.DB.prepare('SELECT status FROM backup_jobs WHERE id=?').bind(id).first('status'),
    ).toBe('pending');
    now += 600001;
    await advanceBackup(env);
    expect(await getBackupStatus(env)).toMatchObject({
      state: 'idle',
      last_success_at: now,
      last_error_code: null,
    });
    expect(
      await env.DB.prepare('SELECT status,attempts FROM backup_jobs WHERE id=?').bind(id).first(),
    ).toMatchObject({ status: 'complete', attempts: 1 });
  });

  it('rejects altered bytes with matching size and metadata, retaining staging and exposing a safe digest failure', async () => {
    const id = await startBackup(env, 'fixture');
    const rows = await env.DB.prepare(
      'SELECT payload FROM backup_rows WHERE backup_id=? ORDER BY id',
    )
      .bind(id)
      .all<{ payload: string }>();
    const body = rows.results.map((row) => row.payload + '\n').join('');
    const changed = body.replace('backup.create', 'backup.creatz');
    expect(changed.length).toBe(body.length);
    await env.BACKUPS!.put(`backups/${id}.ndjson`, changed, {
      customMetadata: {
        schema_version: '1',
        created_at: String(now),
        consistency: 'atomic-d1-snapshot',
      },
    });
    const digest = Array.from(
      new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body))),
      (byte) => byte.toString(16).padStart(2, '0'),
    ).join('');
    await env.DB.prepare(
      'UPDATE backup_jobs SET verification_part=1,verification_etag=?,parts=? WHERE id=?',
    )
      .bind(
        'previous-object-version',
        JSON.stringify([
          { partNumber: 1, etag: 'previous-upload', sha256: digest, size: Buffer.byteLength(body) },
        ]),
        id,
      )
      .run();
    await expect(advanceBackup(env)).rejects.toThrow('BACKUP_OBJECT_DIGEST_MISMATCH');
    expect(
      await env.DB.prepare('SELECT COUNT(*) AS n FROM backup_rows WHERE backup_id=?')
        .bind(id)
        .first('n'),
    ).toBe(rows.results.length);
    expect(await getBackupStatus(env)).toMatchObject({
      last_success_at: null,
      last_error_code: 'BACKUP_OBJECT_DIGEST_MISMATCH',
    });
  });

  it('restores every snapshot record into the upgraded offline schema, including tombstones and binding timestamps', async () => {
    await env.DB.prepare(
      "INSERT INTO deleted_links(slug,link_id,deleted_at,token_id,domain,idempotency_key,request_hash) VALUES('deleted','deleted-id',1,NULL,NULL,NULL,NULL)",
    ).run();
    await env.DB.prepare(
      "INSERT INTO links(id,domain,slug,url,created_at,source,creator) VALUES('fixture-id','gfw.mom','keep','https://example.test/a?x=%2B&x=2#f',1,'admin','fixture')",
    ).run();
    await maintenance(env);
    const id = await env.DB.prepare(
      "SELECT id FROM backup_jobs WHERE status='complete'",
    ).first<string>('id');
    const lines = (await (await env.BACKUPS!.get(`backups/${id}.ndjson`))!.text())
      .trimEnd()
      .split('\n')
      .map(
        (line) =>
          JSON.parse(line) as { table: string; data: Record<string, string | number | null> },
      );
    const restore = new DatabaseSync(':memory:');
    for (const sql of schema) restore.exec(sql);
    restore.exec('PRAGMA foreign_keys=OFF');
    for (const table of new Set(lines.map((row) => row.table)))
      restore.exec(`DELETE FROM ${table}`);
    for (const row of lines) {
      const keys = Object.keys(row.data);
      restore
        .prepare(
          `INSERT INTO ${row.table}(${keys.join(',')}) VALUES(${keys.map(() => '?').join(',')})`,
        )
        .run(...keys.map((key) => row.data[key]));
    }
    restore.exec('PRAGMA foreign_keys=ON');
    expect(restore.prepare('PRAGMA foreign_key_check').all()).toEqual([]);
    expect(restore.prepare("SELECT url FROM links WHERE slug='keep'").get()).toMatchObject({
      url: 'https://example.test/a?x=%2B&x=2#f',
    });
    expect(
      restore.prepare("SELECT slug,link_id FROM deleted_links WHERE slug='deleted'").get(),
    ).toMatchObject({ slug: 'deleted', link_id: 'deleted-id' });
    expect(
      restore
        .prepare(
          "SELECT binding_state,last_checked_at,last_verified_at FROM domains WHERE hostname='gfw.mom'",
        )
        .get(),
    ).toMatchObject({ binding_state: 'verified', last_checked_at: 1, last_verified_at: 1 });
    for (const table of new Set(lines.map((row) => row.table)))
      expect(Number(restore.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get()!.n)).toBe(
        lines.filter((row) => row.table === table).length,
      );
    restore.close();
  });
});

it('migration status distinguishes pending/resume, running, failed, paused and true completion times', async () => {
  expect(await getMigrationStatus(env)).toMatchObject({ state: 'idle', last_success_at: null });
  await env.DB.prepare(
    "INSERT INTO legacy_migration_runs(id,namespace_id,domain,state,digest,started_at,updated_at) VALUES('fixture','legacy','test.gfw.mom','running','',1,1)",
  ).run();
  expect(await getMigrationStatus(env)).toMatchObject({
    state: 'pending',
    next_due_at: now,
    last_success_at: null,
  });
  await env.DB.prepare('UPDATE automation_locks SET lease_until=?')
    .bind(now + 1000)
    .run();
  expect(await getMigrationStatus(env)).toMatchObject({ state: 'running' });
  await env.DB.prepare(
    "UPDATE automation_locks SET lease_until=0,attempts=6,last_error_code='MIGRATION_PERMISSION_DENIED'",
  ).run();
  expect(await getMigrationStatus(env)).toMatchObject({
    state: 'failed',
    next_due_at: null,
    last_success_at: null,
  });
  await env.DB.prepare("UPDATE settings SET value='0' WHERE key='migration_enabled'").run();
  expect(await getMigrationStatus(env)).toMatchObject({ state: 'paused', next_due_at: null });
});
