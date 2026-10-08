import { readFile, readdir } from 'node:fs/promises';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { advanceBackup, maintenance, startBackup } from '../src/maintenance';
import type { Env } from '../src/types';

let mf: Miniflare;
let env: Env;
let now: number;
const domain = 'gfw.mom';
const actor = 'backup-fixture@example.test';
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

beforeAll(async () => {
  mf = new Miniflare(
    convertV4MiniflareOptions({
      modules: true,
      script: 'export default { fetch() { return new Response("fixture"); } }',
      d1Databases: ['DB'],
      r2Buckets: ['BACKUPS'],
    }),
  );
  env = {
    DB: (await mf.getD1Database('DB')) as unknown as D1Database,
    BACKUPS: (await mf.getR2Bucket('BACKUPS')) as unknown as R2Bucket,
    PUBLIC_HOSTNAME: domain,
    ADMIN_HOSTNAME: 'link-admin.lily.lat',
    APP_ENV: 'production',
    ADMIN_EMAILS: actor,
    TURNSTILE_SITE_KEY: 'fixture-public',
    TURNSTILE_SECRET_KEY: 'fixture-private',
  };
  for (const file of (await readdir(new URL('../migrations/', import.meta.url))).sort()) {
    if (!file.endsWith('.sql')) continue;
    const sql = await readFile(new URL(`../migrations/${file}`, import.meta.url), 'utf8');
    await env.DB.batch(
      sql
        .split(';')
        .filter((statement) => statement.trim())
        .map((statement) => env.DB.prepare(statement)),
    );
  }
});
beforeEach(async () => {
  now = Date.now();
  vi.spyOn(Date, 'now').mockImplementation(() => now);
  await env.DB.prepare("UPDATE settings SET value='30' WHERE key='backup_retention_days'").run();
  await env.DB.batch(
    [
      'DELETE FROM backup_rows',
      'DELETE FROM backup_jobs',
      'DELETE FROM audit',
      'DELETE FROM links',
      'DELETE FROM domains',
    ].map((sql) => env.DB.prepare(sql)),
  );
  await env.DB.prepare(
    "INSERT INTO domains(hostname,enabled,bound,created_at,binding_state) VALUES (?,1,1,?,'verified')",
  )
    .bind(domain, now)
    .run();
});
afterEach(() => vi.restoreAllMocks());
afterAll(async () => mf?.dispose());

function wrappedBucket(overrides: Partial<R2Bucket>): R2Bucket {
  const bucket = env.BACKUPS!;
  return {
    head: (key) => bucket.head(key),
    get: (key, options) => bucket.get(key, options),
    createMultipartUpload: (key, options) => bucket.createMultipartUpload(key, options),
    resumeMultipartUpload: (key, id) => bucket.resumeMultipartUpload(key, id),
    ...overrides,
  } as R2Bucket;
}
async function totals(id: string) {
  return (await env.DB.prepare(
    'SELECT COUNT(*) AS records,COALESCE(SUM(length(CAST(payload AS BLOB))+1),0) AS size FROM backup_rows WHERE backup_id=?',
  )
    .bind(id)
    .first<{ records: number; size: number }>())!;
}
async function job(id: string) {
  return (await env.DB.prepare('SELECT * FROM backup_jobs WHERE id=?').bind(id).first<{
    status: string;
    size: number;
    records: number;
    completed_at: number;
    upload_id: string;
    lease_until: number;
    created_at: number;
    retired_at: number | null;
    retention_checked_at: number | null;
  }>())!;
}
async function expireLease(id: string) {
  now = Math.max(now + 120001, (await job(id)).lease_until + 1);
}
async function largeFixture() {
  for (let offset = 0; offset < 700; offset += 100) {
    await env.DB.batch(
      Array.from({ length: 100 }, (_, index) =>
        env.DB.prepare(
          "INSERT INTO links(id,domain,slug,url,source,creator) VALUES (?,?,?,?,'admin',?)",
        ).bind(
          crypto.randomUUID(),
          domain,
          `fixture-${offset + index}`,
          `https://example.test/${'a'.repeat(7800)}?i=${offset + index}`,
          actor,
        ),
      ),
    );
  }
}

describe('backup lease takeover against actual local D1 and R2', () => {
  it('allows a separate old multipart session to recreate a deleted completed object', async () => {
    const id = crypto.randomUUID();
    const key = `backups/${id}.ndjson`;
    const body = new TextEncoder().encode('{}\n');
    const old = await env.BACKUPS!.createMultipartUpload(key);
    const oldPart = await old.uploadPart(1, body);
    const next = await env.BACKUPS!.createMultipartUpload(key);
    const nextPart = await next.uploadPart(1, body);
    await next.complete([nextPart]);
    await env.BACKUPS!.delete(key);
    expect(await env.BACKUPS!.head(key)).toBeNull();
    await old.complete([oldPart]);
    expect((await env.BACKUPS!.head(key))?.size).toBe(body.length);
  });
  it('does not double count an uploaded part when its old execution resumes after takeover', async () => {
    const id = await startBackup(env, actor);
    const expected = await totals(id);
    const entered = deferred(),
      release = deferred();
    let delayed = false;
    const wrap = (upload: R2MultipartUpload): R2MultipartUpload => ({
      key: upload.key,
      uploadId: upload.uploadId,
      abort: () => upload.abort(),
      complete: (parts) => upload.complete(parts),
      async uploadPart(number, body) {
        const part = await upload.uploadPart(number, body);
        if (!delayed) {
          delayed = true;
          entered.resolve();
          await release.promise;
        }
        return part;
      },
    });
    const bucket = wrappedBucket({
      createMultipartUpload: async (key, options) =>
        wrap(await env.BACKUPS!.createMultipartUpload(key, options)),
      resumeMultipartUpload: (key, uploadId) =>
        wrap(env.BACKUPS!.resumeMultipartUpload(key, uploadId)),
    });
    const old = advanceBackup({ ...env, BACKUPS: bucket });
    await entered.promise;
    await expireLease(id);
    await advanceBackup(env);
    release.resolve();
    await Promise.allSettled([old]);
    expect(await job(id)).toMatchObject({ status: 'complete', ...expected });
    expect((await env.BACKUPS!.head(`backups/${id}.ndjson`))?.size).toBe(expected.size);
    expect((await totals(id)).records).toBe(0);
  });

  it('does not complete old prefix parts when the winner deleted the staging rows', async () => {
    await largeFixture();
    const id = await startBackup(env, actor);
    const expected = await totals(id);
    await advanceBackup(env);
    expect((await job(id)).status).toBe('uploading');
    const entered = deferred(),
      release = deferred();
    let oldCompletes = 0,
      oldUploads = 0;
    const bucket = wrappedBucket({
      async head(key) {
        const object = await env.BACKUPS!.head(key);
        entered.resolve();
        await release.promise;
        return object;
      },
      resumeMultipartUpload(key, uploadId) {
        const upload = env.BACKUPS!.resumeMultipartUpload(key, uploadId);
        return {
          key,
          uploadId,
          abort: () => upload.abort(),
          uploadPart: (number, body) => {
            oldUploads++;
            return upload.uploadPart(number, body);
          },
          complete: (parts) => {
            oldCompletes++;
            return upload.complete(parts);
          },
        };
      },
    });
    const old = advanceBackup({ ...env, BACKUPS: bucket });
    await entered.promise;
    await expireLease(id);
    await advanceBackup(env);
    expect((await totals(id)).records).toBe(0);
    release.resolve();
    await Promise.allSettled([old]);
    expect(oldUploads).toBe(0);
    expect(oldCompletes).toBe(0);
    expect(await job(id)).toMatchObject({ status: 'complete', ...expected });
  });

  it('does not repeat completion cleanup after a winner reconciles the completed R2 object', async () => {
    const id = await startBackup(env, actor);
    const expected = await totals(id);
    const entered = deferred(),
      release = deferred();
    const bucket = wrappedBucket({
      async createMultipartUpload(key, options) {
        const upload = await env.BACKUPS!.createMultipartUpload(key, options);
        return {
          key,
          uploadId: upload.uploadId,
          abort: () => upload.abort(),
          uploadPart: (number, body) => upload.uploadPart(number, body),
          async complete(parts) {
            const object = await upload.complete(parts);
            entered.resolve();
            await release.promise;
            return object;
          },
        };
      },
    });
    const old = advanceBackup({ ...env, BACKUPS: bucket });
    await entered.promise;
    await expireLease(id);
    await advanceBackup(env);
    const winnerTime = now;
    now++;
    release.resolve();
    await Promise.allSettled([old]);
    expect(await job(id)).toMatchObject({
      status: 'complete',
      completed_at: winnerTime,
      ...expected,
    });
    expect((await totals(id)).records).toBe(0);
  });

  it('stops a stale HEAD reconciliation after the winner changed status and cleaned the snapshot', async () => {
    const id = await startBackup(env, actor);
    const expected = await totals(id);
    const rows = await env.DB.prepare(
      'SELECT payload FROM backup_rows WHERE backup_id=? ORDER BY id',
    )
      .bind(id)
      .all<{ payload: string }>();
    await env.BACKUPS!.put(
      `backups/${id}.ndjson`,
      rows.results.map((row) => `${row.payload}\n`).join(''),
      {
        customMetadata: {
          schema_version: '1',
          created_at: String((await job(id)).created_at),
          consistency: 'atomic-d1-snapshot',
        },
      },
    );
    const entered = deferred(),
      release = deferred();
    const bucket = wrappedBucket({
      async head(key) {
        const object = await env.BACKUPS!.head(key);
        entered.resolve();
        await release.promise;
        return object;
      },
    });
    const old = advanceBackup({ ...env, BACKUPS: bucket });
    await entered.promise;
    await expireLease(id);
    await advanceBackup(env);
    const winner = await job(id);
    now++;
    release.resolve();
    await expect(old).resolves.toBeUndefined();
    expect(await job(id)).toMatchObject({
      status: 'complete',
      completed_at: winner.completed_at,
      ...expected,
    });
    expect((await totals(id)).records).toBe(0);
  });

  it('does not attach or use a multipart upload whose creation returned after lease loss', async () => {
    const id = await startBackup(env, actor);
    const expected = await totals(id);
    const entered = deferred(),
      release = deferred();
    let orphanId = '',
      oldWrites = 0;
    const bucket = wrappedBucket({
      async createMultipartUpload(key, options) {
        const upload = await env.BACKUPS!.createMultipartUpload(key, options);
        orphanId = upload.uploadId;
        entered.resolve();
        await release.promise;
        return {
          key,
          uploadId: upload.uploadId,
          abort: () => {
            oldWrites++;
            return upload.abort();
          },
          uploadPart: (number, body) => {
            oldWrites++;
            return upload.uploadPart(number, body);
          },
          complete: (parts) => {
            oldWrites++;
            return upload.complete(parts);
          },
        };
      },
    });
    const old = advanceBackup({ ...env, BACKUPS: bucket });
    await entered.promise;
    await expireLease(id);
    await advanceBackup(env);
    const winner = await job(id);
    release.resolve();
    await expect(old).resolves.toBeUndefined();
    expect(oldWrites).toBe(0);
    expect(winner.upload_id).not.toBe(orphanId);
    expect(await job(id)).toMatchObject({
      status: 'complete',
      upload_id: winner.upload_id,
      ...expected,
    });
  });

  it('detaches an expired session before abort and cannot reset or replace the next owner session', async () => {
    const id = await startBackup(env, actor);
    const expected = await totals(id);
    const upload = await env.BACKUPS!.createMultipartUpload(`backups/${id}.ndjson`, {
      customMetadata: {
        schema_version: '1',
        created_at: String((await job(id)).created_at),
        consistency: 'atomic-d1-snapshot',
      },
    });
    await env.DB.prepare(
      "UPDATE backup_jobs SET status='uploading',upload_id=?,upload_started_at=? WHERE id=?",
    )
      .bind(upload.uploadId, now - 7 * 86400000, id)
      .run();
    const entered = deferred(),
      release = deferred();
    let oldCreates = 0;
    const bucket = wrappedBucket({
      createMultipartUpload(key, options) {
        oldCreates++;
        return env.BACKUPS!.createMultipartUpload(key, options);
      },
      resumeMultipartUpload(key, uploadId) {
        const captured = env.BACKUPS!.resumeMultipartUpload(key, uploadId);
        return {
          key,
          uploadId,
          uploadPart: (number, body) => captured.uploadPart(number, body),
          complete: (parts) => captured.complete(parts),
          async abort() {
            await captured.abort();
            entered.resolve();
            await release.promise;
          },
        };
      },
    });
    const old = advanceBackup({ ...env, BACKUPS: bucket });
    await entered.promise;
    expect((await job(id)).upload_id).toBeNull();
    await expireLease(id);
    await advanceBackup(env);
    const winner = await job(id);
    release.resolve();
    await expect(old).resolves.toBeUndefined();
    expect(oldCreates).toBe(0);
    expect(winner.upload_id).not.toBe(upload.uploadId);
    expect(await job(id)).toMatchObject({
      status: 'complete',
      upload_id: winner.upload_id,
      ...expected,
    });
  });

  it('keeps each released and renewed lease generation unique in the same millisecond', async () => {
    const id = await startBackup(env, actor);
    const generations: number[] = [];
    const bucket = wrappedBucket({
      async createMultipartUpload() {
        generations.push((await job(id)).lease_until);
        throw new Error('fixture creation temporarily unavailable');
      },
    });
    for (let attempt = 0; attempt < 3; attempt++) {
      // Force an explicit local retry while retaining the same millisecond so
      // this test continues to isolate monotonic lease generations.
      await env.DB.prepare('UPDATE backup_jobs SET retry_at=NULL WHERE id=?').bind(id).run();
      await expect(advanceBackup({ ...env, BACKUPS: bucket })).rejects.toThrow(
        'BACKUP_STORAGE_OR_DATABASE_UNAVAILABLE',
      );
      expect((await job(id)).lease_until).toBe(-generations.at(-1)!);
    }
    expect(new Set(generations).size).toBe(3);
    expect(generations[1]).toBeGreaterThan(generations[0]);
    expect(generations[2]).toBeGreaterThan(generations[1]);
  });

  it('restarts the same snapshot after an uncompleted multipart fails completion', async () => {
    const id = await startBackup(env, actor);
    const expected = await totals(id);
    const bucket = wrappedBucket({
      async createMultipartUpload(key, options) {
        const upload = await env.BACKUPS!.createMultipartUpload(key, options);
        return {
          key,
          uploadId: upload.uploadId,
          abort: () => upload.abort(),
          uploadPart: (number, body) => upload.uploadPart(number, body),
          complete: async () => {
            throw new Error('fixture outdated part etag');
          },
        };
      },
    });
    await advanceBackup({ ...env, BACKUPS: bucket });
    expect(await totals(id)).toEqual(expected);
    expect(await job(id)).toMatchObject({
      status: 'uploading',
      upload_id: null,
      size: 0,
      records: 0,
    });
    await advanceBackup(env);
    expect(await job(id)).toMatchObject({ status: 'complete', ...expected });
    expect((await totals(id)).records).toBe(0);
  });

  it('survives a previously launched part reaching R2 after the next owner checkpointed that same part', async () => {
    await largeFixture();
    const id = await startBackup(env, actor);
    const expected = await totals(id);
    const staged = await env.DB.prepare(
      'SELECT payload FROM backup_rows WHERE backup_id=? ORDER BY id',
    )
      .bind(id)
      .all<{ payload: string }>();
    const expectedBody = staged.results.map((row) => `${row.payload}\n`).join('');
    const entered = deferred(),
      release = deferred();
    let latePart = false;
    const bucket = wrappedBucket({
      async createMultipartUpload(key, options) {
        const upload = await env.BACKUPS!.createMultipartUpload(key, options);
        return {
          key,
          uploadId: upload.uploadId,
          abort: () => upload.abort(),
          complete: (parts) => upload.complete(parts),
          async uploadPart(number, body) {
            entered.resolve();
            await release.promise;
            latePart = true;
            return upload.uploadPart(number, body);
          },
        };
      },
    });
    const old = advanceBackup({ ...env, BACKUPS: bucket });
    await entered.promise;
    await expireLease(id);
    await advanceBackup(env);
    const checkpoint = await job(id);
    expect(checkpoint.status).toBe('uploading');
    release.resolve();
    await expect(old).resolves.toBeUndefined();
    expect(latePart).toBe(true);
    expect(await job(id)).toEqual(checkpoint);
    await advanceBackup(env);
    // A late overwrite can invalidate the winner's opaque part ETag even for
    // identical bytes. Restart that session while retaining the atomic snapshot.
    expect(await job(id)).toMatchObject({
      status: 'uploading',
      upload_id: null,
      size: 0,
      records: 0,
    });
    expect(await totals(id)).toEqual(expected);
    await advanceBackup(env);
    await advanceBackup(env);
    expect(await job(id)).toMatchObject({ status: 'complete', ...expected });
    expect(await (await env.BACKUPS!.get(`backups/${id}.ndjson`))!.text()).toBe(expectedBody);
  });

  it('ignores a previously launched completion that reaches R2 after the next owner completed', async () => {
    const id = await startBackup(env, actor);
    const expected = await totals(id);
    const entered = deferred(),
      release = deferred();
    let lateComplete = false;
    const bucket = wrappedBucket({
      async createMultipartUpload(key, options) {
        const upload = await env.BACKUPS!.createMultipartUpload(key, options);
        return {
          key,
          uploadId: upload.uploadId,
          abort: () => upload.abort(),
          uploadPart: (number, body) => upload.uploadPart(number, body),
          async complete(parts) {
            entered.resolve();
            await release.promise;
            lateComplete = true;
            return upload.complete(parts);
          },
        };
      },
    });
    const old = advanceBackup({ ...env, BACKUPS: bucket });
    await entered.promise;
    await expireLease(id);
    await advanceBackup(env);
    const winner = await job(id);
    now++;
    release.resolve();
    await expect(old).resolves.toBeUndefined();
    expect(lateComplete).toBe(true);
    expect(await job(id)).toEqual(winner);
    expect(winner).toMatchObject({ status: 'complete', ...expected });
    expect((await env.BACKUPS!.head(`backups/${id}.ndjson`))?.size).toBe(expected.size);
  });

  it('keeps all staging rows when an old completion transaction executes after takeover', async () => {
    const id = await startBackup(env, actor);
    const expected = await totals(id);
    const entered = deferred(),
      release = deferred();
    const nextEntered = deferred(),
      nextRelease = deferred();
    const db = {
      prepare: (sql: string) => env.DB.prepare(sql),
      async batch(statements: D1PreparedStatement[]) {
        entered.resolve();
        await release.promise;
        return env.DB.batch(statements);
      },
    } as D1Database;
    const old = advanceBackup({ ...env, DB: db });
    await entered.promise;
    await expireLease(id);
    const bucket = wrappedBucket({
      async head(key) {
        const object = await env.BACKUPS!.head(key);
        nextEntered.resolve();
        await nextRelease.promise;
        return object;
      },
    });
    const next = advanceBackup({ ...env, BACKUPS: bucket });
    await nextEntered.promise;
    const currentLease = (await job(id)).lease_until;
    release.resolve();
    await expect(old).resolves.toBeUndefined();
    expect(await totals(id)).toEqual(expected);
    expect(await job(id)).toMatchObject({ status: 'uploading', lease_until: currentLease });
    nextRelease.resolve();
    await next;
    expect(await job(id)).toMatchObject({ status: 'complete', ...expected });
    expect((await totals(id)).records).toBe(0);
  });

  it('preserves the snapshot when an existing object has mismatched size or metadata', async () => {
    const id = await startBackup(env, actor);
    const expected = await totals(id);
    const rows = await env.DB.prepare(
      'SELECT payload FROM backup_rows WHERE backup_id=? ORDER BY id',
    )
      .bind(id)
      .all<{ payload: string }>();
    const body = rows.results.map((row) => `${row.payload}\n`).join('');
    const metadata = {
      schema_version: '1',
      created_at: String((await job(id)).created_at),
      consistency: 'atomic-d1-snapshot',
    };
    await env.BACKUPS!.put(`backups/${id}.ndjson`, '{}\n', { customMetadata: metadata });
    await expect(advanceBackup(env)).rejects.toThrow('BACKUP_OBJECT_MISMATCH');
    expect(await totals(id)).toEqual(expected);
    expect((await job(id)).status).toBe('pending');
    await env.BACKUPS!.put(`backups/${id}.ndjson`, body, {
      customMetadata: { ...metadata, schema_version: 'unexpected' },
    });
    now += 600000;
    await expect(advanceBackup(env)).rejects.toThrow('BACKUP_OBJECT_MISMATCH');
    expect(await totals(id)).toEqual(expected);
    expect((await job(id)).status).toBe('pending');
  });

  it('tracks a retired key and cleans it again after a separate late multipart completion', async () => {
    now -= 31 * 86400000;
    const id = await startBackup(env, actor);
    const snapshot = await env.DB.prepare(
      'SELECT payload FROM backup_rows WHERE backup_id=? ORDER BY id',
    )
      .bind(id)
      .all<{ payload: string }>();
    const body = new TextEncoder().encode(
      snapshot.results.map((row) => `${row.payload}\n`).join(''),
    );
    const old = await env.BACKUPS!.createMultipartUpload(`backups/${id}.ndjson`, {
      customMetadata: {
        schema_version: '1',
        created_at: String((await job(id)).created_at),
        consistency: 'atomic-d1-snapshot',
      },
    });
    const oldPart = await old.uploadPart(1, body);
    now += 31 * 86400000;
    await advanceBackup(env);
    now += 31 * 86400000;
    await maintenance(env);
    expect(await env.BACKUPS!.head(`backups/${id}.ndjson`)).toBeNull();
    expect(await job(id)).toMatchObject({
      status: 'complete',
      retired_at: now,
      retention_checked_at: now,
      upload_id: null,
      size: 0,
      records: 0,
    });
    await old.complete([oldPart]);
    expect((await env.BACKUPS!.head(`backups/${id}.ndjson`))?.size).toBe(body.length);
    now += 600000;
    await maintenance(env);
    expect(await env.BACKUPS!.head(`backups/${id}.ndjson`)).toBeNull();
    expect((await job(id)).retention_checked_at).toBe(now);
  });

  it('rotates at most twenty retired keys per pass without touching active snapshots or other prefixes', async () => {
    const ids = Array.from({ length: 30 }, () => crypto.randomUUID());
    await env.DB.batch(
      ids.map((id) =>
        env.DB.prepare(
          "INSERT INTO backup_jobs(id,created_at,status,completed_at,retired_at) VALUES (?,1,'complete',1,1)",
        ).bind(id),
      ),
    );
    const activeId = crypto.randomUUID();
    await env.DB.prepare(
      "INSERT INTO backup_jobs(id,created_at,status,lease_until) VALUES (?,1,'uploading',?)",
    )
      .bind(activeId, now + 3600000)
      .run();
    await env.DB.prepare('INSERT INTO backup_rows(backup_id,payload) VALUES (?,?)')
      .bind(activeId, '{"fixture":"active snapshot"}')
      .run();
    await env.BACKUPS!.put(`backups/${activeId}.ndjson`, 'active fixture');
    await env.BACKUPS!.put('delivery/retention-fixture.json', 'unrelated fixture');
    const deleted: string[] = [];
    const bucket = {
      ...wrappedBucket({}),
      async delete(key: string) {
        deleted.push(key);
        await env.BACKUPS!.delete(key);
      },
    } as R2Bucket;
    await maintenance({ ...env, BACKUPS: bucket });
    expect(deleted).toHaveLength(20);
    expect(new Set(deleted).size).toBe(20);
    now += 600000;
    await maintenance({ ...env, BACKUPS: bucket });
    expect(deleted).toHaveLength(40);
    expect(new Set(deleted)).toEqual(new Set(ids.map((id) => `backups/${id}.ndjson`)));
    expect((await totals(activeId)).records).toBe(1);
    expect((await job(activeId)).status).toBe('uploading');
    expect(await env.BACKUPS!.head(`backups/${activeId}.ndjson`)).not.toBeNull();
    expect(await env.BACKUPS!.head('delivery/retention-fixture.json')).not.toBeNull();
  });

  it('retains a hidden cleanup marker when deletion fails and retries it in a later pass', async () => {
    const id = crypto.randomUUID();
    await env.DB.prepare(
      "INSERT INTO backup_jobs(id,created_at,status,completed_at) VALUES (?,1,'complete',1)",
    )
      .bind(id)
      .run();
    await env.BACKUPS!.put(`backups/${id}.ndjson`, 'retired fixture');
    const bucket = {
      ...wrappedBucket({}),
      async delete() {
        throw new Error('fixture deletion unavailable');
      },
    } as R2Bucket;
    await expect(maintenance({ ...env, BACKUPS: bucket })).rejects.toThrow(
      'BACKUP_RETENTION_RETRY_REQUIRED',
    );
    expect(await job(id)).toMatchObject({
      retired_at: now,
      retention_checked_at: now,
      upload_id: null,
    });
    expect(await env.BACKUPS!.head(`backups/${id}.ndjson`)).not.toBeNull();
    now += 600000;
    await maintenance(env);
    expect(await env.BACKUPS!.head(`backups/${id}.ndjson`)).toBeNull();
    expect((await job(id)).retention_checked_at).toBe(now);
  });
});
