import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import {
  ACCOUNT,
  EXPECTED,
  DATABASE,
  BUCKET,
  OWNER_KEY,
  REPOSITORY,
} from '../scripts/cf-client.mjs';
import { objectPath } from '../scripts/deploy-resources.mjs';
import {
  CONFIRMATION,
  SELECTS,
  readClient,
  verifyBackupBytes,
  main,
} from '../scripts/verify-iteration.mjs';
const owner = '00000000-0000-4000-8000-000000000001',
  database = '00000000-0000-4000-8000-000000000002',
  backup = '00000000-0000-4000-8000-000000000003',
  run = '00000000-0000-4000-8000-000000000004';
const secret = 'PRIVATE_BUSINESS_TOKEN_OR_URL';
const manifest = {
  schema: 1,
  project: REPOSITORY,
  account: EXPECTED.CLOUDFLARE_ACCOUNT_ID,
  worker: EXPECTED.WORKER_NAME,
  environment: 'test',
  bucket: BUCKET,
  owner_id: owner,
  d1: { name: DATABASE, id: database },
  worker_created: true,
  domains: {},
};
const sha = (value) => createHash('sha256').update(value).digest('hex');
const rows = [
  {
    table: 'delivery_ownership',
    data: {
      singleton: 1,
      project: manifest.project,
      owner_id: owner,
      account_id: manifest.account,
      worker: manifest.worker,
    },
  },
  { table: 'domains', data: { hostname: 'test.gfw.mom', binding_state: 'verified' } },
  { table: 'settings', data: { key: 'backup_enabled', value: '1' } },
  { table: 'automation_locks', data: { name: 'legacy-migration', lease_until: 0 } },
  {
    table: 'links',
    data: { id: 'fixture', slug: 'fixture', url: `https://example.test/${secret}` },
  },
];
const raw = rows.map((row) => JSON.stringify(row) + '\n').join('');
const size = Buffer.byteLength(raw),
  digest = sha(`${size}:${sha(raw)}\n`);
const job = {
  id: backup,
  created_at: 100,
  status: 'complete',
  completed_at: 200,
  size,
  records: rows.length,
  snapshot_digest: digest,
  object_digest: digest,
  actor: 'system:scheduled',
};
const env = {
  ...EXPECTED,
  GITHUB_ACTIONS: 'true',
  GITHUB_EVENT_NAME: 'workflow_dispatch',
  GITHUB_REPOSITORY: REPOSITORY,
  GITHUB_REF: 'refs/heads/main',
  CONFIRM_TARGET: CONFIRMATION,
  CLOUDFLARE_API_TOKEN: 'fixture-secret',
};
const response = (result) =>
  new Response(JSON.stringify({ success: true, result }), {
    headers: { 'Content-Type': 'application/json' },
  });
const settings = {
  backup_enabled: '1',
  backup_interval_hours: '1',
  backup_retention_days: '0',
  analytics_retention_days: '0',
  audit_retention_days: '0',
  migration_enabled: '1',
  migration_interval_hours: '1',
};
function fixture(url, options) {
  const path = new URL(url).pathname.slice('/client/v4'.length);
  if (path === objectPath(OWNER_KEY)) return new Response(JSON.stringify(manifest));
  if (path === `${ACCOUNT}/d1/database/${database}`)
    return response({ uuid: database, name: DATABASE });
  if (path === `${ACCOUNT}/workers/scripts/${EXPECTED.WORKER_NAME}/settings`)
    return response({
      bindings: [
        { name: 'RESOURCE_OWNER_ID', type: 'plain_text', text: owner },
        { name: 'DB', type: 'd1', id: database },
        { name: 'BACKUPS', type: 'r2_bucket', bucket_name: BUCKET },
      ],
    });
  if (path === `${ACCOUNT}/d1/database/${database}/query`) {
    const sql = JSON.parse(options.body).sql;
    let data;
    if (sql === SELECTS.owner)
      data = [
        {
          project: manifest.project,
          owner_id: owner,
          account_id: manifest.account,
          worker: manifest.worker,
        },
      ];
    if (sql === SELECTS.schema)
      data = [
        { name: 'links_global_slug', type: 'index' },
        { name: 'deleted_links', type: 'table' },
        { name: 'automation_locks', type: 'table' },
      ];
    if (sql === SELECTS.settings)
      data = Object.entries(settings).map(([key, value]) => ({ key, value }));
    if (sql === SELECTS.counts)
      data = [
        {
          links: 1,
          tombstones: 1,
          active_domains: 1,
          migration_runs: 1,
          migration_observations: 3,
          retained_complete_backups: 1,
        },
      ];
    if (sql === SELECTS.migration)
      data = [
        {
          id: run,
          state: 'complete',
          processed: 3,
          imported: 1,
          unchanged: 0,
          skipped: 1,
          conflicts: 0,
          unknown: 1,
          started_at: 1,
          updated_at: 200,
          completed_at: 200,
          attempts: 0,
          retry_at: null,
          last_error_code: null,
          cursor_present: 0,
        },
      ];
    if (sql === SELECTS.automation)
      data = [
        {
          lease_until: 0,
          last_success_at: 200,
          attempts: 0,
          retry_at: null,
          last_error_code: null,
        },
      ];
    if (sql === SELECTS.scheduled)
      data = [{ ...job, attempts: 0, retry_at: null, last_error_code: null }];
    if (sql === SELECTS.completed) data = [job];
    assert.ok(data, 'only fixed reviewed SELECTs');
    return response([{ success: true, results: data }]);
  }
  if (path === `${ACCOUNT}/r2/buckets/${BUCKET}/objects`)
    return response([
      {
        key: `backups/${backup}.ndjson`,
        size,
        etag: 'fixture-etag',
        custom_metadata: {
          created_at: '100',
          schema_version: '1',
          consistency: 'atomic-d1-snapshot',
        },
      },
    ]);
  if (path === objectPath(`backups/${backup}.ndjson`)) return new Response(raw);
  throw new Error('unexpected endpoint');
}

test('fixed owned verification reads actual backup bytes, emits only aggregate counters and digest proof', async () => {
  const calls = [];
  const report = await main([], env, {
    now: () => 300,
    fetcher: async (url, options) => {
      calls.push({ url, options });
      return fixture(url, options);
    },
  });
  assert.equal(report.exit_code, 0);
  assert.equal(report.automatic_backup_verified, true);
  assert.equal(report.completed_backup.object_digest, digest);
  assert.equal(report.completed_backup.records, rows.length);
  assert.equal(report.counters.tombstones, 1);
  assert.doesNotMatch(
    JSON.stringify(report),
    new RegExp(`${secret}|fixture-secret|owner_id|example\\.test`),
  );
  for (const call of calls) {
    assert.equal(new URL(call.url).hostname, 'api.cloudflare.com');
    assert.equal(call.options.redirect, 'error');
    if (call.options.method === 'POST') {
      const body = JSON.parse(call.options.body);
      assert.ok(Object.values(SELECTS).includes(body.sql));
      assert.deepEqual(body.params, []);
      assert.match(body.sql, /^SELECT /);
    }
  }
});
test('digest mismatches and a foreign snapshot owner fail closed even when metadata is plausible', () => {
  assert.throws(
    () => verifyBackupBytes(raw, { ...job, object_digest: 'f'.repeat(64) }, manifest),
    (error) => error.code === 'ITERATION_BACKUP_DIGEST_MISMATCH',
  );
  const foreign = raw.replace(owner, '00000000-0000-4000-8000-000000000099');
  const length = Buffer.byteLength(foreign),
    hash = sha(`${length}:${sha(foreign)}\n`);
  assert.throws(
    () =>
      verifyBackupBytes(
        foreign,
        { ...job, size: length, snapshot_digest: hash, object_digest: hash },
        manifest,
      ),
    (error) => error.code === 'ITERATION_BACKUP_OWNER_MISMATCH',
  );
});
test('read guard rejects arbitrary SQL, foreign objects and every non-query mutation', async () => {
  const client = readClient('fixture-secret', () => {
    throw new Error('must not fetch');
  });
  client.bindD1(database);
  client.bindBackup(backup);
  for (const [path, options] of [
    [
      `${ACCOUNT}/d1/database/${database}/query`,
      { method: 'POST', json: { sql: 'DELETE FROM links', params: [] } },
    ],
    [objectPath('delivery/foreign.json'), {}],
    [objectPath(`backups/${backup}.ndjson`), { method: 'PUT', body: 'x' }],
    [`${ACCOUNT}/workers/scripts/${EXPECTED.WORKER_NAME}`, { method: 'PUT', body: 'x' }],
  ])
    await assert.rejects(
      client.request(path, options),
      (error) => error.code === 'ITERATION_READ_SCOPE_FORBIDDEN',
    );
});
test('workflow is manual main-only and exposes the CF credential only to its final read step', () => {
  const text = readFileSync('.github/workflows/verify-iteration.yml', 'utf8');
  assert.match(text, /workflow_dispatch:/);
  assert.doesNotMatch(text, /schedule:|wrangler|TURNSTILE_SECRET_KEY|CF_ANALYTICS_READ_TOKEN/);
  assert.match(text, /github\.ref == 'refs\/heads\/main'/);
  assert.equal((text.match(/secrets\.CLOUDFLARE_API_TOKEN/g) || []).length, 1);
  assert.ok(text.indexOf('secrets.CLOUDFLARE_API_TOKEN') > text.indexOf('npm run check'));
});
