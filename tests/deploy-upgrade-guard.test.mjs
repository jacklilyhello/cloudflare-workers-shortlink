import test from 'node:test';
import assert from 'node:assert/strict';
import { verifyGlobalUpgradeBackup } from '../scripts/deploy-upgrade-guard.mjs';
import { EXPECTED, BUCKET, DATABASE, ACCOUNT } from '../scripts/cf-client.mjs';
import { objectPath } from '../scripts/deploy-resources.mjs';

function fixture() {
  const now = 1791175200000;
  const manifest = {
    schema: 1,
    project: 'jacklilyhello/cloudflare-workers-shortlink',
    account: EXPECTED.CLOUDFLARE_ACCOUNT_ID,
    worker: EXPECTED.WORKER_NAME,
    environment: 'test',
    owner_id: '09c9fca5-d203-4fbe-b380-c17103b95a01',
    bucket: BUCKET,
    domains: {},
    d1: { name: DATABASE, id: 'ce123456-0a45-4da3-bbf1-738ae3134a9c' },
  };
  const owner = {
    singleton: 1,
    owner_id: manifest.owner_id,
    project: manifest.project,
    worker: manifest.worker,
    account_id: manifest.account,
  };
  let content =
    [
      {
        table: 'links',
        data: { id: 'link-id', slug: 'short', url: 'https://private.invalid/?secret=private' },
      },
      { table: 'delivery_ownership', data: owner },
    ]
      .map((row) => JSON.stringify(row))
      .join('\n') + '\n';
  const job = {
    id: '971feb32-69e6-4cb2-b12a-80a5c2d1ae84',
    created_at: now - 60000,
    completed_at: now - 30000,
    size: Buffer.byteLength(content),
    records: 2,
  };
  const state = { upgraded: false, links: 1, conflicts: 0, job, content, checkpoint: null };
  const calls = [];
  const client = {
    request: async (path, options = {}) => {
      calls.push({ path, ...options });
      if (path === `${ACCOUNT}/d1/database/${manifest.d1.id}/query`) {
        assert.equal(options.method, 'POST');
        const sql = options.json.sql;
        let rows;
        if (sql.includes('sqlite_master'))
          rows = state.upgraded
            ? [{ name: 'links_global_slug', type: 'index' }]
            : [{ name: 'links', type: 'table' }];
        else if (sql.includes('GROUP BY')) rows = [{ count: state.conflicts }];
        else if (sql.includes('backup_jobs')) rows = state.job ? [state.job] : [];
        else rows = [{ count: state.links }];
        return { result: [{ success: true, results: rows }] };
      }
      if (path.includes('/objects?prefix='))
        return {
          result: [
            {
              key: `backups/${job.id}.ndjson`,
              size: state.job.size,
              etag: 'etag',
              custom_metadata: {
                schema_version: '1',
                created_at: String(state.job.created_at),
                consistency: 'atomic-d1-snapshot',
              },
            },
          ],
          result_info: { is_truncated: false },
        };
      if (path === objectPath(`backups/${job.id}.ndjson`)) {
        assert.equal(options.raw, true);
        return state.content;
      }
      assert.equal(
        path,
        objectPath(`delivery/${manifest.owner_id}/pre-global-upgrade-backup-${job.id}.json`),
      );
      assert.equal(options.method, 'PUT');
      state.checkpoint = options.body;
      return { result: {} };
    },
    optional: async () => state.checkpoint,
  };
  return { now, manifest, state, calls, client };
}
test('0005 guard reads the private completed snapshot, verifies counts/owner and saves its first immutable digest', async () => {
  const f = fixture();
  const proof = await verifyGlobalUpgradeBackup(f.client, f.manifest, { now: () => f.now });
  assert.equal(proof.link_records, 1);
  assert.equal(proof.records, 2);
  assert.match(proof.sha256, /^[a-f\d]{64}$/);
  assert.doesNotMatch(JSON.stringify(proof), /private\.invalid|secret/);
  const saved = f.state.checkpoint;
  await verifyGlobalUpgradeBackup(f.client, f.manifest, { now: () => f.now });
  assert.equal(f.state.checkpoint, saved);
  assert.equal(f.calls.filter((c) => c.method === 'PUT').length, 1);
});
test('0005 guard refuses missing, expired, wrong-size and wrong-count backups before schema or resource changes', async () => {
  for (const [change, code] of [
    [
      (f) => {
        f.state.job = null;
      },
      'PRE_UPGRADE_RECENT_COMPLETE_BACKUP_REQUIRED',
    ],
    [
      (f) => {
        f.state.job.created_at = f.now - 2 * 86400000;
      },
      'PRE_UPGRADE_RECENT_COMPLETE_BACKUP_REQUIRED',
    ],
    [
      (f) => {
        f.state.job.size++;
      },
      'PRE_UPGRADE_BACKUP_SIZE_MISMATCH',
    ],
    [
      (f) => {
        f.state.job.records++;
      },
      'PRE_UPGRADE_BACKUP_RECORDS_MISMATCH',
    ],
    [
      (f) => {
        f.state.links = 2;
      },
      'PRE_UPGRADE_BACKUP_MAPPING_COUNT_DRIFT',
    ],
    [
      (f) => {
        f.state.conflicts = 1;
      },
      'GLOBAL_SHORTCODE_CONFLICT_PRESERVED',
    ],
  ]) {
    const f = fixture();
    change(f);
    await assert.rejects(verifyGlobalUpgradeBackup(f.client, f.manifest, { now: () => f.now }), {
      code,
    });
    assert.ok(f.calls.every((c) => c.method !== 'PUT'));
  }
});
test('already upgraded and empty new databases do not create duplicate backup checkpoints', async () => {
  const f = fixture();
  f.state.upgraded = true;
  assert.equal(
    (await verifyGlobalUpgradeBackup(f.client, f.manifest)).global_namespace_already_upgraded,
    true,
  );
  assert.equal(f.calls.length, 1);
  const empty = fixture();
  empty.state.links = 0;
  assert.equal(
    (await verifyGlobalUpgradeBackup(empty.client, empty.manifest)).no_existing_mappings,
    true,
  );
  assert.equal(empty.calls.length, 2);
});
test('a corrupted ownership record or a modified original checkpoint fails closed', async () => {
  const f = fixture();
  f.state.content = f.state.content.replace(
    f.manifest.owner_id,
    'ffffffff-ffff-ffff-ffff-ffffffffffff',
  );
  await assert.rejects(verifyGlobalUpgradeBackup(f.client, f.manifest, { now: () => f.now }), {
    code: 'PRE_UPGRADE_BACKUP_OWNERSHIP_UNPROVEN',
  });
  const valid = fixture();
  await verifyGlobalUpgradeBackup(valid.client, valid.manifest, { now: () => valid.now });
  valid.state.checkpoint = JSON.stringify({
    ...JSON.parse(valid.state.checkpoint),
    sha256: '0'.repeat(64),
  });
  await assert.rejects(
    verifyGlobalUpgradeBackup(valid.client, valid.manifest, { now: () => valid.now }),
    { code: 'PRE_UPGRADE_BACKUP_CHECKPOINT_DRIFT' },
  );
});
