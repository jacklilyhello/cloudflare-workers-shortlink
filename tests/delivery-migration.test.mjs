import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { classifyLegacy, importLink, migrate } from '../scripts/migrate-legacy.mjs';
import { ACCOUNT, EXPECTED } from '../scripts/cf-client.mjs';
import { validateRestrictedIPs, verifyIPCondition } from '../scripts/security-ip-policy.mjs';

const sha = (x, kind = 'sha256') => createHash(kind).update(x).digest('hex');
const dbId = '4e844b76-30b4-47e7-9d53-ff76c3e9a23a';
function fixture(records, pages) {
  const db = new DatabaseSync(':memory:');
  db.exec(readFileSync('migrations/0001.sql', 'utf8'));
  db.exec(readFileSync('migrations/0002_delivery.sql', 'utf8'));
  db.prepare('INSERT INTO domains(hostname,enabled,bound,created_at) VALUES (?,1,1,1)').run(
    'test.gfw.mom',
  );
  let failKey = '';
  const calls = [];
  const sql = async (text, params = []) => {
    const stmt = db.prepare(text);
    if (stmt.columns().length)
      return [{ success: true, results: stmt.all(...params), meta: { changes: 0 } }];
    const r = stmt.run(...params);
    return [{ success: true, results: [], meta: { changes: Number(r.changes) } }];
  };
  const client = {
    request: async (path, options = {}) => {
      calls.push({ path, options });
      if (path === `${ACCOUNT}/d1/database/${dbId}/query`)
        return { success: true, result: await sql(options.json.sql, options.json.params) };
      assert.equal(options.method, undefined, 'legacy KV is never written');
      const u = new URL(`https://x${path}`);
      assert.match(
        u.pathname,
        /\/storage\/kv\/namespaces\/5fad543837b4409898805eab154b5b84\/keys$/,
      );
      const cursor = u.searchParams.get('cursor') || '';
      const index = cursor ? Number(cursor.slice(1)) : 0;
      return {
        success: true,
        result: pages[index].map((name) => ({
          name,
          ...(records[name]?.metadata ? { metadata: records[name].metadata } : {}),
        })),
        result_info: { cursor: index + 1 < pages.length ? `p${index + 1}` : '' },
      };
    },
    optional: async (path) => {
      calls.push({ path, options: {} });
      const key = decodeURIComponent(path.split('/values/')[1]);
      if (key === failKey) {
        failKey = '';
        throw new Error('simulated interrupted page');
      }
      return records[key]?.value ?? null;
    },
  };
  return {
    db,
    sql,
    client,
    calls,
    manifest: { d1: { id: dbId } },
    failOnceAt: (key) => {
      failKey = key;
    },
  };
}

test('128-hex keys require value and pointer relation, never length-based discard', async () => {
  const url = 'https://example.com/a?q=a%2Bb#part';
  const key = sha(url, 'sha512');
  assert.deepEqual(await classifyLegacy(key, 'saved-slug', async () => url), {
    kind: 'skipped',
    reason: 'verified_sha512_reverse_index',
  });
  assert.equal((await classifyLegacy(key, url, async () => null)).kind, 'link');
  assert.equal(
    (await classifyLegacy('a'.repeat(128), 'saved-slug', async () => url)).kind,
    'unknown',
  );
  let read = false;
  assert.equal(
    (
      await classifyLegacy('SYS_CONFIG_API_TOKEN', null, async () => {
        read = true;
      })
    ).kind,
    'skipped',
  );
  assert.equal(read, false);
});
test('unsafe targets and reserved legacy slugs remain reviewable unknowns', async () => {
  for (const value of [
    'https:///example.com',
    'https://@example.com',
    'https://example.com/%ZZ',
    'https://example.com\\evil',
    'https://example.com/\ud800',
  ])
    assert.equal((await classifyLegacy('safe', value, async () => null)).kind, 'unknown');
  for (const slug of ['api', 'Admin', 'logout', 'config', '_internal', 'static'])
    assert.equal(
      (await classifyLegacy(slug, 'https://example.com/', async () => null)).kind,
      'unknown',
    );
});
test('true SQLite import preserves mapping, exact URL, unknown timestamp and stable legacy id; conflicts never overwrite', async () => {
  const f = fixture({}, [[]]);
  const original = 'https://example.com/a?sig=a%2Bb&x=1#frag';
  const a = await importLink(f.sql, 'test.gfw.mom', 'long-code', original, {}, 100);
  assert.equal(a.status, 'imported');
  assert.equal(a.reason, 'mapping_verified_creation_time_unknown');
  const row = f.db.prepare('SELECT * FROM links WHERE slug=?').get('long-code');
  assert.equal(row.url, original);
  assert.equal(row.created_at, null);
  assert.match(row.id, /^legacy:[a-f\d]{64}$/);
  assert.equal(row.query_mode, 'preserve');
  assert.equal(row.enabled, 1);
  assert.equal(
    (await importLink(f.sql, 'test.gfw.mom', 'long-code', original, { createdAt: 123 }, 100))
      .status,
    'unchanged',
  );
  assert.equal(
    (await importLink(f.sql, 'test.gfw.mom', 'long-code', 'https://other.example/', {}, 100))
      .status,
    'conflict',
  );
  assert.equal(f.db.prepare('SELECT url FROM links WHERE slug=?').get('long-code').url, original);
  f.db.close();
});
test('existing creation time is preserved and not falsely reported as verified', async () => {
  const f = fixture({}, [[]]);
  const url = 'https://example.com/';
  await importLink(f.sql, 'test.gfw.mom', 'time', url, { createdAt: 123 }, 100);
  const result = await importLink(f.sql, 'test.gfw.mom', 'time', url, { createdAt: 456 }, 100);
  assert.equal(result.reason, 'mapping_verified_existing_creation_time_preserved');
  assert.equal(
    f.db.prepare('SELECT created_at FROM links WHERE slug=?').get('time').created_at,
    123,
  );
  f.db.close();
});
test('interrupted page resumes without duplicate mappings or double counting; a new full scan brings increments', async () => {
  const url = 'https://example.com/a?one=1#f';
  const index = sha(url, 'sha512');
  const records = {
    alpha: { value: url, metadata: { createdAt: 1234 } },
    beta: { value: 'https://example.com/b' },
    [index]: { value: 'alpha' },
    SYS_CONFIG_API_TOKEN: { value: 'private-old-token' },
  };
  const f = fixture(records, [
    ['alpha', 'beta'],
    [index, 'SYS_CONFIG_API_TOKEN'],
  ]);
  f.failOnceAt('beta');
  await assert.rejects(migrate({ client: f.client, manifest: f.manifest, maxPages: 1 }));
  const run = f.db.prepare('SELECT * FROM legacy_migration_runs').get();
  assert.equal(run.cursor, '');
  const resume = await migrate({
    client: f.client,
    manifest: f.manifest,
    resume: run.id,
    maxPages: 1,
  });
  assert.equal(resume.state, 'running');
  assert.equal(resume.processed_observations, 2);
  const done = await migrate({
    client: f.client,
    manifest: f.manifest,
    resume: run.id,
    maxPages: 1,
  });
  assert.equal(done.state, 'complete');
  assert.equal(done.imported, 2);
  assert.equal(done.skipped, 2);
  assert.equal(done.fully_verified, true);
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM links').get().n, 2);
  records.beta.value = 'https://example.com/new-target'; // Existing old mapping changes are conflicts.
  const increment = await migrate({ client: f.client, manifest: f.manifest, maxPages: 2 });
  assert.equal(increment.conflicts, 1);
  assert.equal(increment.fully_verified, false);
  assert.equal(
    f.db.prepare("SELECT url FROM links WHERE slug='beta'").get().url,
    'https://example.com/b',
  );
  assert.ok(f.calls.filter((c) => c.path.includes('/storage/kv/')).every((c) => !c.options.method));
  assert.doesNotMatch(JSON.stringify(done), /private-old-token|example\.com\/a|alpha|beta/);
  f.db.close();
});
test('production rejects full IPv4/IPv6 allowances including CIDR unions; real restricted lists remain CF-owned', async () => {
  for (const ips of [
    ['0.0.0.0/0'],
    ['::/0'],
    ['0.0.0.0/1', '128.0.0.0/1'],
    ['::/1', '8000::/1'],
    [],
  ])
    assert.throws(() => validateRestrictedIPs(ips));
  assert.deepEqual(validateRestrictedIPs(['192.0.2.10', '2001:db8::/48', '::ffff:192.0.2.10']), {
    restricted: true,
    item_count: 3,
  });
  const results = [];
  const client = {
    request: async (path) => {
      results.push(path);
      return {
        result: path.includes('/items')
          ? [{ ip: '192.0.2.10' }, { ip: '2001:db8::/48' }]
          : [{ id: 'a'.repeat(32), name: 'shortlink_api_allowlist', kind: 'ip' }],
        result_info: { cursors: {} },
      };
    },
  };
  assert.deepEqual(await verifyIPCondition(client, 'ip.src in $shortlink_api_allowlist'), {
    restricted: true,
    item_count: 2,
  });
  assert.equal(results.length, 2);
  assert.ok(results.every((p) => p.startsWith(`${ACCOUNT}/rules/lists`)));
});
