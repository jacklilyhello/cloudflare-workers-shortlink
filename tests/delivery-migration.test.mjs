import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { classifyLegacy, importLink, migrate } from '../scripts/migrate-legacy.mjs';
import {
  ACCOUNT,
  EXPECTED,
  createCFClient,
  DeliveryError,
  safeError,
} from '../scripts/cf-client.mjs';
import { validateRestrictedIPs, verifyIPCondition } from '../scripts/security-ip-policy.mjs';
import {
  isNewSlug,
  isSafeLegacySlug,
  decodeLegacyPath,
  encodeLegacySlug,
} from '../src/legacy-slug.mjs';

const sha = (x, kind = 'sha256') => createHash(kind).update(x).digest('hex');
const dbId = '4e844b76-30b4-47e7-9d53-ff76c3e9a23a';

test('legacy slug grammar preserves permitted characters and exact normalization forms', () => {
  for (const slug of [
    'a.b',
    ' leading',
    'trailing ',
    'two spaces',
    '中文',
    'é',
    'e\u0301',
    '数字１２',
    "it's-saved",
    '（已存）',
    '（）',
  ]) {
    assert.equal(isSafeLegacySlug(slug), true, slug);
    assert.equal(isNewSlug(slug), false, slug);
    const encoded = encodeLegacySlug(slug);
    assert.equal(encoded.includes("'"), false);
    assert.equal(decodeURIComponent(encoded), slug);
    assert.deepEqual(decodeLegacyPath(`/${encoded}`), { slug, requiresMigration: true });
  }
  assert.notEqual(encodeLegacySlug('é'), encodeLegacySlug('e\u0301'));
  assert.equal(isNewSlug('Normal_code-12'), true);
  assert.equal(encodeLegacySlug('Normal_code-12'), 'Normal_code-12');
  assert.equal(isNewSlug('SYS_CONFIG_new'), true, 'existing new ASCII grammar stays unchanged');
  assert.equal(isSafeLegacySlug('SYS_CONFIG_new'), false);
});

test('legacy slug validation rejects dangerous characters, reserved paths and excess UTF-8 bytes', () => {
  for (const slug of [
    '',
    '.',
    '..',
    'API',
    'admin',
    'assets',
    'static',
    'Robots.txt',
    'favicon.ico',
    'status.css',
    'index.html',
    'SYS_CONFIG_saved',
    'a/b',
    'a\\b',
    'a%27b',
    'a:b',
    'a@b',
    'a+b',
    'a?b',
    'a#b',
    'a!b',
    'a*b',
    '(old)',
    'a\u0000b',
    'a\u007fb',
    'a\u202eb',
    'a\u200bb',
    'a\u034fb',
    'a\ufe0fb',
    'a\ue000b',
    'a\u0378b',
    'a\ud800b',
    'a\udc00b',
    'a😀b',
  ]) {
    assert.equal(isSafeLegacySlug(slug), false, JSON.stringify(slug));
  }
  assert.equal(isSafeLegacySlug('a'.repeat(512)), true);
  assert.equal(isSafeLegacySlug('a'.repeat(513)), false);
  const exact = '路'.repeat(170) + 'ab';
  assert.equal(Buffer.byteLength(exact), 512);
  assert.equal(isSafeLegacySlug(exact), true);
  assert.equal(isSafeLegacySlug(`${exact}c`), false);
});

test('legacy paths decode once and mark every encoding fallback as migration-only', () => {
  assert.deepEqual(decodeLegacyPath('/Normal_code'), {
    slug: 'Normal_code',
    requiresMigration: false,
  });
  assert.deepEqual(decodeLegacyPath('/%4eormal_code'), {
    slug: 'Normal_code',
    requiresMigration: true,
  });
  assert.deepEqual(decodeLegacyPath('/a%2eb'), { slug: 'a.b', requiresMigration: true });
  assert.deepEqual(decodeLegacyPath('/it%27s'), { slug: "it's", requiresMigration: true });
  assert.deepEqual(decodeLegacyPath(`/${'a'.repeat(65)}`), {
    slug: 'a'.repeat(65),
    requiresMigration: true,
  });
  const exact = 'Ā'.repeat(256);
  assert.equal(Buffer.byteLength(exact), 512);
  assert.equal(encodeLegacySlug(exact).length, 1536);
  assert.deepEqual(decodeLegacyPath(`/${encodeLegacySlug(exact)}`), {
    slug: exact,
    requiresMigration: true,
  });
  for (const path of [
    '',
    '/',
    'one',
    '/one/',
    '/one/two',
    '/%61pi',
    '/%61dmin',
    '/robots%2etxt',
    '/status%2Ecss',
    '/%2e',
    '/%2e%2e',
    '/one%2ftwo',
    '/one%5ctwo',
    '/one%2527two',
    '/%25',
    '/%00',
    '/%ff',
    '/%c0%af',
    '/%ed%a0%80',
    '/%e4%b8',
    '/%',
    '/%1',
    '/%gg',
    '/%53YS_CONFIG_saved',
    `/${encodeLegacySlug(exact)}%41`,
  ]) {
    assert.equal(decodeLegacyPath(path), null, path);
  }
});

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
    optional: async (path, options = {}) => {
      calls.push({ path, options });
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
test('hash pointers cannot indirectly read excluded system configuration values', async () => {
  let reads = 0;
  assert.deepEqual(
    await classifyLegacy('a'.repeat(128), 'SYS_CONFIG_API_TOKEN', async () => {
      reads++;
      return 'private-old-token';
    }),
    { kind: 'unknown', reason: 'hash_index_configuration_target_excluded' },
  );
  assert.equal(reads, 0);
});

test('safe legacy punctuation and Unicode import as exact permanent binary mappings', async () => {
  const slugs = ['dot.code', ' leading', 'trailing ', '中文', 'é', 'e\u0301', "it's", '（已存）'];
  const target = 'https://example.com/original?q=a+b&q=a%20b&sig=a%2Bb#fragment';
  const records = Object.fromEntries(slugs.map((slug) => [slug, { value: target }]));
  const f = fixture(records, [slugs]);
  const report = await migrate({ client: f.client, manifest: f.manifest });
  assert.equal(report.imported, slugs.length);
  assert.equal(report.unknown, 0);
  for (const slug of slugs) {
    const row = f.db
      .prepare('SELECT * FROM links WHERE domain=? AND slug=?')
      .get('test.gfw.mom', slug);
    assert.equal(row.slug, slug);
    assert.equal(row.url, target);
    assert.equal(row.source, 'migration');
    assert.equal(row.query_mode, 'preserve');
    assert.equal(row.id, `legacy:${sha(`test.gfw.mom\0${slug}`)}`);
  }
  const original = f.db
    .prepare('SELECT * FROM legacy_migration_runs WHERE id=?')
    .get(report.run_id);
  records['dot.code'].value = 'https://example.com/changed';
  const next = await migrate({ client: f.client, manifest: f.manifest });
  assert.equal(next.unchanged, slugs.length - 1);
  assert.equal(next.conflicts, 1);
  assert.equal(next.imported, 0);
  assert.equal(next.fully_verified, false);
  assert.equal(f.db.prepare('SELECT url FROM links WHERE slug=?').get('dot.code').url, target);
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM links').get().n, slugs.length);
  assert.deepEqual(
    f.db.prepare('SELECT * FROM legacy_migration_runs WHERE id=?').get(report.run_id),
    original,
  );
  f.db.close();
});

test('extended and long legacy collisions with non-migration sources remain conflicts without changing any field', async () => {
  const url = 'https://example.com/existing?signature=a%2Bb#fragment';
  const slugs = ['dot.code', 'a'.repeat(65)];
  const records = Object.fromEntries(slugs.map((slug) => [slug, { value: url }]));
  const f = fixture(records, [slugs]);
  for (const [index, slug] of slugs.entries()) {
    f.db
      .prepare(
        "INSERT INTO links(id,domain,slug,url,created_at,expires_at,enabled,confirm_enabled,confirm_text,query_mode,source,creator) VALUES(?,?,?,?,123,456,0,1,'existing administrator text','merge','admin','fixture-existing-admin')",
      )
      .run(`existing-fixture-${index}`, 'test.gfw.mom', slug, url);
  }
  const before = f.db.prepare('SELECT * FROM links ORDER BY slug').all();
  const report = await migrate({ client: f.client, manifest: f.manifest });
  assert.equal(report.conflicts, 2);
  assert.equal(report.imported, 0);
  assert.equal(report.unchanged, 0);
  assert.equal(report.fully_verified, false);
  assert.deepEqual(f.db.prepare('SELECT * FROM links ORDER BY slug').all(), before);
  const observations = f.db.prepare('SELECT status,reason FROM legacy_migration_items').all();
  assert.equal(observations.length, 2);
  for (const observation of observations)
    assert.deepEqual(
      { ...observation },
      {
        status: 'conflict',
        reason: 'existing_mapping_source_not_routable_never_overwritten',
      },
    );
  f.db.close();
});

test('ordinary ASCII existing non-migration mappings with the same URL remain unchanged', async () => {
  const slug = 'ordinary_ASCII-64';
  const url = 'https://example.com/existing?signature=a%2Bb#fragment';
  const f = fixture({ [slug]: { value: url } }, [[slug]]);
  f.db
    .prepare(
      "INSERT INTO links(id,domain,slug,url,created_at,expires_at,enabled,confirm_enabled,confirm_text,query_mode,source,creator) VALUES('existing-plain',?,?,?,123,456,0,1,'existing administrator text','merge','admin','fixture-existing-admin')",
    )
    .run('test.gfw.mom', slug, url);
  const before = f.db.prepare('SELECT * FROM links WHERE slug=?').get(slug);
  const report = await migrate({ client: f.client, manifest: f.manifest });
  assert.equal(report.conflicts, 0);
  assert.equal(report.imported, 0);
  assert.equal(report.unchanged, 1);
  assert.equal(report.fully_verified, true);
  assert.deepEqual(f.db.prepare('SELECT * FROM links WHERE slug=?').get(slug), before);
  assert.equal(f.db.prepare('SELECT status FROM legacy_migration_items').get().status, 'unchanged');
  f.db.close();
});

test('extended legacy reverse indexes require exact raw SHA-512 relationships', async () => {
  const records = Object.create(null);
  const slugs = ['saved.code', ' saved ', '旧短码', "it's", '（已存）'];
  for (const [index, slug] of slugs.entries()) {
    const url = `https://example.com/${index}?raw=a+b&sig=a%2Bb#fragment`;
    records[slug] = { value: url };
    records[sha(url, 'sha512')] = { value: slug };
  }
  const mismatch = sha(records['saved.code'].value.replace('raw=a+b', 'raw=a%20b'), 'sha512');
  records[mismatch] = { value: 'saved.code' };
  const urlValuedKey = 'f'.repeat(128);
  records[urlValuedKey] = { value: 'https://example.com/hash-is-a-real-slug' };
  const f = fixture(records, [Object.keys(records)]);
  const report = await migrate({ client: f.client, manifest: f.manifest });
  assert.equal(report.imported, slugs.length + 1);
  assert.equal(report.skipped, slugs.length);
  assert.equal(report.unknown, 1);
  for (const slug of slugs) {
    const index = sha(records[slug].value, 'sha512');
    assert.equal(f.db.prepare('SELECT id FROM links WHERE slug=?').get(index), undefined);
    assert.equal(
      f.db.prepare('SELECT reason FROM legacy_migration_items WHERE key_hash=?').get(sha(index))
        .reason,
      'verified_sha512_reverse_index',
    );
  }
  assert.equal(
    f.db.prepare('SELECT reason FROM legacy_migration_items WHERE key_hash=?').get(sha(mismatch))
      .reason,
    'hash_index_relationship_unverified',
  );
  assert.equal(
    f.db.prepare('SELECT url FROM links WHERE slug=?').get(urlValuedKey).url,
    records[urlValuedKey].value,
  );
  f.db.close();
});

test('reserved static names and unsafe encoded keys remain unknown without indirect reads', async () => {
  const url = 'https://example.com/original';
  let reads = 0;
  for (const slug of [
    'robots.txt',
    'STATUS.CSS',
    'favicon.ico',
    'index.html',
    'one/two',
    'one%20two',
    'one:two',
    'one\\two',
    '.',
    '..',
    'one\u202etwo',
  ]) {
    assert.deepEqual(
      await classifyLegacy(slug, url, async () => {
        reads++;
        return url;
      }),
      {
        kind: 'unknown',
        reason: 'unsafe_or_reserved_legacy_slug_requires_review',
      },
    );
    assert.equal(
      (
        await classifyLegacy(sha(url, 'sha512'), slug, async () => {
          reads++;
          return url;
        })
      ).kind,
      'unknown',
    );
  }
  assert.equal(reads, 0);
});

test('legacy URL imports accept 8 to 16 KiB while the actual value read remains bounded at 16 KiB', async () => {
  const prefix = 'https://example.com/';
  const records = Object.fromEntries(
    [8192, 8193, 16384, 16385].map((bytes) => [
      `bytes-${bytes}`,
      { value: prefix + 'a'.repeat(bytes - Buffer.byteLength(prefix)) },
    ]),
  );
  const f = fixture(records, [Object.keys(records)]);
  const observed = boundedValues(f, records);
  const report = await migrate({ client: f.client, manifest: f.manifest });
  assert.equal(report.imported, 3);
  assert.equal(report.unknown, 1);
  assert.equal(report.unverified_value_fingerprints, 1);
  assert.equal(report.fully_verified, false);
  assert.equal(observed.cancellations.includes('bytes-16385'), true);
  for (const bytes of [8192, 8193, 16384]) {
    const row = f.db.prepare('SELECT url,query_mode FROM links WHERE slug=?').get(`bytes-${bytes}`);
    assert.equal(row.url, records[`bytes-${bytes}`].value);
    assert.equal(row.query_mode, 'preserve');
  }
  assert.equal(f.db.prepare('SELECT id FROM links WHERE slug=?').get('bytes-16385'), undefined);
  const previous = f.db
    .prepare('SELECT * FROM legacy_migration_runs WHERE id=?')
    .get(report.run_id);
  const fresh = await migrate({ client: f.client, manifest: f.manifest });
  assert.notEqual(fresh.run_id, report.run_id);
  assert.equal(fresh.imported, 0);
  assert.equal(fresh.unchanged, 3);
  assert.equal(fresh.unknown, 1);
  assert.equal(fresh.fully_verified, false);
  assert.deepEqual(
    f.db.prepare('SELECT * FROM legacy_migration_runs WHERE id=?').get(report.run_id),
    previous,
  );
  assert.equal(f.db.prepare('SELECT COUNT(*) AS count FROM links').get().count, 3);
  f.db.close();
});
test('legacy URL boundaries count UTF-8 bytes rather than JavaScript characters', async () => {
  const prefix = 'https://example.com/';
  const remaining = 16384 - Buffer.byteLength(prefix);
  const exact = prefix + '路'.repeat(Math.floor(remaining / 3)) + 'a'.repeat(remaining % 3);
  assert.equal(Buffer.byteLength(exact), 16384);
  assert.ok(exact.length < 8192);
  const records = { unicode: { value: exact }, longer: { value: `${exact}😀` } };
  const f = fixture(records, [Object.keys(records)]);
  boundedValues(f, records, { contentLength: false });
  const report = await migrate({ client: f.client, manifest: f.manifest });
  assert.equal(report.imported, 1);
  assert.equal(report.unknown, 1);
  assert.equal(report.unverified_value_fingerprints, 1);
  assert.equal(f.db.prepare('SELECT url FROM links WHERE slug=?').get('unicode').url, exact);
  assert.equal(f.db.prepare('SELECT id FROM links WHERE slug=?').get('longer'), undefined);
  f.db.close();
});
test('16 KiB reverse indexes require the exact raw SHA-512 and URL-valued hash keys remain mappings', async () => {
  const prefix = 'https://example.com/';
  const suffix = '?q=a+b&q=a%20b&sig=fixture%2Bsignature&escape=%2f#fragment';
  const target = prefix + 'a'.repeat(16384 - Buffer.byteLength(prefix + suffix)) + suffix;
  const index = sha(target, 'sha512');
  const equivalentQueryIndex = sha(target.replace('q=a+b', 'q=a%20b'), 'sha512');
  const urlValuedKey = 'e'.repeat(128);
  const records = {
    'long-target': { value: target },
    [index]: { value: 'long-target' },
    [equivalentQueryIndex]: { value: 'long-target' },
    [urlValuedKey]: { value: target },
  };
  const f = fixture(records, [Object.keys(records)]);
  boundedValues(f, records);
  const report = await migrate({ client: f.client, manifest: f.manifest });
  assert.equal(report.imported, 2);
  assert.equal(report.skipped, 1);
  assert.equal(report.unknown, 1);
  assert.equal(report.fully_verified, false);
  assert.equal(f.db.prepare('SELECT url FROM links WHERE slug=?').get(urlValuedKey).url, target);
  assert.equal(f.db.prepare('SELECT id FROM links WHERE slug=?').get(index), undefined);
  assert.equal(
    f.db.prepare('SELECT reason FROM legacy_migration_items WHERE key_hash=?').get(sha(index))
      .reason,
    'verified_sha512_reverse_index',
  );
  assert.equal(
    f.db
      .prepare('SELECT reason FROM legacy_migration_items WHERE key_hash=?')
      .get(sha(equivalentQueryIndex)).reason,
    'hash_index_relationship_unverified',
  );
  f.db.close();
});
function boundedValues(f, records, { contentLength = true } = {}) {
  const cancellations = [];
  const pulls = [];
  const real = createCFClient('fixture-only-credential', {
    fetcher: async (url, options) => {
      assert.equal(new URL(url).origin, 'https://api.cloudflare.com');
      assert.equal(options.method, 'GET');
      assert.equal(options.redirect, 'error');
      const key = decodeURIComponent(new URL(url).pathname.split('/values/')[1]);
      const record = records[key];
      assert.ok(record, 'only fixture KV values are requested');
      const encoded = Buffer.from(record.value);
      let offset = 0;
      const body = new ReadableStream(
        {
          pull(controller) {
            pulls.push(key);
            if (offset === encoded.length) controller.close();
            else {
              const next = Math.min(offset + 4096, encoded.length);
              controller.enqueue(encoded.subarray(offset, next));
              offset = next;
            }
          },
          cancel() {
            cancellations.push(key);
          },
        },
        { highWaterMark: 0 },
      );
      return new Response(body, {
        status: record.status || 200,
        headers: contentLength ? { 'content-length': String(encoded.length) } : {},
      });
    },
  });
  f.client.optional = async (path, options) => {
    f.calls.push({ path, options });
    assert.equal(options.raw, true);
    assert.equal(options.maxBytes, 16 * 1024);
    return real.optional(path, options);
  };
  return { cancellations, pulls };
}
for (const contentLength of [true, false])
  test(`bounded actual client continues past oversized values with unverified markers (${contentLength ? 'declared size' : 'streamed size'})`, async () => {
    const large = 'secret-like-fixture-value'.repeat(5000);
    const index = 'a'.repeat(128);
    const records = {
      huge: { value: large },
      [index]: { value: 'huge' },
      good: { value: 'https://example.com/good' },
      SYS_CONFIG_API_TOKEN: { value: large },
    };
    const f = fixture(records, [['huge', index, 'SYS_CONFIG_API_TOKEN', 'good']]);
    const observed = boundedValues(f, records, { contentLength });
    const report = await migrate({ client: f.client, manifest: f.manifest });
    assert.equal(report.state, 'complete');
    assert.equal(report.processed_observations, 4);
    assert.equal(report.imported, 1);
    assert.equal(report.skipped, 1);
    assert.equal(report.unknown, 2);
    assert.equal(report.unverified_value_fingerprints, 1);
    assert.equal(report.fully_verified, false);
    assert.equal(
      report.verification_digest_scope,
      'observations_including_unverified_value_markers',
    );
    const item = f.db
      .prepare('SELECT * FROM legacy_migration_items WHERE key_hash=?')
      .get(sha('huge'));
    assert.equal(item.reason, 'legacy_value_exceeds_read_limit_value_fingerprint_unverified');
    assert.match(item.value_hash, /^[a-f\d]{64}$/);
    assert.notEqual(
      item.value_hash,
      sha(large),
      'an unread marker is not presented as the value hash',
    );
    assert.equal(
      f.db.prepare('SELECT reason FROM legacy_migration_items WHERE key_hash=?').get(sha(index))
        .reason,
      'hash_index_target_exceeds_read_limit_relationship_unverified',
    );
    assert.ok(observed.cancellations.filter((key) => key === 'huge').length === 2);
    assert.equal(observed.pulls.includes('SYS_CONFIG_API_TOKEN'), false);
    assert.equal(
      f.calls.some((call) => call.path.includes('/values/SYS_CONFIG_')),
      false,
    );
    const largeReads = observed.pulls.filter((key) => key === 'huge').length;
    assert.equal(
      largeReads,
      contentLength ? 0 : 10,
      'the bounded client never drains oversized values',
    );
    assert.doesNotMatch(JSON.stringify(report), /secret-like|example\.com|SYS_CONFIG|huge/);
    f.db.close();
  });
test('oversized marker survives interrupted-page replay and fresh incremental scans without pretending full-value verification', async () => {
  const records = { huge: { value: 'x'.repeat(100000) }, good: { value: 'https://example.com/' } };
  const f = fixture(records, [['huge', 'good']]);
  boundedValues(f, records);
  const read = f.client.optional;
  let interrupt = true;
  f.client.optional = async (path, options) => {
    if (interrupt && path.endsWith('/good')) {
      interrupt = false;
      throw new DeliveryError('NETWORK_OR_REDIRECT_BLOCKED');
    }
    return read(path, options);
  };
  await assert.rejects(migrate({ client: f.client, manifest: f.manifest }), {
    code: 'NETWORK_OR_REDIRECT_BLOCKED',
  });
  const run = f.db.prepare('SELECT * FROM legacy_migration_runs').get();
  assert.equal(run.cursor, '');
  assert.equal(run.state, 'running');
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM legacy_migration_items').get().n, 1);
  const done = await migrate({ client: f.client, manifest: f.manifest, resume: run.id });
  assert.equal(done.processed_observations, 2);
  assert.equal(done.unverified_value_fingerprints, 1);
  assert.equal(done.unknown, 1);
  assert.equal(done.fully_verified, false);
  const next = await migrate({ client: f.client, manifest: f.manifest });
  assert.equal(next.processed_observations, 2);
  assert.equal(next.unchanged, 1);
  assert.equal(next.unknown, 1);
  assert.equal(next.unverified_value_fingerprints, 1);
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM links').get().n, 1);
  f.db.close();
});
test('a fully read 16 KiB non-link has a real content fingerprint and remains unknown', async () => {
  const records = { exact: { value: 'x'.repeat(16 * 1024) } };
  const f = fixture(records, [['exact']]);
  boundedValues(f, records);
  const report = await migrate({ client: f.client, manifest: f.manifest });
  assert.equal(report.unknown, 1);
  assert.equal(report.unverified_value_fingerprints, 0);
  assert.equal(report.fully_verified, false);
  assert.equal(report.verification_digest_scope, 'hashed_observations');
  assert.equal(
    f.db.prepare('SELECT value_hash FROM legacy_migration_items').get().value_hash,
    sha(records.exact.value),
  );
  f.db.close();
});
test('an invalid declared response size is a protocol failure, not an oversized-value observation', async () => {
  const f = fixture({}, [['invalid']]);
  let cancelled = false;
  const real = createCFClient('fixture-only-credential', {
    fetcher: async () =>
      new Response(
        new ReadableStream(
          {
            cancel() {
              cancelled = true;
            },
          },
          { highWaterMark: 0 },
        ),
        { headers: { 'content-length': 'not-a-number' } },
      ),
  });
  f.client.optional = real.optional;
  await assert.rejects(migrate({ client: f.client, manifest: f.manifest }), {
    code: 'RESPONSE_LENGTH_INVALID',
  });
  assert.equal(cancelled, true);
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM legacy_migration_items').get().n, 0);
  f.db.close();
});
for (const status of [401, 403, 429, 500])
  test(`oversized HTTP ${status} error bodies remain fatal and safely redacted`, async () => {
    const records = { denied: { value: 'do-not-log-sensitive-body'.repeat(1000), status } };
    const f = fixture(records, [['denied']]);
    const observed = boundedValues(f, records);
    await assert.rejects(migrate({ client: f.client, manifest: f.manifest }), (error) => {
      assert.equal(error.code, 'RESPONSE_TOO_LARGE');
      assert.equal(error.status, status);
      assert.deepEqual(safeError(error), {
        code: 'RESPONSE_TOO_LARGE',
        http_status: status,
        cf_error_codes: [],
        endpoint_category: 'LEGACY_KV_VALUE',
        request_method: 'GET',
        detail: 'Raw responses, credentials and business data are withheld.',
      });
      return true;
    });
    assert.equal(observed.cancellations.length, 1);
    assert.equal(f.db.prepare('SELECT state FROM legacy_migration_runs').get().state, 'running');
    assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM legacy_migration_items').get().n, 0);
    f.db.close();
  });
test('an unqualified size error never converts an operational failure into an unknown observation', async () => {
  const f = fixture({}, [['failure']]);
  f.client.optional = async () => {
    throw new DeliveryError('RESPONSE_TOO_LARGE');
  };
  await assert.rejects(migrate({ client: f.client, manifest: f.manifest }), {
    code: 'RESPONSE_TOO_LARGE',
  });
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM legacy_migration_items').get().n, 0);
  f.db.close();
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
  const prefix = 'https://example.com/';
  const suffix = '?sig=a%2Bb&x=1&x=a+b&x=a%20b#frag';
  const original = prefix + 'a'.repeat(16384 - Buffer.byteLength(prefix + suffix)) + suffix;
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
