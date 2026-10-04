#!/usr/bin/env node
import { createHash, randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import {
  ACCOUNT,
  EXPECTED,
  REPOSITORY,
  ensure,
  fail,
  createCFClient,
  requireAction,
  verifyAccount,
  safeError,
} from './cf-client.mjs';
import { readManifest, verifyD1Owner, query, privateSnapshot } from './deploy-resources.mjs';

const hash = (value, algorithm = 'sha256') => createHash(algorithm).update(value).digest('hex');
const slugSafe = (key) =>
  typeof key === 'string' &&
  /^[A-Za-z0-9_-]{1,512}$/.test(key) &&
  ![
    'api',
    'admin',
    'login',
    'logout',
    'assets',
    'static',
    'robots',
    'favicon',
    'health',
    'config',
    '_internal',
  ].includes(key.toLowerCase());
const urlSafe = (value) => {
  if (
    typeof value !== 'string' ||
    Buffer.byteLength(value) > 8192 ||
    /[\u0000-\u0020\u007f\\]/.test(value) ||
    /%(?![A-Fa-f0-9]{2})/.test(value) ||
    /[\ud800-\udfff]/u.test(value)
  )
    return false;
  const authority = /^https?:\/\/([^/?#]+)/i.exec(value);
  if (!authority || authority[1].includes('@')) return false;
  try {
    const u = new URL(value);
    return (
      ['http:', 'https:'].includes(u.protocol) && Boolean(u.hostname) && !u.username && !u.password
    );
  } catch {
    return false;
  }
};
export async function classifyLegacy(key, value, readValue) {
  if (key.startsWith('SYS_CONFIG_')) return { kind: 'skipped', reason: 'system_configuration' };
  // A URL-valued 128-hex key is a real mapping; length alone never identifies an index.
  if (urlSafe(value))
    return slugSafe(key)
      ? { kind: 'link', url: value }
      : { kind: 'unknown', reason: 'unsafe_or_reserved_legacy_slug_requires_review' };
  if (/^[a-f\d]{128}$/i.test(key) && slugSafe(value)) {
    const target = await readValue(value);
    if (urlSafe(target) && hash(target, 'sha512').toLowerCase() === key.toLowerCase())
      return { kind: 'skipped', reason: 'verified_sha512_reverse_index' };
    return { kind: 'unknown', reason: 'hash_index_relationship_unverified' };
  }
  return { kind: 'unknown', reason: 'unrecognized_legacy_value' };
}
function keyPath(key) {
  ensure(
    typeof key === 'string' &&
      key.length > 0 &&
      Buffer.byteLength(key) <= 512 &&
      !['.', '..'].includes(key) &&
      !/[\r\n\0]/.test(key),
    'LEGACY_KV_KEY_INVALID',
  );
  return `${ACCOUNT}/storage/kv/namespaces/${EXPECTED.LEGACY_KV_NAMESPACE_ID}/values/${encodeURIComponent(key).replace(/\./g, '%2E')}`;
}
export async function importLink(db, domain, key, value, metadata, now) {
  const id = `legacy:${hash(`${domain}\0${key}`)}`;
  const created =
    Number.isSafeInteger(metadata?.createdAt) &&
    metadata.createdAt > 0 &&
    metadata.createdAt <= 8640000000000000
      ? metadata.createdAt
      : null;
  const inserted = await db(
    "INSERT INTO links (id,domain,slug,url,created_at,enabled,confirm_enabled,confirm_text,query_mode,source,creator) VALUES (?,?,?,?,?,1,0,'','preserve','migration','legacy-kv') ON CONFLICT(domain,slug) DO NOTHING",
    [id, domain, key, value, created],
  );
  const rows = await db(
    'SELECT id,url,source,creator,created_at FROM links WHERE domain = ? AND slug = ?',
    [domain, key],
  );
  const row = rows[0].results?.[0];
  ensure(row, 'MIGRATED_ROW_READBACK_MISSING');
  if (row.url !== value)
    return { status: 'conflict', reason: 'existing_mapping_differs_never_overwritten' };
  return {
    status: inserted[0].meta?.changes > 0 ? 'imported' : 'unchanged',
    reason:
      row.created_at === null
        ? 'mapping_verified_creation_time_unknown'
        : row.created_at === created
          ? 'mapping_and_creation_time_verified'
          : 'mapping_verified_existing_creation_time_preserved',
  };
}
async function saveItem(db, runId, keyHash, valueHash, status, reason, domain, key, now) {
  await db(
    'INSERT INTO legacy_migration_items (run_id,key_hash,value_hash,status,reason) VALUES (?,?,?,?,?) ON CONFLICT(run_id,key_hash,value_hash) DO NOTHING',
    [runId, keyHash, valueHash, status, reason],
  );
  // The administrator sees fingerprints and a safe reason; no Token/configuration gets imported.
  if (status !== 'unknown')
    await db(
      'INSERT INTO migration_records (source_key_hash,domain,slug,status,value_hash,reason,updated_at) VALUES (?,?,?,?,?,?,?) ON CONFLICT(source_key_hash) DO UPDATE SET status = excluded.status, value_hash = excluded.value_hash, reason = excluded.reason, updated_at = excluded.updated_at',
      [
        keyHash,
        domain,
        ['imported', 'unchanged', 'conflict'].includes(status) ? key : null,
        status,
        valueHash,
        reason,
        now,
      ],
    );
}
async function summarizeRun(db, runId, cursor, complete, now) {
  const total = (
    await db(
      "SELECT COUNT(*) AS processed, SUM(status='imported') AS imported, SUM(status='unchanged') AS unchanged, SUM(status='skipped') AS skipped, SUM(status='conflict') AS conflicts, SUM(status='unknown') AS unknown FROM legacy_migration_items WHERE run_id = ?",
      [runId],
    )
  )[0].results[0];
  const aggregate = createHash('sha256');
  let after = '';
  let afterValue = '';
  for (;;) {
    const items = (
      await db(
        'SELECT key_hash,value_hash,status FROM legacy_migration_items WHERE run_id = ? AND (key_hash > ? OR (key_hash = ? AND value_hash > ?)) ORDER BY key_hash,value_hash LIMIT 500',
        [runId, after, after, afterValue],
      )
    )[0].results;
    if (!items.length) break;
    for (const item of items)
      aggregate.update(`${item.key_hash}\0${item.value_hash}\0${item.status}\n`);
    after = items.at(-1).key_hash;
    afterValue = items.at(-1).value_hash;
  }
  const digest = aggregate.digest('hex');
  await db(
    'UPDATE legacy_migration_runs SET cursor=?,state=?,processed=?,imported=?,unchanged=?,skipped=?,conflicts=?,unknown=?,digest=?,updated_at=? WHERE id=?',
    [
      cursor,
      complete ? 'complete' : 'running',
      total.processed || 0,
      total.imported || 0,
      total.unchanged || 0,
      total.skipped || 0,
      total.conflicts || 0,
      total.unknown || 0,
      digest,
      now,
      runId,
    ],
  );
  return {
    run_id: runId,
    state: complete ? 'complete' : 'running',
    processed_observations: total.processed || 0,
    imported: total.imported || 0,
    unchanged: total.unchanged || 0,
    skipped: total.skipped || 0,
    conflicts: total.conflicts || 0,
    unknown: total.unknown || 0,
    verification_digest_sha256: digest,
  };
}
export async function migrate({
  client,
  manifest,
  resume = '',
  maxPages = 100,
  now = () => Date.now(),
}) {
  ensure(
    Number.isInteger(maxPages) && maxPages >= 1 && maxPages <= 1000,
    'MIGRATION_PAGE_LIMIT_INVALID',
  );
  const domain = EXPECTED.PUBLIC_HOSTNAME;
  const db = (sql, params) => query(client, manifest.d1.id, sql, params);
  const registered = (
    await db('SELECT hostname,bound FROM domains WHERE hostname = ?', [domain])
  )[0].results?.[0];
  ensure(registered?.hostname === domain && registered.bound === 1, 'MIGRATION_DOMAIN_NOT_BOUND');
  let runId = resume || randomUUID();
  let cursor = '';
  if (resume) {
    ensure(/^[a-f\d-]{36}$/i.test(resume), 'MIGRATION_RUN_ID_INVALID');
    const run = (await db('SELECT * FROM legacy_migration_runs WHERE id = ?', [resume]))[0]
      .results?.[0];
    ensure(
      run &&
        run.namespace_id === EXPECTED.LEGACY_KV_NAMESPACE_ID &&
        run.domain === domain &&
        run.state !== 'complete',
      'MIGRATION_RUN_NOT_RESUMABLE',
    );
    cursor = run.cursor;
  } else
    await db(
      "INSERT INTO legacy_migration_runs (id,namespace_id,domain,cursor,state,digest,started_at,updated_at) VALUES (?,?,?,'','running','',?,?)",
      [runId, EXPECTED.LEGACY_KV_NAMESPACE_ID, domain, now(), now()],
    );
  const seenCursors = new Set([cursor]);
  let summary;
  const readValue = async (key) => {
    const response = await client.optional(keyPath(key), { raw: true, maxBytes: 16 * 1024 });
    return response;
  };
  for (let page = 0; page < maxPages; page++) {
    const url = new URL(
      `https://api.cloudflare.com/client/v4${ACCOUNT}/storage/kv/namespaces/${EXPECTED.LEGACY_KV_NAMESPACE_ID}/keys`,
    );
    url.searchParams.set('limit', '100');
    if (cursor) url.searchParams.set('cursor', cursor);
    const list = await client.request(
      url.href.slice('https://api.cloudflare.com/client/v4'.length),
    );
    ensure(Array.isArray(list.result), 'LEGACY_KEY_LIST_INVALID');
    for (const k of list.result) {
      ensure(typeof k.name === 'string', 'LEGACY_KEY_LIST_INVALID');
      const keyHash = hash(k.name);
      const value = k.name.startsWith('SYS_CONFIG_') ? null : await readValue(k.name);
      const valueHash = hash(value === null ? '<system-or-missing>' : value);
      const seen =
        (
          await db(
            'SELECT status FROM legacy_migration_items WHERE run_id=? AND key_hash=? AND value_hash=?',
            [runId, keyHash, valueHash],
          )
        )[0].results || [];
      if (seen.length) continue; // Replaying a partially completed page cannot overwrite or double count.
      const classification = await classifyLegacy(k.name, value, readValue);
      const result =
        classification.kind === 'link'
          ? await importLink(db, domain, k.name, value, k.metadata, now())
          : { status: classification.kind, reason: classification.reason };
      await saveItem(
        db,
        runId,
        keyHash,
        valueHash,
        result.status,
        result.reason,
        domain,
        k.name,
        now(),
      );
    }
    const next = list.result_info?.cursor || '';
    if (next) {
      ensure(!seenCursors.has(next), 'LEGACY_CURSOR_REPEATED');
      seenCursors.add(next);
    }
    cursor = next;
    summary = await summarizeRun(db, runId, cursor, !cursor, now());
    if (!cursor) break;
  }
  return {
    ...summary,
    source: 'legacy KV reads only',
    destination: 'owned new D1 test domain',
    snapshot: false,
    production_cutover: false,
    next_action:
      summary.state !== 'complete'
        ? 'resume this run_id'
        : 'start another full scan for incremental additions/changes',
    fully_verified:
      summary.state === 'complete' && summary.conflicts === 0 && summary.unknown === 0,
  };
}
export async function main(env = process.env) {
  requireAction(env, 'read old KV and migrate owned test D1 only');
  const client = createCFClient(env.CLOUDFLARE_API_TOKEN, { allowWrites: true });
  await verifyAccount(client);
  const manifest = await readManifest(client);
  ensure(manifest?.d1, 'RESOURCE_BOOTSTRAP_REQUIRED');
  await verifyD1Owner(client, manifest);
  const result = await migrate({
    client,
    manifest,
    resume: env.MIGRATION_RESUME_RUN || '',
    maxPages: Number(env.MIGRATION_MAX_PAGES || 100),
  });
  await privateSnapshot(client, manifest, `migration-${result.run_id}`, result);
  console.log(JSON.stringify(result)); // Fingerprint totals only; no KV keys, URLs, SQL or credential output/artifacts.
  if (!result.fully_verified) process.exitCode = 2;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    await main();
  } catch (e) {
    console.error(JSON.stringify(safeError(e)));
    process.exitCode = 1;
  }
}
