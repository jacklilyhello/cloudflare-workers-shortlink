import { readFile, readdir } from 'node:fs/promises';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { handleAdmin } from '../src/admin';
import { errorResponse, handleRedirect, validateUrl } from '../src/core';
import { advanceBackup, startBackup } from '../src/maintenance';
import type { Env, LinkRow } from '../src/types';

const domain = 'gfw.mom';
const host = 'link-admin.lily.lat';
const identity = { email: 'admin@example.test', csrf: 'fixture-only' };
const legacyBytes = 16 * 1024;
let mf: Miniflare;
let env: Env;
let ctx: ExecutionContext;
let jobs: Promise<unknown>[];

function legacyURL(index: number, bytes = legacyBytes): string {
  const prefix = `https://example.com/legacy/%2F/${index}?X-Amz-Signature=${'a'.repeat(64)}&repeat=a+b&repeat=a%20b&slash=%2f&padding=`;
  const suffix = '#片';
  const padding = 'x'.repeat(bytes - Buffer.byteLength(prefix + suffix, 'utf8'));
  return `${prefix}${padding}${suffix}`;
}
function legacyInsert(index: number, url: string) {
  return env.DB.prepare(
    "INSERT INTO links(id,domain,slug,url,created_at,query_mode,source,creator) VALUES(?,?,?,?,NULL,'preserve','migration','legacy-kv')",
  ).bind(`legacy:${index.toString(16).padStart(64, '0')}`, domain, `legacy-long-${index}`, url);
}
async function call(path: string, method = 'GET', body?: unknown): Promise<Response> {
  try {
    return await handleAdmin(
      new Request(`https://${host}/api/admin/${path}`, {
        method,
        ...(body === undefined
          ? {}
          : { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
      }),
      env,
      ctx,
      identity,
    );
  } catch (error) {
    return errorResponse(error);
  }
}
function redirect(slug: string): Promise<Response> {
  return handleRedirect(
    new Request(`https://${domain}/${slug}?repeat=ignored&additional=ignored%2Fvalue`),
    env,
    ctx,
    domain,
    slug,
  );
}
interface ManagedLink {
  id: string;
  url: string;
  enabled: boolean;
  confirmation_enabled: boolean;
  confirmation_text: string;
  query_policy: 'preserve' | 'merge';
  created_at: number | null;
}

beforeAll(async () => {
  mf = new Miniflare(
    convertV4MiniflareOptions({
      modules: true,
      script: 'export default { fetch() { return new Response("test"); } }',
      d1Databases: ['DB'],
      r2Buckets: ['BACKUPS'],
    }),
  );
  env = {
    DB: (await mf.getD1Database('DB')) as unknown as D1Database,
    BACKUPS: (await mf.getR2Bucket('BACKUPS')) as unknown as R2Bucket,
    PUBLIC_HOSTNAME: domain,
    ADMIN_HOSTNAME: host,
    APP_ENV: 'production',
    ADMIN_EMAILS: identity.email,
    TURNSTILE_SITE_KEY: 'fixture-public',
    TURNSTILE_SECRET_KEY: 'fixture-private',
  };
  const files = (await readdir(new URL('../migrations/', import.meta.url)))
    .filter((file) => file.endsWith('.sql'))
    .sort();
  for (const file of files) {
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
  await env.DB.batch(
    [
      'DELETE FROM backup_rows',
      'DELETE FROM backup_jobs',
      'DELETE FROM legacy_migration_items',
      'DELETE FROM legacy_migration_runs',
      'DELETE FROM migration_records',
      'DELETE FROM audit',
      'DELETE FROM daily_stats',
      'DELETE FROM links',
      'DELETE FROM deleted_links',
      'DELETE FROM token_domains',
      'DELETE FROM tokens',
      'DELETE FROM domains',
      'DELETE FROM rate_windows',
    ].map((statement) => env.DB.prepare(statement)),
  );
  await env.DB.prepare(
    "INSERT INTO domains(hostname,enabled,bound,created_at,binding_state) VALUES(?,1,1,?,'verified')",
  )
    .bind(domain, Date.now())
    .run();
  jobs = [];
  ctx = {
    waitUntil(job: Promise<unknown>) {
      jobs.push(job);
    },
    passThroughOnException() {},
  } as unknown as ExecutionContext;
});
afterEach(async () => {
  await Promise.all(jobs);
});
afterAll(async () => {
  await mf?.dispose();
});

describe('legacy URL compatibility on actual local D1/R2', () => {
  it('preserves a 16 KiB legacy URL through redirects and lifecycle edits while new URLs stay capped at 8 KiB', async () => {
    const raw = legacyURL(0);
    expect(Buffer.byteLength(raw, 'utf8')).toBe(legacyBytes);
    expect(validateUrl(legacyURL(0, 8 * 1024))).toBe(legacyURL(0, 8 * 1024));
    let validationError: unknown;
    try {
      validateUrl(raw);
    } catch (error) {
      validationError = error;
    }
    expect(validationError).toMatchObject({ status: 413, code: 'URL_TOO_LONG' });
    await legacyInsert(0, raw).run();
    const slug = 'legacy-long-0';
    const encoded = raw.replace('#片', '#%E7%89%87');
    const direct = await redirect(slug);
    expect(direct.status).toBe(302);
    expect(direct.headers.get('Location')).toBe(encoded);
    expect(direct.headers.get('Location')).not.toContain('additional=');

    const listed = await call('links');
    expect(listed.status).toBe(200);
    const list = (await listed.json()) as { data: { items: ManagedLink[] } };
    expect(list.data.items).toHaveLength(1);
    expect(list.data.items[0]).toMatchObject({
      url: raw,
      enabled: true,
      confirmation_enabled: false,
      query_policy: 'preserve',
      created_at: null,
    });
    const path = `links/${encodeURIComponent(list.data.items[0].id)}`;
    const disabled = await call(path, 'PATCH', { enabled: false });
    expect(disabled.status).toBe(200);
    expect((await disabled.json()) as { data: ManagedLink }).toMatchObject({
      data: { url: raw, enabled: false },
    });
    expect((await redirect(slug)).status).toBe(410);

    const confirmationText = '验收 <b>说明</b>：🙂';
    const updated = await call(path, 'PATCH', {
      enabled: true,
      confirmation_enabled: true,
      confirmation_text: confirmationText,
    });
    expect(updated.status).toBe(200);
    expect((await updated.json()) as { data: ManagedLink }).toMatchObject({
      data: { url: raw, enabled: true, confirmation_enabled: true, query_policy: 'preserve' },
    });
    const confirmation = await redirect(slug);
    expect(confirmation.status).toBe(200);
    expect(confirmation.headers.get('Content-Security-Policy')).toContain("frame-ancestors 'none'");
    const html = await confirmation.text();
    expect(html).toContain('验收 &lt;b&gt;说明&lt;/b&gt;：🙂');
    expect(html).not.toContain('<b>说明</b>');
    const href = /<a class="button" href="([^"]+)"/.exec(html)?.[1];
    expect(href).toBeDefined();
    const target = href!.replaceAll('&amp;', '&');
    expect(target).toBe(raw);
    expect(new URL(target).href).toBe(encoded);
    const stored = await env.DB.prepare('SELECT * FROM links WHERE domain=? AND slug=?')
      .bind(domain, slug)
      .first<LinkRow>();
    expect(stored).toMatchObject({
      url: raw,
      enabled: 1,
      confirm_enabled: 1,
      confirm_text: confirmationText,
      query_mode: 'preserve',
      created_at: null,
    });
  });

  it('backs up 340 long legacy URLs from the original snapshot across the exact 5 MiB multipart boundary', async () => {
    const urls = Array.from({ length: 340 }, (_, index) => legacyURL(index));
    expect(urls.every((url) => Buffer.byteLength(url, 'utf8') === legacyBytes)).toBe(true);
    for (let offset = 0; offset < urls.length; offset += 50)
      await env.DB.batch(
        urls.slice(offset, offset + 50).map((url, index) => legacyInsert(offset + index, url)),
      );
    const id = await startBackup(env, identity.email);
    const staging = await env.DB.prepare(
      'SELECT payload FROM backup_rows WHERE backup_id=? ORDER BY id',
    )
      .bind(id)
      .all<{ payload: string }>();
    const expectedBody = staging.results.map((row) => `${row.payload}\n`).join('');
    const expectedBytes = Buffer.byteLength(expectedBody, 'utf8');
    expect(expectedBytes).toBeGreaterThan(5 * 1024 * 1024);
    await env.DB.prepare('UPDATE links SET url=?,enabled=0,confirm_text=?')
      .bind('https://example.com/after-snapshot', 'changed after snapshot')
      .run();
    await advanceBackup(env);
    const checkpoint = await env.DB.prepare(
      'SELECT status,size,part_number,row_offset,records FROM backup_jobs WHERE id=?',
    )
      .bind(id)
      .first<{
        status: string;
        size: number;
        part_number: number;
        row_offset: number;
        records: number;
      }>();
    expect(checkpoint).toMatchObject({
      status: 'uploading',
      size: 5 * 1024 * 1024,
      part_number: 2,
    });
    expect(checkpoint!.row_offset).toBeGreaterThan(0);
    expect(checkpoint!.records).toBeLessThan(staging.results.length);
    for (let pass = 0; pass < 3; pass++) {
      const status = await env.DB.prepare('SELECT status FROM backup_jobs WHERE id=?')
        .bind(id)
        .first<string>('status');
      if (status === 'complete') break;
      await advanceBackup(env);
    }
    const job = await env.DB.prepare('SELECT status,size,records,parts FROM backup_jobs WHERE id=?')
      .bind(id)
      .first<{ status: string; size: number; records: number; parts: string }>();
    expect(job?.status).toBe('complete');
    expect(job?.records).toBe(staging.results.length);
    expect(job?.size).toBe(expectedBytes);
    expect(JSON.parse(job!.parts)).toHaveLength(2);
    const object = await env.BACKUPS!.get(`backups/${id}.ndjson`);
    expect(object).not.toBeNull();
    expect(object!.size).toBe(expectedBytes);
    const body = await object!.text();
    expect(Buffer.byteLength(body, 'utf8')).toBe(expectedBytes);
    expect(Buffer.compare(Buffer.from(body, 'utf8'), Buffer.from(expectedBody, 'utf8'))).toBe(0);
    const records = body
      .trimEnd()
      .split('\n')
      .map((line) => JSON.parse(line) as { table: string; data: LinkRow });
    expect(records).toHaveLength(staging.results.length);
    const links = new Map(
      records.filter((row) => row.table === 'links').map((row) => [row.data.slug, row.data]),
    );
    expect(links.size).toBe(urls.length);
    urls.forEach((url, index) => {
      expect(links.get(`legacy-long-${index}`)).toMatchObject({
        url,
        enabled: 1,
        confirm_text: '',
        query_mode: 'preserve',
      });
    });
    expect(
      await env.DB.prepare('SELECT COUNT(*) AS count FROM links WHERE enabled=0 AND url=?')
        .bind('https://example.com/after-snapshot')
        .first<number>('count'),
    ).toBe(urls.length);
    expect(
      await env.DB.prepare('SELECT COUNT(*) AS count FROM backup_rows WHERE backup_id=?')
        .bind(id)
        .first<number>('count'),
    ).toBe(0);
  }, 20_000);
});
