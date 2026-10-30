import { readFile, readdir } from 'node:fs/promises';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { handleAdmin } from '../src/admin';
import { errorResponse } from '../src/core';
import worker from '../src/index';
import { INTERSTITIAL_HTML_MAX_BYTES, validPageContent } from '../src/interstitial';
import { startBackup } from '../src/maintenance';
import type { Env } from '../src/types';

const primary = 'gfw.mom';
const secondary = 'gfw.lat';
const admin = 'link-admin.lily.lat';
const identity = { email: 'admin@example.test', csrf: 'fixture-only' };
let mf: Miniflare;
let env: Env;
let pending: Promise<unknown>[];
let ctx: ExecutionContext;

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
    APP_ENV: 'production',
    PUBLIC_HOSTNAME: primary,
    ADMIN_HOSTNAME: admin,
    ADMIN_EMAILS: identity.email,
    TURNSTILE_SITE_KEY: 'fixture',
    TURNSTILE_SECRET_KEY: 'fixture',
  };
  for (const file of (await readdir(new URL('../migrations/', import.meta.url)))
    .filter((f) => f.endsWith('.sql'))
    .sort()) {
    const sql = await readFile(new URL(`../migrations/${file}`, import.meta.url), 'utf8');
    await env.DB.batch(
      sql
        .split(';')
        .filter((s) => s.trim())
        .map((s) => env.DB.prepare(s)),
    );
  }
});
beforeEach(async () => {
  await env.DB.batch(
    [
      'backup_rows',
      'backup_jobs',
      'audit',
      'daily_stats',
      'daily_browser_stats',
      'links',
      'deleted_links',
      'domains',
    ].map((table) => env.DB.prepare(`DELETE FROM ${table}`)),
  );
  for (const domain of [primary, secondary])
    await env.DB.prepare(
      "INSERT INTO domains(hostname,created_at,enabled,bound,binding_state) VALUES(?,1,1,1,'verified')",
    )
      .bind(domain)
      .run();
  pending = [];
  ctx = {
    waitUntil(job: Promise<unknown>) {
      pending.push(job);
    },
    passThroughOnException() {},
  } as ExecutionContext;
});
afterEach(async () => {
  await Promise.all(pending);
});
afterAll(async () => {
  await mf?.dispose();
});

async function call(path: string, method = 'GET', body?: unknown) {
  try {
    return await handleAdmin(
      new Request(`https://${admin}/api/admin/${path}`, {
        method,
        ...(body === undefined
          ? {}
          : { body: JSON.stringify(body), headers: { 'Content-Type': 'application/json' } }),
      }),
      env,
      ctx,
      identity,
    );
  } catch (error) {
    return errorResponse(error);
  }
}
async function data(response: Response): Promise<any> {
  return ((await response.json()) as any).data;
}
async function create(slug = 'fixture') {
  return data(
    await call('links', 'POST', {
      domain: primary,
      slug,
      url: 'https://example.com/123456?sig=original#fragment',
    }),
  );
}
function visit(slug = 'fixture', host = primary, query = '', method = 'GET') {
  return worker.fetch(new Request(`https://${host}/${slug}${query}`, { method }), env, ctx);
}

describe('per-domain interstitial and link override with actual D1 migrations', () => {
  it('defaults all new behavior off and configures a domain independently of its binding', async () => {
    const link = await create();
    expect(link).toMatchObject({
      confirmation_mode: 'text',
      confirmation_enabled: false,
      query_policy: 'merge',
    });
    const changed = await call(`domains/${primary}`, 'PATCH', {
      interstitial_enabled: true,
      interstitial_delay: 7,
      interstitial_html:
        '<style>h1{color:red}</style><h1>Domain fixture</h1><script>document.title="custom"</script>',
    });
    expect(changed.status).toBe(200);
    expect(await data(changed)).toMatchObject({
      enabled: true,
      bound: true,
      interstitial_enabled: true,
      interstitial_delay: 7,
    });
    const page = await visit();
    expect(page.status).toBe(200);
    expect(page.headers.get('Content-Security-Policy')).toContain("connect-src 'none'");
    const html = await page.text();
    expect(html).toContain('sandbox="allow-scripts"');
    expect(html).not.toContain('allow-same-origin');
    expect(html).toContain('7 秒后自动继续');
    expect(html).toContain('&lt;h1&gt;Domain fixture&lt;/h1&gt;');
    expect((await visit('fixture', secondary)).status).toBe(302);
    const head = await visit('fixture', primary, '', 'HEAD');
    expect(head.status).toBe(200);
    expect(await head.text()).toBe('');
    await env.DB.prepare(
      "UPDATE domains SET bound=0,binding_state='unbound',enabled=0 WHERE hostname=?",
    )
      .bind(secondary)
      .run();
    expect(
      (
        await call(`domains/${secondary}`, 'PATCH', {
          interstitial_enabled: true,
          interstitial_delay: 0,
        })
      ).status,
    ).toBe(200);
    expect((await call(`domains/${secondary}`, 'PATCH', { enabled: true })).status).toBe(409);
  });

  it('uses single-link confirmation first, keeps legacy text inert, and never times out a confirmation', async () => {
    const link = await create();
    await call(`domains/${primary}`, 'PATCH', {
      interstitial_enabled: true,
      interstitial_delay: 1,
      interstitial_html: '<h1>Domain content</h1>',
    });
    await call(`links/${link.id}`, 'PATCH', {
      confirmation_enabled: true,
      confirmation_text: '<script>legacy()</script>',
    });
    let html = await (await visit()).text();
    expect(html).toContain('&lt;script&gt;legacy()&lt;/script&gt;');
    expect(html).not.toContain('Domain content');
    expect(html).not.toContain('countdown');
    await call(`links/${link.id}`, 'PATCH', {
      confirmation_mode: 'html',
      confirmation_text:
        '</iframe><script>parent.document.body.remove()</script><style>body{color:red}</style>',
    });
    const response = await visit();
    html = await response.text();
    expect(html).toContain('&lt;/iframe&gt;&lt;script&gt;parent.document.body.remove()');
    expect(html).not.toContain('</iframe><script>parent.document');
    expect(html).not.toContain('秒后自动继续');
    expect(response.headers.get('Content-Security-Policy')).toContain("frame-src 'self'");
    await call(`links/${link.id}`, 'PATCH', { enabled: false });
    expect((await visit()).status).toBe(410);
    await call(`links/${link.id}`, 'PATCH', { enabled: true, expires_at: 0 });
    expect((await visit()).status).toBe(410);
    expect((await visit('missing')).status).toBe(404);
  });

  it('strips the target to its origin without changing stored signed URL or the other policies', async () => {
    const link = await create();
    expect((await call(`links/${link.id}`, 'PATCH', { query_policy: 'origin' })).status).toBe(200);
    const redirected = await visit('fixture', primary, '?extra=yes');
    expect(redirected.headers.get('Location')).toBe('https://example.com/');
    expect(
      await env.DB.prepare('SELECT url FROM links WHERE id=?').bind(link.id).first('url'),
    ).toBe(link.url);
    expect((await data(await call('links'))).items[0].query_policy).toBe('origin');
    await call(`links/${link.id}`, 'PATCH', { query_policy: 'preserve' });
    expect((await visit('fixture', primary, '?extra=yes')).headers.get('Location')).toBe(link.url);
    await call(`links/${link.id}`, 'PATCH', { query_policy: 'merge' });
    expect((await visit('fixture', primary, '?extra=yes')).status).toBe(400);
  });

  it('bulk edits content and enable state independently and filters only actual link overrides', async () => {
    const a = await create('one'),
      b = await create('two'),
      c = await create('three');
    await call(`domains/${primary}`, 'PATCH', { interstitial_enabled: true });
    const ids = [a.id, b.id];
    expect(
      (
        await call('links/bulk', 'POST', {
          ids,
          action: 'confirmation',
          confirmation_mode: 'html',
          confirmation_text: '<h2>Shared content</h2>',
        })
      ).status,
    ).toBe(200);
    expect((await data(await call('links?confirmation=enabled'))).items).toHaveLength(0);
    await call('links/bulk', 'POST', { ids, action: 'confirmation', confirmation_enabled: true });
    const filtered = await data(await call('links?confirmation=enabled'));
    expect(filtered.items.map((item: any) => item.id).sort()).toEqual(ids.sort());
    expect(filtered.items.every((item: any) => item.confirmation_mode === 'html')).toBe(true);
    await call('links/bulk', 'POST', {
      ids: [a.id],
      action: 'confirmation',
      confirmation_enabled: false,
    });
    expect(
      (await data(await call('links?confirmation=enabled'))).items.map((item: any) => item.id),
    ).toEqual([b.id]);
    expect(
      await env.DB.prepare('SELECT confirm_text FROM links WHERE id=?')
        .bind(a.id)
        .first('confirm_text'),
    ).toBe('<h2>Shared content</h2>');
    expect(
      (await data(await call('links'))).items.find((item: any) => item.id === c.id)
        .confirmation_enabled,
    ).toBe(false);
  });

  it('updates all 100 selected links within the D1 per-statement binding limit', async () => {
    const ids = Array.from({ length: 100 }, () => crypto.randomUUID());
    await env.DB.batch(
      ids.map((id, index) =>
        env.DB.prepare(
          "INSERT INTO links(id,domain,slug,url,source,creator) VALUES(?,?,?,?,'admin','fixture')",
        ).bind(id, primary, `bulk-${index}`, 'https://example.com/'),
      ),
    );
    const bindingCounts: number[] = [];
    const limitedDB = {
      prepare(sql: string) {
        const statement = env.DB.prepare(sql);
        if (!sql.startsWith('UPDATE links SET')) return statement;
        return {
          bind(...args: (string | number | null)[]) {
            bindingCounts.push(args.length);
            if (args.length > 100) throw new Error('D1 statement binding limit exceeded');
            return statement.bind(...args);
          },
        };
      },
      batch: env.DB.batch.bind(env.DB),
    } as D1Database;
    const response = await handleAdmin(
      new Request(`https://${admin}/api/admin/links/bulk`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ids,
          action: 'confirmation',
          confirmation_enabled: true,
          confirmation_mode: 'html',
          confirmation_text: '<p>Bulk content</p>',
        }),
      }),
      { ...env, DB: limitedDB },
      ctx,
      identity,
    );
    expect(await data(response)).toEqual({ updated: 100 });
    expect(bindingCounts).toEqual([100, 6]);
    expect(
      await env.DB.prepare(
        "SELECT COUNT(*) AS n FROM links WHERE confirm_enabled=1 AND confirm_mode='html'",
      ).first('n'),
    ).toBe(100);
  });

  it('validates action fields, HTML byte limits, text mode and timing before any mutation', async () => {
    const link = await create();
    for (const body of [
      { interstitial_delay: -1 },
      { interstitial_delay: 301 },
      { interstitial_delay: 0.5 },
      { interstitial_enabled: 'yes' },
      { interstitial_html: '中'.repeat(INTERSTITIAL_HTML_MAX_BYTES) },
      { bound: true },
      {},
    ]) {
      expect((await call(`domains/${primary}`, 'PATCH', body)).status).toBe(400);
    }
    expect(validPageContent('中'.repeat(43000), 'html')).toBe(true);
    expect(validPageContent('中'.repeat(44000), 'html')).toBe(false);
    for (const body of [
      { confirmation_mode: null },
      { confirmation_text: null },
      { confirmation_mode: null, confirmation_text: 'must reject null mode' },
      { confirmation_mode: 'html', confirmation_text: null },
    ]) {
      expect((await call(`links/${link.id}`, 'PATCH', body)).status).toBe(400);
    }
    expect(
      await env.DB.prepare('SELECT confirm_text FROM links WHERE id=?')
        .bind(link.id)
        .first('confirm_text'),
    ).toBe('');
    expect(
      await env.DB.prepare('SELECT confirm_mode FROM links WHERE id=?')
        .bind(link.id)
        .first('confirm_mode'),
    ).toBe('text');
    expect(
      (
        await call(`links/${link.id}`, 'PATCH', {
          confirmation_text: '<p>' + 'x'.repeat(3000) + '</p>',
        })
      ).status,
    ).toBe(400);
    expect(
      (
        await call(`links/${link.id}`, 'PATCH', {
          confirmation_mode: 'html',
          confirmation_text: '<p>' + 'x'.repeat(3000) + '</p>',
        })
      ).status,
    ).toBe(200);
    expect((await call(`links/${link.id}`, 'PATCH', { confirmation_mode: 'text' })).status).toBe(
      400,
    );
    for (const body of [
      { action: 'enable', confirmation_enabled: true },
      { action: 'confirmation', expires_at: null },
      { action: 'confirmation' },
      { action: 'confirmation', confirmation_text: 'missing mode' },
    ]) {
      expect((await call('links/bulk', 'POST', { ids: [link.id], ...body })).status).toBe(400);
    }
    expect((await call('links?confirmation=invalid')).status).toBe(400);
  });

  it('includes domain and link custom settings in the atomic backup snapshot', async () => {
    const link = await create();
    await call(`domains/${primary}`, 'PATCH', {
      interstitial_enabled: true,
      interstitial_delay: 9,
      interstitial_html: '<p>backup domain</p>',
    });
    await call(`links/${link.id}`, 'PATCH', {
      confirmation_mode: 'html',
      confirmation_text: '<p>backup link</p>',
      query_policy: 'origin',
    });
    const id = await startBackup(env, identity.email);
    const rows = await env.DB.prepare('SELECT payload FROM backup_rows WHERE backup_id=?')
      .bind(id)
      .all<{ payload: string }>();
    const snapshot = rows.results.map((row) => JSON.parse(row.payload));
    const domain = snapshot.find((row) => row.table === 'domains' && row.data.hostname === primary);
    const savedLink = snapshot.find((row) => row.table === 'links');
    expect(domain.data).toMatchObject({
      interstitial_enabled: 1,
      interstitial_delay: 9,
      interstitial_html: '<p>backup domain</p>',
    });
    expect(savedLink.data).toMatchObject({ confirm_mode: 'html', target_origin_only: 1 });
  });
});
