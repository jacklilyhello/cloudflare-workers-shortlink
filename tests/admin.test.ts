import { readFile, readdir } from 'node:fs/promises';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { afterAll, beforeAll, beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { handleAdmin } from '../src/admin';
import { errorResponse, handleCreate, handleRedirect, hash } from '../src/core';
import worker from '../src/index';
import { advanceBackup, maintenance, startBackup } from '../src/maintenance';
import type { Env, LinkRow } from '../src/types';

const domain = 'test.gfw.mom';
const host = 'link-admin.lily.lat';
const identity = { email: 'admin@example.test', csrf: 'fixture-only' };
let mf: Miniflare;
let env: Env;
let ctx: ExecutionContext;
let jobs: Promise<unknown>[];

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
    APP_ENV: 'test',
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
      'DELETE FROM migration_records',
      'DELETE FROM audit',
      'DELETE FROM daily_stats',
      'DELETE FROM links',
      'DELETE FROM token_domains',
      'DELETE FROM tokens',
      'DELETE FROM domains',
      'DELETE FROM rate_windows',
    ].map((statement) => env.DB.prepare(statement)),
  );
  await env.DB.prepare(
    'INSERT INTO domains(hostname, enabled, bound, created_at) VALUES (?, 1, 1, ?)',
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

async function call(path: string, method = 'GET', body?: unknown): Promise<Response> {
  const request = new Request(`https://${host}/api/admin/${path}`, {
    method,
    ...(body === undefined
      ? {}
      : { body: JSON.stringify(body), headers: { 'Content-Type': 'application/json' } }),
  });
  try {
    return await handleAdmin(request, env, ctx, identity);
  } catch (error) {
    return errorResponse(error);
  }
}
async function output(response: Response): Promise<any> {
  return response.json();
}
async function link(slug = 'admin-link'): Promise<any> {
  const response = await call('links', 'POST', {
    url: 'https://example.com/?q=a+b#fragment',
    domain,
    slug,
  });
  expect(response.status).toBe(201);
  return (await output(response)).data;
}

describe('administrator operations against actual local D1/R2', () => {
  it('creates separate permanent links, supports lifecycle updates and bulk disable without deleting mappings', async () => {
    const first = await link('first');
    const second = await link('second');
    expect(first).toMatchObject({
      expires_at: null,
      enabled: true,
      confirmation_enabled: false,
      source: 'admin',
    });
    expect(first.id).not.toBe(second.id);
    const changed = await call(`links/${first.id}`, 'PATCH', {
      confirmation_enabled: true,
      confirmation_text: 'Confirm fixture',
      expires_at: Date.now() + 86_400_000,
      query_policy: 'preserve',
    });
    expect(changed.status).toBe(200);
    expect((await output(changed)).data).toMatchObject({
      confirmation_enabled: true,
      confirmation_text: 'Confirm fixture',
      query_policy: 'preserve',
    });
    expect(
      (await call('links/bulk', 'POST', { ids: [first.id, second.id], action: 'disable' })).status,
    ).toBe(200);
    expect(await env.DB.prepare('SELECT COUNT(*) AS count FROM links').first('count')).toBe(2);
    const disabled = await handleRedirect(
      new Request(`https://${domain}/first`),
      env,
      ctx,
      domain,
      'first',
    );
    expect(disabled.status).toBe(410);
    const conflict = await call('links', 'POST', {
      url: 'https://other.example',
      domain,
      slug: 'first',
    });
    expect(conflict.status).toBe(409);
    expect(
      (await call('links/bulk', 'POST', { ids: [first.id], action: 'expiry', expires_at: null }))
        .status,
    ).toBe(200);
    expect((await call('links/bulk', 'POST', { ids: [first.id], action: 'delete' })).status).toBe(
      400,
    );
    expect((await call(`links/${first.id}`, 'DELETE')).status).toBe(404);
    expect(await env.DB.prepare('SELECT COUNT(*) AS count FROM links').first('count')).toBe(2);
  });

  it('does not permit mutation of the permanent domain, slug, URL or ownership through patch', async () => {
    const created = await link();
    for (const field of ['url', 'domain', 'slug', 'source', 'creator']) {
      expect((await call(`links/${created.id}`, 'PATCH', { [field]: 'replacement' })).status).toBe(
        400,
      );
    }
    expect(
      (await env.DB.prepare('SELECT * FROM links WHERE id = ?').bind(created.id).first<LinkRow>())
        ?.url,
    ).toBe(created.url);
  });

  it('manages migrated legacy IDs using single path decoding and rejects encoded aliases or path injection', async () => {
    const id = `legacy:${'a'.repeat(64)}`;
    const slug = 'b'.repeat(128);
    await env.DB.prepare(
      "INSERT INTO links(id,domain,slug,url,created_at,source,creator) VALUES (?, ?, ?, ?, NULL, 'migration', 'legacy-kv')",
    )
      .bind(id, domain, slug, 'https://legacy.example/?sig=a%2Bb#f')
      .run();
    const patch = await call(`links/${encodeURIComponent(id)}`, 'PATCH', {
      expires_at: Date.now() + 86_400_000,
      confirmation_enabled: true,
      confirmation_text: 'Legacy confirmation',
    });
    expect(patch.status).toBe(200);
    expect((await output(patch)).data).toMatchObject({
      id,
      created_at: null,
      confirmation_enabled: true,
    });
    expect((await call('links/bulk', 'POST', { ids: [id], action: 'disable' })).status).toBe(200);
    expect(
      await env.DB.prepare('SELECT enabled FROM links WHERE id = ?').bind(id).first('enabled'),
    ).toBe(0);
    for (const invalid of [
      encodeURIComponent(encodeURIComponent(id)),
      'legacy%3A' + 'a'.repeat(63),
      encodeURIComponent(id + '/extra'),
      '%ZZ',
    ]) {
      expect([400, 404]).toContain(
        (await call(`links/${invalid}`, 'PATCH', { enabled: true })).status,
      );
    }
    expect(
      (await call('links/bulk', 'POST', { ids: [encodeURIComponent(id)], action: 'enable' }))
        .status,
    ).toBe(400);
    expect(await env.DB.prepare('SELECT COUNT(*) AS count FROM links').first('count')).toBe(1);
    expect(
      await env.DB.prepare('SELECT enabled FROM links WHERE id = ?').bind(id).first('enabled'),
    ).toBe(0);
  });

  it('searches and filters using literal text and has stable pagination', async () => {
    await link('search_one');
    await link('search-two');
    expect((await output(await call('links?q=search_one'))).data.items).toHaveLength(1);
    expect(
      (await output(await call('links?q=' + encodeURIComponent("' OR 1=1 --")))).data.items,
    ).toHaveLength(0);
    expect((await call('links?status=unknown')).status).toBe(400);
    expect((await output(await call('links?status=active'))).data.items).toHaveLength(2);
  });

  it('registers unbound inactive domains and rejects attempts to self-assert platform binding', async () => {
    const response = await call('domains', 'POST', { hostname: 'new.example.com' });
    expect(response.status).toBe(201);
    expect((await output(response)).data).toMatchObject({ enabled: false, bound: false });
    expect((await call('domains/new.example.com', 'PATCH', { enabled: true })).status).toBe(409);
    expect(
      (await call('domains/new.example.com', 'PATCH', { enabled: true, bound: true })).status,
    ).toBe(400);
    expect((await call('domains', 'POST', { hostname: host })).status).toBe(400);
    expect(
      (await call('links', 'POST', { domain: 'new.example.com', url: 'https://example.com' }))
        .status,
    ).toBe(403);
    expect(
      await env.DB.prepare('SELECT enabled FROM domains WHERE hostname = ?')
        .bind('new.example.com')
        .first('enabled'),
    ).toBe(0);
    expect((await call(`domains/${domain}`, 'PATCH', { enabled: false })).status).toBe(200);
  });

  it('returns high entropy business token only once, stores its hash, keeps plaintext and digest out of lists/audit, then revokes', async () => {
    const response = await call('tokens', 'POST', {
      name: 'Fixture robot',
      domains: [domain],
      rate_per_minute: 50,
    });
    expect(response.status).toBe(201);
    const created = (await output(response)).data;
    expect(created.token).toMatch(/^sl_[a-f0-9]{64}$/);
    const stored = await env.DB.prepare('SELECT * FROM tokens WHERE id = ?')
      .bind(created.id)
      .first<{ digest: string }>();
    expect(stored?.digest).toBe(await hash(created.token));
    expect(JSON.stringify(stored)).not.toContain(created.token);
    const list = await call('tokens');
    const serialized = await list.text();
    expect(serialized).not.toContain(created.token);
    expect(serialized).not.toContain(stored!.digest);
    expect(serialized).not.toContain('"digest"');
    expect(await (await call('audit')).text()).not.toContain(created.token);
    const machine = () =>
      handleCreate(
        new Request(`https://${host}/api/shorten`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${created.token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: 'https://machine.example', domain }),
        }),
        env,
        ctx,
        'machine',
      );
    expect((await machine()).status).toBe(201);
    expect((await call(`tokens/${created.id}`, 'DELETE')).status).toBe(200);
    expect((await machine()).status).toBe(401);
    expect(await env.DB.prepare('SELECT COUNT(*) AS count FROM tokens').first('count')).toBe(1);
  });

  it('does not grant unbound domain access or let token input set identity/digest/admin powers', async () => {
    await call('domains', 'POST', { hostname: 'unbound.example.com' });
    expect(
      (await call('tokens', 'POST', { name: 'Fixture', domains: ['unbound.example.com'] })).status,
    ).toBe(403);
    expect(
      (await call('tokens', 'POST', { name: 'Fixture', domains: [domain], digest: 'fixture' }))
        .status,
    ).toBe(400);
    expect(
      (await call('tokens', 'POST', { name: 'Fixture', domains: [domain], admin: true })).status,
    ).toBe(400);
    expect(
      (await call('tokens', 'POST', { name: 'Fixture', domains: [domain], expires_at: 1 })).status,
    ).toBe(400);
    expect(await env.DB.prepare('SELECT COUNT(*) AS count FROM tokens').first('count')).toBe(0);
  });

  it('limits settings to documented administrator fields and validates retention, rate and error copy', async () => {
    expect((await call('settings', 'PUT', { TURNSTILE_SECRET_KEY: 'fixture' })).status).toBe(400);
    expect((await call('settings', 'PUT', { analytics_retention_days: 0 })).status).toBe(400);
    expect((await call('settings', 'PUT', { domain_rate_per_minute: 1001 })).status).toBe(400);
    expect((await call('settings', 'PUT', { error_404: 'x'.repeat(501) })).status).toBe(400);
    const response = await call('settings', 'PUT', {
      analytics_retention_days: 90,
      backup_interval_hours: 24,
      error_404: '<img src=x onerror=fixture>',
    });
    expect(response.status).toBe(200);
    const missing = await handleRedirect(
      new Request(`https://${domain}/missing`),
      env,
      ctx,
      domain,
      'missing',
    );
    expect(await missing.text()).toContain('&lt;img');
    expect(
      await env.DB.prepare(
        "SELECT COUNT(*) AS count FROM settings WHERE key = 'TURNSTILE_SECRET_KEY'",
      ).first('count'),
    ).toBe(0);
  });

  it('reports visits, countries, devices and referrers as explicitly approximate aggregates', async () => {
    await link();
    const day = new Date().toISOString().slice(0, 10);
    await env.DB.batch([
      env.DB.prepare('INSERT INTO daily_stats VALUES (?, ?, ?, ?, ?, ?, ?)').bind(
        day,
        domain,
        'admin-link',
        'SG',
        'mobile',
        'direct',
        3,
      ),
      env.DB.prepare('INSERT INTO daily_stats VALUES (?, ?, ?, ?, ?, ?, ?)').bind(
        day,
        domain,
        'admin-link',
        'US',
        'desktop',
        'referrer.example',
        5,
      ),
    ]);
    const stats = (await output(await call('stats?days=7'))).data;
    expect(stats.approximate).toBe(true);
    expect(stats.totals).toMatchObject({ links: 1, active_links: 1, visits: 8 });
    expect(stats.daily).toEqual([{ date: day, visits: 8 }]);
    expect(stats.countries[0]).toEqual({ name: 'US', count: 5 });
    expect(stats.devices[0]).toEqual({ name: 'desktop', count: 5 });
    expect(stats.referrers[0]).toEqual({ name: 'referrer.example', count: 5 });
    expect((await call('stats?days=91')).status).toBe(400);
  });

  it('exports every D1 row across authenticated cursor pages with exact legacy fields and no business credentials', async () => {
    const business = (
      await output(
        await call('tokens', 'POST', {
          name: 'Export fixture',
          domains: [domain],
        }),
      )
    ).data;
    const digest = await env.DB.prepare('SELECT digest FROM tokens WHERE id=?')
      .bind(business.id)
      .first<string>('digest');
    expect(digest).toMatch(/^[a-f0-9]{64}$/);
    const prefix = 'https://example.test/路径?sig=abc%2f&same=+&same=%20&padding=';
    const suffix = '#片';
    const longUrl = prefix + 'x'.repeat(16 * 1024 - Buffer.byteLength(prefix + suffix)) + suffix;
    expect(Buffer.byteLength(longUrl)).toBe(16 * 1024);
    const legacySlugs = new Map([
      [0, "旧's（保留）"],
      [501, 'Cafe\u0301.code'],
      [502, 'Café.code'],
    ]);
    const rows: LinkRow[] = [];
    for (let index = 0; index < 503; index++) {
      const migrated = legacySlugs.has(index);
      const slug = legacySlugs.get(index) || `export-${index}`;
      const source: LinkRow['source'] = migrated
        ? 'migration'
        : (['admin', 'machine', 'anonymous'] as const)[index % 3];
      const machine = source === 'machine';
      rows.push({
        id: migrated ? `legacy:${await hash(`${domain}\0${slug}`)}` : crypto.randomUUID(),
        domain,
        slug,
        url: index === 0 ? longUrl : `https://example.test/${index}?raw=a%2Fb&same=+&same=%20#片`,
        created_at: migrated ? null : 123 + index,
        expires_at: index % 5 === 0 ? 456 : null,
        enabled: index % 7 === 0 ? 0 : 1,
        confirm_enabled: index % 11 === 0 ? 1 : 0,
        confirm_text: '导出 <b>保留</b> 🙂',
        query_mode: migrated ? 'preserve' : 'merge',
        source,
        creator: migrated ? 'legacy-kv' : 'synthetic-export-creator',
        token_id: machine ? business.id : null,
        idempotency_key: machine ? `export-fixture-${index}` : null,
        request_hash: machine ? 'a'.repeat(64) : null,
      });
    }
    const fields = Object.keys(rows[0]) as (keyof LinkRow)[];
    await env.DB.batch(
      rows.map((row) =>
        env.DB.prepare(
          `INSERT INTO links (${fields.join(',')}) VALUES (${fields.map(() => '?').join(',')})`,
        ).bind(...fields.map((field) => row[field])),
      ),
    );
    const before = (await env.DB.prepare('SELECT * FROM links ORDER BY rowid').all<LinkRow>())
      .results;
    expect(before).toEqual(rows);

    const issuer = 'https://lilyya.cloudflareaccess.com';
    const audience = 'd'.repeat(64);
    const { privateKey, publicKey } = await generateKeyPair('RS256');
    const jwk = {
      ...(await exportJWK(publicKey)),
      kid: 'synthetic-export-key',
      alg: 'RS256',
      use: 'sig',
    };
    const assertion = await new SignJWT({ email: 'admin@888888.mom', type: 'app' })
      .setProtectedHeader({ alg: 'RS256', kid: jwk.kid })
      .setIssuer(issuer)
      .setAudience(audience)
      .setSubject('synthetic-export-admin')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);
    const protectedEnv: Env = {
      ...env,
      CF_ACCESS_TEAM_DOMAIN: 'lilyya.cloudflareaccess.com',
      CF_ACCESS_AUD: audience,
      ADMIN_EMAILS: 'lilyyaloveyou@gmail.com,admin@888888.mom',
      WORKERS_DEV_HOSTNAME: 'shortlink-new.fixture.workers.dev',
    };
    const upstream: string[] = [];
    const intercepted = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, options) => {
      const address =
        typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      upstream.push(address);
      expect(address).toBe(`${issuer}/cdn-cgi/access/certs`);
      expect(options?.method || (input instanceof Request ? input.method : 'GET')).toBe('GET');
      return Response.json({ keys: [jwk] });
    });
    try {
      const exported: Record<string, unknown>[] = [];
      const pageSizes: number[] = [];
      const cursors = new Set<string>();
      let next: string | null = null;
      do {
        expect(pageSizes.length).toBeLessThan(3);
        const url = new URL(`https://${host}/api/admin/export`);
        if (next) url.searchParams.set('cursor', next);
        const response = await worker.fetch(
          new Request(url, {
            headers: { 'Cf-Access-Jwt-Assertion': assertion },
          }),
          protectedEnv,
          ctx,
        );
        expect(response.status).toBe(200);
        expect(response.headers.get('Cache-Control')).toBe('no-store');
        expect(response.headers.get('Content-Type')).toContain('application/json');
        expect(response.headers.get('Content-Security-Policy')).toContain("default-src 'none'");
        const raw = await response.text();
        expect(raw).not.toContain(business.token);
        expect(raw).not.toContain(digest);
        const page = JSON.parse(raw);
        expect(page.schema_version).toBe(1);
        expect(Array.isArray(page.links)).toBe(true);
        pageSizes.push(page.links.length);
        exported.push(...page.links);
        next = page.next_cursor;
        if (next !== null) {
          expect(typeof next).toBe('string');
          expect(next.length).toBeGreaterThan(0);
          expect(cursors.has(next)).toBe(false);
          cursors.add(next);
        }
      } while (next !== null);
      expect(pageSizes).toEqual([500, 3]);
      expect(exported).toHaveLength(rows.length);
      expect(new Set(exported.map((row) => row.id)).size).toBe(rows.length);
      for (const [index, row] of [...rows].reverse().entries()) {
        const actual = exported[index];
        expect(actual).toEqual({
          id: row.id,
          domain: row.domain,
          slug: row.slug,
          url: row.url,
          short_url: `https://${domain}/${encodeURIComponent(row.slug).replaceAll("'", '%27')}`,
          created_at: row.created_at,
          expires_at: row.expires_at,
          enabled: !!row.enabled,
          confirmation_enabled: !!row.confirm_enabled,
          confirmation_text: row.confirm_text,
          query_policy: row.query_mode,
          source: row.source,
        });
      }
      expect(Buffer.from(exported[502].url as string)).toEqual(Buffer.from(longUrl));
      expect(exported[502].short_url).toContain('%27');
      expect(exported[0].slug).not.toBe(exported[1].slug);
      expect(
        (await env.DB.prepare('SELECT * FROM links ORDER BY rowid').all<LinkRow>()).results,
      ).toEqual(before);
      for (const headers of [
        new Headers(),
        new Headers({ Authorization: `Bearer ${business.token}` }),
      ]) {
        const refused = await worker.fetch(
          new Request(`https://${host}/api/admin/export`, {
            headers,
          }),
          protectedEnv,
          ctx,
        );
        expect(refused.status).toBe(401);
        expect((await refused.json()) as { error: { code: string } }).toMatchObject({
          error: { code: 'ADMIN_REQUIRED' },
        });
      }
      for (const publicHost of [domain, protectedEnv.WORKERS_DEV_HOSTNAME]) {
        const refused = await worker.fetch(
          new Request(`https://${publicHost}/api/admin/export`, {
            headers: { Authorization: `Bearer ${business.token}` },
          }),
          protectedEnv,
          ctx,
        );
        expect(refused.status).toBe(403);
        expect((await refused.json()) as { error: { code: string } }).toMatchObject({
          error: { code: 'HOST_FORBIDDEN' },
        });
      }
      expect(upstream).toEqual([`${issuer}/cdn-cgi/access/certs`]);
    } finally {
      intercepted.mockRestore();
    }
  });

  it('backs up one atomic D1 snapshot to genuine R2 NDJSON and serves it through the protected handler', async () => {
    const created = await link('snapshot');
    await call('tokens', 'POST', { name: 'Snapshot fixture', domains: [domain] });
    const id = await startBackup(env, identity.email);
    const capturedCount = await env.DB.prepare(
      'SELECT COUNT(*) AS count FROM backup_rows WHERE backup_id = ?',
    )
      .bind(id)
      .first<number>('count');
    await call(`links/${created.id}`, 'PATCH', { confirmation_text: 'later mutation' });
    await call('settings', 'PUT', { error_404: 'later copy' });
    await advanceBackup(env);
    const job = await env.DB.prepare('SELECT status, records FROM backup_jobs WHERE id = ?')
      .bind(id)
      .first<{ status: string; records: number }>();
    expect(job?.status).toBe('complete');
    expect(job?.records).toBe(capturedCount);
    const download = await call(`backups/${id}/download`);
    expect(download.status).toBe(200);
    expect(download.headers.get('Cache-Control')).toBe('no-store');
    const lines = (await download.text())
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line));
    expect(lines).toHaveLength(capturedCount!);
    expect(
      lines.find((line) => line.table === 'links' && line.data.id === created.id).data.confirm_text,
    ).toBe('');
    expect(
      lines.find((line) => line.table === 'settings' && line.data.key === 'error_404').data.value,
    ).not.toBe('later copy');
    expect(
      lines.some((line) => line.table === 'tokens' && /^[a-f0-9]{64}$/.test(line.data.digest)),
    ).toBe(true);
    expect(
      await env.DB.prepare('SELECT COUNT(*) AS count FROM backup_rows WHERE backup_id = ?')
        .bind(id)
        .first('count'),
    ).toBe(0);
  });

  it('coalesces concurrent backup starts into one job and one snapshot', async () => {
    await link('concurrent-backup');
    const ids = await Promise.all(
      Array.from({ length: 6 }, () => startBackup(env, identity.email)),
    );
    expect(new Set(ids).size).toBe(1);
    expect(await env.DB.prepare('SELECT COUNT(*) AS count FROM backup_jobs').first('count')).toBe(
      1,
    );
    expect(
      await env.DB.prepare(
        "SELECT COUNT(*) AS count FROM audit WHERE action = 'backup.create'",
      ).first('count'),
    ).toBe(1);
    await Promise.all(Array.from({ length: 3 }, () => advanceBackup(env)));
    expect(await env.DB.prepare('SELECT status FROM backup_jobs').first('status')).toBe('complete');
  });

  it('paginates snapshot reads and preserves exact counts above a single 500-row read', async () => {
    for (let offset = 0; offset < 600; offset += 100) {
      await env.DB.batch(
        Array.from({ length: 100 }, (_, index) =>
          env.DB.prepare(
            "INSERT INTO links(id,domain,slug,url,created_at,source,creator) VALUES (?, ?, ?, ?, ?, 'admin', ?)",
          ).bind(
            crypto.randomUUID(),
            domain,
            `page-${offset + index}`,
            `https://example.com/${offset + index}`,
            Date.now(),
            identity.email,
          ),
        ),
      );
    }
    const id = await startBackup(env, identity.email);
    await advanceBackup(env);
    const object = await env.BACKUPS!.get(`backups/${id}.ndjson`);
    const lines = (await object!.text())
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line));
    expect(lines.filter((line) => line.table === 'links')).toHaveLength(600);
    expect(
      new Set(lines.filter((line) => line.table === 'links').map((line) => line.data.slug)).size,
    ).toBe(600);
  });

  it('recovers an expired multipart upload from the same atomic snapshot and preserves exact 5 MiB Unicode row checkpoints', async () => {
    const urls = Array.from(
      { length: 800 },
      (_, index) =>
        `https://example.com/路径/%2F/${'x'.repeat(7000)}?index=${index}&q=a+b&q=a%20b#片段`,
    );
    for (let offset = 0; offset < urls.length; offset += 100) {
      await env.DB.batch(
        urls
          .slice(offset, offset + 100)
          .map((url, index) =>
            env.DB.prepare(
              "INSERT INTO links(id,domain,slug,url,created_at,source,creator) VALUES (?, ?, ?, ?, ?, 'admin', ?)",
            ).bind(
              crypto.randomUUID(),
              domain,
              `large-${offset + index}`,
              url,
              Date.now(),
              identity.email,
            ),
          ),
      );
    }
    const id = await startBackup(env, identity.email);
    const expectedRecords = await env.DB.prepare(
      'SELECT COUNT(*) AS count FROM backup_rows WHERE backup_id = ?',
    )
      .bind(id)
      .first<number>('count');
    await advanceBackup(env);
    const checkpoint = await env.DB.prepare('SELECT * FROM backup_jobs WHERE id = ?')
      .bind(id)
      .first<{
        size: number;
        part_number: number;
        row_offset: number;
        status: string;
        upload_id: string;
      }>();
    expect(checkpoint).toMatchObject({
      size: 5 * 1024 * 1024,
      part_number: 2,
      status: 'uploading',
    });
    expect(checkpoint!.row_offset).toBeGreaterThan(0);
    await env.BACKUPS!.resumeMultipartUpload(`backups/${id}.ndjson`, checkpoint!.upload_id).abort();
    await env.DB.prepare('UPDATE backup_jobs SET upload_started_at = ? WHERE id = ?')
      .bind(Date.now() - 7 * 86_400_000, id)
      .run();
    await env.DB.prepare(
      "UPDATE links SET enabled = 0, confirm_text = 'mutation after snapshot' WHERE slug = 'large-0'",
    ).run();
    for (let pass = 0; pass < 3; pass++) await advanceBackup(env);
    const finalJob = await env.DB.prepare(
      'SELECT status, size, records, parts FROM backup_jobs WHERE id = ?',
    )
      .bind(id)
      .first<{ status: string; size: number; records: number; parts: string }>();
    expect(finalJob!.status).toBe('complete');
    expect(JSON.parse(finalJob!.parts)).toHaveLength(2);
    expect(finalJob!.records).toBe(expectedRecords);
    const object = await env.BACKUPS!.get(`backups/${id}.ndjson`);
    const text = await object!.text();
    expect(object!.size).toBe(finalJob!.size);
    expect(new TextEncoder().encode(text).byteLength).toBe(finalJob!.size);
    const records = text
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line));
    expect(records).toHaveLength(expectedRecords!);
    const mapping = new Map(
      records
        .filter((record) => record.table === 'links')
        .map((record) => [record.data.slug, record.data.url]),
    );
    expect(mapping.size).toBe(800);
    urls.forEach((url, index) => expect(mapping.get(`large-${index}`)).toBe(url));
    expect(
      records.find((record) => record.table === 'links' && record.data.slug === 'large-0').data,
    ).toMatchObject({ enabled: 1, confirm_text: '' });
  }, 20_000);

  it('retention cleans old aggregates/audit/backup objects but preserves expired and disabled link mappings', async () => {
    const created = await link('permanent-map');
    await call(`links/${created.id}`, 'PATCH', { enabled: false, expires_at: 1 });
    await env.DB.prepare(
      "INSERT INTO daily_stats VALUES ('2000-01-01', ?, ?, 'XX', 'desktop', 'direct', 1)",
    )
      .bind(domain, created.slug)
      .run();
    await env.DB.prepare(
      'INSERT INTO audit(id,actor,action,entity_id,created_at) VALUES (?, ?, ?, ?, 1)',
    )
      .bind(crypto.randomUUID(), identity.email, 'fixture.old', 'fixture')
      .run();
    const oldId = crypto.randomUUID();
    await env.DB.prepare(
      "INSERT INTO backup_jobs(id, created_at, status, completed_at) VALUES (?, 1, 'complete', 1)",
    )
      .bind(oldId)
      .run();
    await env.BACKUPS!.put(`backups/${oldId}.ndjson`, '{"fixture":true}\n');
    await maintenance(env);
    expect(await env.DB.prepare('SELECT COUNT(*) AS count FROM links').first('count')).toBe(1);
    expect(
      await env.DB.prepare('SELECT url FROM links WHERE id = ?').bind(created.id).first('url'),
    ).toBe(created.url);
    expect(
      await env.DB.prepare(
        "SELECT COUNT(*) AS count FROM daily_stats WHERE day = '2000-01-01'",
      ).first('count'),
    ).toBe(0);
    expect(
      await env.DB.prepare(
        "SELECT COUNT(*) AS count FROM audit WHERE action = 'fixture.old'",
      ).first('count'),
    ).toBe(0);
    expect(await env.BACKUPS!.get(`backups/${oldId}.ndjson`)).toBeNull();
    expect(
      await env.DB.prepare(
        'SELECT retired_at,retention_checked_at,upload_id,parts,size,records FROM backup_jobs WHERE id = ?',
      )
        .bind(oldId)
        .first(),
    ).toMatchObject({
      retired_at: expect.any(Number),
      retention_checked_at: expect.any(Number),
      upload_id: null,
      parts: '[]',
      size: 0,
      records: 0,
    });
    expect(
      (await output(await call('backups'))).data.items.some(
        (item: { id: string }) => item.id === oldId,
      ),
    ).toBe(false);
    expect((await call(`backups/${oldId}/download`)).status).toBe(404);
    await env.BACKUPS!.put(`backups/${oldId}.ndjson`, '{"fixture":"late completion"}\n');
    expect((await call(`backups/${oldId}/download`)).status).toBe(404);
    await maintenance(env);
    expect(await env.BACKUPS!.get(`backups/${oldId}.ndjson`)).toBeNull();
  });
});
