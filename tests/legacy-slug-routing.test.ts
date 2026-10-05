import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { build } from 'vite';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const publicHost = 'test.gfw.mom';
const workersHost = 'shortlink-new.fixture.workers.dev';
const adminHost = 'link-admin.lily.lat';
const issuer = 'https://lilyya.cloudflareaccess.com';
const audience = 'c'.repeat(64);
const machineToken = 'synthetic-legacy-routing-token-' + 'x'.repeat(16);
const captcha = 'synthetic-legacy-routing-captcha';
const rawTarget = 'https://example.test/签名/%2F?sig=abc%2f&same=+&same=%20#片';
const encodedTarget =
  'https://example.test/%E7%AD%BE%E5%90%8D/%2F?sig=abc%2f&same=+&same=%20#%E7%89%87';
const css = 'body { color: black; }';
const javascript = 'export const fixture = true;';
let mf: Miniflare;
let directory: string;
let db: D1Database;
let assertion: string;
let csrf: string;
const outbound: string[] = [];
type FetchInit = Parameters<Miniflare['dispatchFetch']>[1];
interface ManagedLink {
  id: string;
  slug: string;
  url: string;
  short_url: string;
  enabled: boolean;
  confirmation_enabled: boolean;
}

function canonical(slug: string): string {
  return `https://${publicHost}/${encodeURIComponent(slug).replaceAll("'", '%27')}`;
}
function request(host: string, path: string, init?: FetchInit) {
  return mf.dispatchFetch(`https://${host}${path}`, { ...init, redirect: 'manual' });
}
function admin(path: string, method = 'GET', body?: unknown) {
  return request(adminHost, `/api/admin/${path}`, {
    method,
    headers: {
      'Cf-Access-Jwt-Assertion': assertion,
      ...(body === undefined
        ? {}
        : {
            Origin: `https://${adminHost}`,
            'X-CSRF-Token': csrf,
            'Content-Type': 'application/json',
          }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}
async function insert(slug: string, source = 'migration'): Promise<string> {
  const id = `legacy:${createHash('sha256').update(slug).digest('hex')}`;
  await db
    .prepare(
      "INSERT INTO links(id,domain,slug,url,created_at,query_mode,source,creator) VALUES(?,?,?,?,NULL,'preserve',?,'synthetic-fixture')",
    )
    .bind(id, publicHost, slug, rawTarget, source)
    .run();
  return id;
}

beforeAll(async () => {
  const built = await build({
    configFile: false,
    root: fileURLToPath(new URL('..', import.meta.url)),
    logLevel: 'silent',
    build: {
      write: false,
      minify: false,
      target: 'es2022',
      lib: {
        entry: fileURLToPath(new URL('../src/index.ts', import.meta.url)),
        formats: ['es'],
        fileName: 'worker',
      },
    },
  });
  const builds = Array.isArray(built) ? built : [built];
  const chunks = builds.flatMap((result) =>
    'output' in result ? result.output.filter((output) => output.type === 'chunk') : [],
  );
  expect(chunks).toHaveLength(1);
  const { privateKey, publicKey } = await generateKeyPair('RS256');
  const jwk = {
    ...(await exportJWK(publicKey)),
    kid: 'synthetic-legacy-routing-key',
    alg: 'RS256',
    use: 'sig',
  };
  assertion = await new SignJWT({ email: 'admin@888888.mom', type: 'app' })
    .setProtectedHeader({ alg: 'RS256', kid: jwk.kid })
    .setIssuer(issuer)
    .setAudience(audience)
    .setSubject('synthetic-legacy-routing-admin')
    .setIssuedAt()
    .setExpirationTime('10m')
    .sign(privateKey);
  directory = await mkdtemp(join(tmpdir(), 'shortlink-legacy-slugs-'));
  await mkdir(join(directory, 'assets'));
  await Promise.all([
    writeFile(join(directory, 'index.html'), '<!doctype html><title>synthetic page</title>'),
    writeFile(join(directory, 'status.css'), css),
    writeFile(join(directory, 'assets', 'fixture.js'), javascript),
  ]);
  mf = new Miniflare(
    convertV4MiniflareOptions({
      modules: true,
      compatibilityDate: '2026-07-02',
      script: chunks[0].code,
      bindings: {
        APP_ENV: 'test',
        PUBLIC_HOSTNAME: publicHost,
        ADMIN_HOSTNAME: adminHost,
        WORKERS_DEV_HOSTNAME: workersHost,
        CF_ACCESS_TEAM_DOMAIN: 'lilyya.cloudflareaccess.com',
        CF_ACCESS_AUD: audience,
        ADMIN_EMAILS: 'lilyyaloveyou@gmail.com,admin@888888.mom',
        TURNSTILE_SITE_KEY: 'synthetic-site-key',
        TURNSTILE_SECRET_KEY: 'synthetic-secret-key',
      },
      d1Databases: ['DB'],
      assets: {
        directory,
        binding: 'ASSETS',
        run_worker_first: true,
        routerConfig: { has_user_worker: true },
        assetConfig: { html_handling: 'none' },
      },
      outboundService: async (incoming) => {
        outbound.push(incoming.url);
        if (incoming.url === `${issuer}/cdn-cgi/access/certs`) {
          expect(incoming.method).toBe('GET');
          return Response.json({ keys: [jwk] });
        }
        expect(incoming.url).toBe('https://challenges.cloudflare.com/turnstile/v0/siteverify');
        expect(incoming.method).toBe('POST');
        const form = new URLSearchParams(await incoming.text());
        expect(form.get('secret')).toBe('synthetic-secret-key');
        expect(form.get('response')).toBe(captcha);
        return Response.json({ success: true, hostname: publicHost, action: 'create' });
      },
    }),
  );
  db = (await mf.getD1Database('DB')) as unknown as D1Database;
  for (const file of (await readdir(new URL('../migrations/', import.meta.url)))
    .filter((name) => name.endsWith('.sql'))
    .sort()) {
    const sql = await readFile(new URL(`../migrations/${file}`, import.meta.url), 'utf8');
    await db.batch(
      sql
        .split(';')
        .filter((statement) => statement.trim())
        .map((statement) => db.prepare(statement)),
    );
  }
  await db
    .prepare(
      "INSERT INTO domains(hostname,enabled,bound,created_at,binding_state) VALUES(?,1,1,?,'verified')",
    )
    .bind(publicHost, Date.now())
    .run();
  await db
    .prepare('INSERT INTO tokens(id,label,digest,created_at) VALUES(?,?,?,?)')
    .bind(
      'synthetic-token',
      'fixture',
      createHash('sha256').update(machineToken).digest('hex'),
      Date.now(),
    )
    .run();
  await db
    .prepare('INSERT INTO token_domains VALUES(?,?)')
    .bind('synthetic-token', publicHost)
    .run();
  const session = await admin('session');
  expect(session.status).toBe(200);
  const identity = (await session.json()) as { data: { email: string; csrf: string } };
  expect(identity.data.email).toBe('admin@888888.mom');
  expect(identity.data.csrf).toMatch(/^[a-f0-9]{64}$/);
  csrf = identity.data.csrf;
}, 30000);

afterAll(async () => {
  try {
    await mf?.dispose();
  } finally {
    if (directory) await rm(directory, { recursive: true, force: true });
  }
});

describe('legacy slug routing in the actual Workers runtime', () => {
  it('retains exact dots, spaces, Unicode marks, apostrophes and fullwidth parentheses on both public hosts', async () => {
    for (const slug of [
      'file.name',
      ' spaced key ',
      '保留é',
      'Cafe\u0301',
      "owner's",
      '全角（保持）',
      'x'.repeat(65),
      'é'.repeat(256),
    ]) {
      expect(Buffer.byteLength(slug)).toBeLessThanOrEqual(512);
      await insert(slug);
      for (const host of [publicHost, workersHost]) {
        const response = await request(
          host,
          new URL(canonical(slug)).pathname + '?extra=ignored&same=override',
        );
        expect(response.status, slug).toBe(302);
        expect(response.headers.get('Location')).toBe(encodedTarget);
        expect(response.headers.get('Cache-Control')).toBe('no-store');
      }
      const stored = await db
        .prepare('SELECT slug,url FROM links WHERE domain=? AND slug=?')
        .bind(publicHost, slug)
        .first();
      expect(stored).toMatchObject({ slug, url: rawTarget });
    }
    await insert('Café');
    expect((await request(publicHost, '/Caf%C3%A9')).status).toBe(302);
    const separate = await db
      .prepare('SELECT COUNT(*) AS count FROM links WHERE slug IN (?,?)')
      .bind('Café', 'Cafe\u0301')
      .first<{ count: number }>();
    expect(separate?.count).toBe(2);
  });

  it('allows a single percent decode and ASCII aliases only for migration rows', async () => {
    await insert('Alias', 'migration');
    expect((await request(publicHost, '/%41lias')).status).toBe(302);
    expect((await request(publicHost, '/%41%6c%69%61%73')).status).toBe(302);
    expect((await request(publicHost, '/%2541lias')).status).toBe(404);
    expect((await request(publicHost, '/%61lias')).status).toBe(404);
    for (const source of ['machine', 'anonymous', 'admin']) {
      const slug = `${source}-plain`;
      await insert(slug, source);
      expect((await request(publicHost, `/${slug}`)).status).toBe(302);
      expect(
        (await request(publicHost, `/%${slug.charCodeAt(0).toString(16)}${slug.slice(1)}`)).status,
      ).toBe(404);
      const wide = `${source}.wide`;
      await insert(wide, source);
      expect((await request(publicHost, new URL(canonical(wide)).pathname)).status).toBe(404);
      const long = `${source}-${'l'.repeat(65)}`;
      await insert(long, source);
      expect((await request(publicHost, `/${long}`)).status).toBe(404);
    }
    await insert('SYS_CONFIG_created', 'admin');
    expect((await request(publicHost, '/SYS_CONFIG_created')).status).toBe(302);
    expect((await request(publicHost, '/%53YS_CONFIG_created')).status).toBe(404);
  });

  it('keeps admin list and lifecycle DTO URLs canonical and navigable without changing permanent fields', async () => {
    const slug = "管理员's （原文）";
    const id = await insert(slug);
    const listed = await admin(`links?q=${encodeURIComponent(slug)}`);
    expect(listed.status).toBe(200);
    const data = (await listed.json()) as { data: { items: ManagedLink[] } };
    const item = data.data.items.find((link) => link.id === id);
    expect(item).toMatchObject({ slug, url: rawTarget, short_url: canonical(slug), enabled: true });
    expect(item?.short_url).toContain('%27');
    expect(
      (await mf.dispatchFetch(item!.short_url, { redirect: 'manual' })).headers.get('Location'),
    ).toBe(encodedTarget);
    const disabled = await admin(`links/${encodeURIComponent(id)}`, 'PATCH', { enabled: false });
    expect(disabled.status).toBe(200);
    expect((await disabled.json()) as { data: ManagedLink }).toMatchObject({
      data: { slug, url: rawTarget, short_url: canonical(slug), enabled: false },
    });
    expect((await request(publicHost, new URL(canonical(slug)).pathname)).status).toBe(410);
    const restored = await admin(`links/${encodeURIComponent(id)}`, 'PATCH', {
      enabled: true,
      confirmation_enabled: true,
      confirmation_text: '<script>synthetic confirmation</script>',
    });
    expect(restored.status).toBe(200);
    const confirmed = await request(publicHost, new URL(canonical(slug)).pathname);
    expect(confirmed.status).toBe(200);
    const html = await confirmed.text();
    expect(html).toContain('&lt;script&gt;synthetic confirmation&lt;/script&gt;');
    expect(html).not.toContain('<script>synthetic confirmation</script>');
    const href = /<a class="button" href="([^"]+)"/.exec(html)?.[1];
    expect(href?.replaceAll('&amp;', '&')).toBe(rawTarget);
  });

  it('retains reserved API and static routes before any legacy mapping, including encoded aliases', async () => {
    for (const slug of [
      'api',
      'admin',
      'assets',
      'robots.txt',
      'status.css',
      'api/public/config',
      'assets/fixture.js',
    ])
      await insert(slug);
    const config = await request(publicHost, '/api/public/config');
    expect(config.status).toBe(200);
    expect(await config.json()).toMatchObject({ ok: true, data: { domain: publicHost } });
    expect((await request(publicHost, '/api/shorten')).status).toBe(403);
    expect((await request(publicHost, '/admin')).status).toBe(403);
    expect((await request(publicHost, '/assets')).status).toBe(404);
    const robots = await request(publicHost, '/robots.txt');
    expect(robots.status).toBe(200);
    expect(await robots.text()).toContain('Disallow: /api/');
    const style = await request(publicHost, '/status.css');
    expect(style.status).toBe(200);
    expect(await style.text()).toBe(css);
    const script = await request(publicHost, '/assets/fixture.js');
    expect(script.status).toBe(200);
    expect(await script.text()).toBe(javascript);
    for (const path of [
      '/%61pi',
      '/%61dmin',
      '/%61ssets',
      '/robots%2etxt',
      '/%73tatus.css',
      '/%53YS_CONFIG_created',
    ])
      expect((await request(publicHost, path)).status, path).toBe(404);
  });

  it('requires Access identity before every admin legacy or static path', async () => {
    for (const path of [
      '/file.name',
      '/%41lias',
      '/assets/fixture.js',
      '/status.css',
      '/api/shorten/',
    ]) {
      expect((await request(adminHost, path)).status, path).toBe(401);
      const authenticated = await request(adminHost, path, {
        headers: { 'Cf-Access-Jwt-Assertion': assertion },
      });
      expect(authenticated.status, path).toBe(
        path.startsWith('/assets/') || path === '/status.css' ? 200 : 404,
      );
      expect(authenticated.headers.get('Location')).toBeNull();
    }
    expect(
      (
        await request(adminHost, '/file.name', {
          headers: { 'Cf-Access-Jwt-Assertion': 'synthetic-invalid-jwt' },
        })
      ).status,
    ).toBe(401);
    expect(
      outbound.filter((url) => url === `${issuer}/cdn-cgi/access/certs`).length,
    ).toBeGreaterThan(0);
  });

  it('rejects path delimiters, malformed encodings, controls and excessive raw UTF-8 bytes', async () => {
    const invalidSlugs = [
      '/',
      '\\',
      '?',
      '#',
      '%41',
      'unsafe\u0000key',
      'hidden\u200bkey',
      'bidi\u202ekey',
      'é'.repeat(256) + 'a',
    ];
    for (const slug of invalidSlugs) {
      await insert(slug);
      const response = await request(publicHost, '/' + encodeURIComponent(slug));
      expect(response.status, slug).toBe(404);
      expect(response.headers.get('Location')).toBeNull();
    }
    // WHATWG Request normalizes dot segments before Worker code receives the URL.
    // Even a poisoned local row must never turn that normalized homepage into a redirect.
    await insert('.');
    await insert('..');
    for (const path of ['/.', '/..', '/%2e', '/%2e%2e']) {
      const response = await request(publicHost, path);
      expect(response.status).toBe(200);
      expect(response.headers.get('Location')).toBeNull();
      expect(await response.text()).toContain('synthetic page');
    }
    for (const path of [
      '/%',
      '/%GG',
      '/%C0%AF',
      '/%E2%82',
      '/%ED%A0%80',
      '/a/b',
      '/a%2Fb',
      '/a%5cb',
      '/a%252Fb',
      '/' + '%61'.repeat(513),
    ]) {
      const response = await request(publicHost, path);
      expect(response.status, path).toBe(404);
      expect(response.headers.get('Location')).toBeNull();
    }
  });

  it('keeps new creation limited to ASCII 1–64 through anonymous, machine and authenticated admin routes', async () => {
    for (const [mode, host, path, letter] of [
      ['anonymous', publicHost, '/api/public/shorten', 'A'],
      ['machine', adminHost, '/api/shorten', 'B'],
      ['admin', adminHost, '/api/admin/links', 'C'],
    ] as const) {
      const create = (slug: string) =>
        request(host, path, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...(mode === 'anonymous' ? { Origin: `https://${publicHost}` } : {}),
            ...(mode === 'machine' ? { Authorization: `Bearer ${machineToken}` } : {}),
            ...(mode === 'admin'
              ? {
                  Origin: `https://${adminHost}`,
                  'Cf-Access-Jwt-Assertion': assertion,
                  'X-CSRF-Token': csrf,
                }
              : {}),
          },
          body: JSON.stringify({
            url: rawTarget,
            slug,
            ...(mode === 'anonymous' ? { turnstile_token: captcha } : { domain: publicHost }),
          }),
        });
      for (const slug of [letter, letter.repeat(64)]) {
        const response = await create(slug);
        expect(response.status, mode).toBe(201);
        expect(await response.json()).toMatchObject({
          ok: true,
          data: { slug, short_url: canonical(slug) },
        });
        expect((await request(publicHost, `/${slug}`)).status).toBe(302);
      }
      for (const slug of [
        '',
        letter.repeat(65),
        `${letter}.dot`,
        `${letter} space`,
        `${letter}中`,
        `${letter}'quote`,
        `${letter}（括号）`,
      ]) {
        const response = await create(slug);
        expect(response.status, `${mode}:${slug}`).toBe(400);
        expect(await response.json()).toMatchObject({ ok: false, error: { code: 'INVALID_SLUG' } });
      }
    }
    expect(
      outbound.every((url) =>
        [
          `${issuer}/cdn-cgi/access/certs`,
          'https://challenges.cloudflare.com/turnstile/v0/siteverify',
        ].includes(url),
      ),
    ).toBe(true);
  });
});
