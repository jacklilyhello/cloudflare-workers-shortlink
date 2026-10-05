import { readFile, readdir } from 'node:fs/promises';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import {
  handleCreate,
  handleRedirect,
  hash,
  locationHeader,
  mergeQuery,
  parseJSONStrict,
  validateSlug,
  validateUrl,
} from '../src/core';
import type { Env, LinkRow } from '../src/types';
import { route } from '../src/index';

const publicHost = 'test.gfw.mom';
const adminHost = 'link-admin.lily.lat';
const bearer = 'sl_' + 'A'.repeat(43);
const secondBearer = 'sl_' + 'B'.repeat(43);
let mf: Miniflare;
let env: Env;
let jobs: Promise<unknown>[];
let ctx: ExecutionContext;

async function token(id = 'token-1', value = bearer): Promise<void> {
  await env.DB.prepare('INSERT INTO tokens(id, label, digest, created_at) VALUES (?, ?, ?, ?)')
    .bind(id, 'test fixture', await hash(value), Date.now())
    .run();
  await env.DB.prepare('INSERT INTO token_domains(token_id, domain) VALUES (?, ?)')
    .bind(id, publicHost)
    .run();
}

function create(
  body: unknown = { url: 'https://example.com/a', domain: publicHost },
  options: {
    token?: string | null;
    headers?: HeadersInit;
    host?: string;
    mode?: 'machine' | 'anonymous';
    raw?: string;
    method?: string;
  } = {},
): Promise<Response> {
  const mode = options.mode ?? 'machine';
  const headers = new Headers(options.headers);
  if (!headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  if (options.token !== null && mode === 'machine')
    headers.set('Authorization', `Bearer ${options.token ?? bearer}`);
  const host = options.host ?? (mode === 'machine' ? adminHost : publicHost);
  if (mode === 'anonymous' && !headers.has('Origin')) headers.set('Origin', `https://${host}`);
  return handleCreate(
    new Request(`https://${host}/${mode === 'machine' ? 'api/shorten' : 'api/create'}`, {
      method: options.method ?? 'POST',
      headers,
      ...(options.method === 'GET' ? {} : { body: options.raw ?? JSON.stringify(body) }),
    }),
    env,
    ctx,
    mode,
  );
}

async function data(response: Response): Promise<Record<string, any>> {
  return (await response.json()) as Record<string, any>;
}

async function redirect(
  slug: string,
  query = '',
  method = 'GET',
  headers?: HeadersInit,
): Promise<Response> {
  return handleRedirect(
    new Request(`https://${publicHost}/${slug}${query}`, { method, headers }),
    env,
    ctx,
    publicHost,
    slug,
  );
}

async function row(slug: string): Promise<LinkRow> {
  return (await env.DB.prepare('SELECT * FROM links WHERE domain = ? AND slug = ?')
    .bind(publicHost, slug)
    .first<LinkRow>())!;
}

beforeAll(async () => {
  mf = new Miniflare(
    convertV4MiniflareOptions({
      modules: true,
      script: 'export default { fetch() { return new Response("test"); } }',
      d1Databases: ['DB'],
    }),
  );
  const DB = await mf.getD1Database('DB');
  env = {
    DB: DB as unknown as D1Database,
    PUBLIC_HOSTNAME: publicHost,
    ADMIN_HOSTNAME: adminHost,
    WORKERS_DEV_HOSTNAME: 'shortlink-new.example.workers.dev',
    APP_ENV: 'test',
    ADMIN_EMAILS: 'admin@example.test',
    TURNSTILE_SITE_KEY: 'fixture-sitekey',
    TURNSTILE_SECRET_KEY: 'fixture-secret',
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
      'DELETE FROM audit',
      'DELETE FROM daily_stats',
      'DELETE FROM links',
      'DELETE FROM deleted_links',
      'DELETE FROM token_domains',
      'DELETE FROM tokens',
      'DELETE FROM domains',
      'DELETE FROM rate_windows',
    ].map((sql) => env.DB.prepare(sql)),
  );
  await env.DB.prepare(
    "INSERT INTO domains(hostname, enabled, bound, created_at, binding_state) VALUES (?, 1, 1, ?, 'verified')",
  )
    .bind(publicHost, Date.now())
    .run();
  await token();
  await env.DB.prepare(
    "UPDATE settings SET value = CASE key WHEN 'domain_rate_per_minute' THEN '120' WHEN 'anonymous_rate_per_minute' THEN '10' ELSE value END",
  ).run();
  jobs = [];
  ctx = {
    waitUntil(promise: Promise<unknown>) {
      jobs.push(promise);
    },
    passThroughOnException() {},
  } as unknown as ExecutionContext;
});

afterEach(async () => {
  await Promise.all(jobs);
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
afterAll(async () => {
  await mf?.dispose();
});

describe('creation on actual local D1', () => {
  it('preserves complete original URL and defaults to permanent direct links without global deduplication', async () => {
    const target = 'https://example.com/路径/%2F?q=a+b&q=a%20b&x=%2b#片段';
    const first = await data(await create({ url: target, domain: publicHost }));
    const second = await data(await create({ url: target, domain: publicHost }));
    expect(first.data.slug).not.toBe(second.data.slug);
    const stored = await row(first.data.slug);
    expect(stored.url).toBe(target);
    expect(stored.expires_at).toBeNull();
    expect(stored.enabled).toBe(1);
    expect(stored.confirm_enabled).toBe(0);
    expect(await env.DB.prepare('SELECT COUNT(*) AS count FROM audit').first('count')).toBe(2);
  });

  it.each([null, '', 'wrong-token', 'sl_' + 'C'.repeat(43)])(
    'rejects missing/malformed/unknown tokens %s',
    async (value) => {
      const response = await create(undefined, { token: value });
      expect(response.status).toBe(401);
      expect((await data(response)).error.code).toBe(
        value === null ? 'TOKEN_REQUIRED' : 'TOKEN_INVALID',
      );
      expect(await env.DB.prepare('SELECT COUNT(*) AS count FROM links').first('count')).toBe(0);
    },
  );

  it.each(['revoked', 'expired'])(
    'rejects %s token without distinguishing existence',
    async (state) => {
      await env.DB.prepare(
        state === 'revoked'
          ? 'UPDATE tokens SET revoked_at = ?'
          : 'UPDATE tokens SET expires_at = ?',
      )
        .bind(Date.now() - 1)
        .run();
      const response = await create();
      expect(response.status).toBe(401);
      expect((await data(response)).error.code).toBe('TOKEN_INVALID');
    },
  );

  it.each(['unbound', 'disabled', 'unassigned'])(
    'enforces domain registration/binding/permission: %s',
    async (state) => {
      await env.DB.prepare(
        state === 'unbound'
          ? 'UPDATE domains SET bound = 0'
          : state === 'disabled'
            ? 'UPDATE domains SET enabled = 0'
            : 'DELETE FROM token_domains',
      ).run();
      expect((await create()).status).toBe(403);
    },
  );

  it.each([
    'gfw.mom',
    'other.lily.lat',
    'https://test.gfw.mom',
    'test.gfw.mom.',
    'TEST.gfw.mom',
    'test.gfw.mom:443',
  ])('rejects unauthorized or noncanonical domain %s', async (domain) => {
    expect([400, 403]).toContain((await create({ url: 'https://example.com', domain })).status);
  });

  it.each([publicHost, 'shortlink-new.example.workers.dev'])(
    'does not expose machine creation on %s',
    async (host) => {
      const response = await create(undefined, { host });
      expect(response.status).toBe(403);
      expect((await data(response)).error.code).toBe('HOST_FORBIDDEN');
    },
  );

  it.each([
    'expires_at',
    'enabled',
    'confirmation_enabled',
    'confirmation_text',
    'query_policy',
    'token_id',
    '__proto__',
  ])('refuses management or unknown field %s', async (field) => {
    const response = await create(undefined, {
      raw: `{"url":"https://example.com","domain":"${publicHost}","${field}":true}`,
    });
    expect(response.status).toBe(400);
    expect((await data(response)).error.code).toBe('UNKNOWN_FIELD');
    expect(await env.DB.prepare('SELECT COUNT(*) AS count FROM links').first('count')).toBe(0);
  });

  it.each([
    '{"url":"https://example.com","url":"https://other.example","domain":"test.gfw.mom"}',
    '{"url":"https://example.com","\\u0075rl":"https://other.example","domain":"test.gfw.mom"}',
    '[]',
    'null',
    '{} trailing',
    '{"url":NaN}',
    '{"url":{"a":1,"a":2}}',
  ])('rejects malformed/nonobject/duplicate JSON %s', async (raw) => {
    const response = await create(undefined, { raw });
    expect(response.status).toBe(400);
    expect((await data(response)).error.code).toBe('INVALID_JSON');
  });

  it('enforces actual streaming byte limits instead of trusting Content-Length', async () => {
    const raw = JSON.stringify({
      url: 'https://example.com/' + 'x'.repeat(20_000),
      domain: publicHost,
    });
    const response = await create(undefined, { raw });
    expect(response.status).toBe(413);
    expect((await data(response)).error.code).toBe('BODY_TOO_LARGE');
    const targetTooLong = await create({
      url: 'https://example.com/' + 'x'.repeat(8500),
      domain: publicHost,
    });
    expect(targetTooLong.status).toBe(413);
    expect((await data(targetTooLong)).error.code).toBe('URL_TOO_LONG');
    const misleading = await create(undefined, { raw, headers: { 'Content-Length': '1' } });
    expect(misleading.status).toBe(413);
  });

  it('rejects wrong Content-Type and methods', async () => {
    expect((await create(undefined, { headers: { 'Content-Type': 'text/plain' } })).status).toBe(
      415,
    );
    const wrongMethod = await create(undefined, { method: 'GET' });
    expect(wrongMethod.status).toBe(405);
    expect(wrongMethod.headers.get('Allow')).toBe('POST');
  });

  it('handles same custom slug under concurrency once without overwrite, including disabled links', async () => {
    const responses = await Promise.all(
      Array.from({ length: 10 }, (_, index) =>
        create({ url: `https://example.com/${index}`, domain: publicHost, slug: 'Fixed_code' }),
      ),
    );
    expect(responses.filter((response) => response.status === 201)).toHaveLength(1);
    expect(responses.filter((response) => response.status === 409)).toHaveLength(9);
    const stored = await row('Fixed_code');
    await env.DB.prepare('UPDATE links SET enabled = 0, expires_at = 1 WHERE id = ?')
      .bind(stored.id)
      .run();
    expect(
      (await create({ url: 'https://other.example', domain: publicHost, slug: 'Fixed_code' }))
        .status,
    ).toBe(409);
    expect((await row('Fixed_code')).url).toBe(stored.url);
  });

  it('keeps case-sensitive slug uniqueness', async () => {
    expect(
      (await create({ url: 'https://example.com', domain: publicHost, slug: 'CODE' })).status,
    ).toBe(201);
    expect(
      (await create({ url: 'https://example.com', domain: publicHost, slug: 'code' })).status,
    ).toBe(201);
  });

  it('retries random collisions finitely, never replacing existing mappings', async () => {
    await create({ url: 'https://first.example', domain: publicHost, slug: 'AAAAAAAAAA' });
    vi.spyOn(crypto, 'getRandomValues').mockImplementation((bytes: any) => {
      bytes.fill(0);
      return bytes;
    });
    const response = await create();
    expect(response.status).toBe(503);
    expect((await data(response)).error.code).toBe('SLUG_GENERATION_EXHAUSTED');
    expect((await row('AAAAAAAAAA')).url).toBe('https://first.example');
  });

  it('atomically resolves concurrent idempotency to one durable mapping; full request and identity are bound', async () => {
    const body = { url: 'https://example.com/?q=a+b#f', domain: publicHost };
    const responses = await Promise.all(
      Array.from({ length: 8 }, () =>
        create(body, { headers: { 'Idempotency-Key': 'operation-1' } }),
      ),
    );
    expect(responses.filter((response) => response.status === 201)).toHaveLength(1);
    expect(responses.filter((response) => response.status === 200)).toHaveLength(7);
    const outputs = await Promise.all(responses.map(data));
    expect(new Set(outputs.map((output) => output.data.slug)).size).toBe(1);
    expect(await env.DB.prepare('SELECT COUNT(*) AS count FROM links').first('count')).toBe(1);
    expect(await env.DB.prepare('SELECT COUNT(*) AS count FROM audit').first('count')).toBe(1);
    expect(
      (
        await create(
          { ...body, url: 'https://example.com/?q=a%20b#f' },
          { headers: { 'Idempotency-Key': 'operation-1' } },
        )
      ).status,
    ).toBe(409);
    expect(
      (
        await create(
          { ...body, slug: 'new-code' },
          { headers: { 'Idempotency-Key': 'operation-1' } },
        )
      ).status,
    ).toBe(409);
    await token('token-2', secondBearer);
    expect(
      (await create(body, { token: secondBearer, headers: { 'Idempotency-Key': 'operation-1' } }))
        .status,
    ).toBe(201);
  });

  it('rejects an existing idempotency replay while its domain is disabled and resumes the same mapping after re-enabling', async () => {
    const body = {
      url: 'https://example.com/?q=a+b&q=a%20b&sig=a%2Bb#fragment',
      domain: publicHost,
    };
    const options = { headers: { 'Idempotency-Key': 'domain-lifecycle-replay' } };
    const created = await create(body, options);
    expect(created.status).toBe(201);
    const original = (await data(created)).data;
    const stored = await row(original.slug);
    expect(stored).toMatchObject({
      url: body.url,
      token_id: 'token-1',
      idempotency_key: 'domain-lifecycle-replay',
    });
    expect(stored.request_hash).toMatch(/^[a-f0-9]{64}$/);

    await env.DB.prepare('UPDATE domains SET enabled=0 WHERE hostname=?').bind(publicHost).run();
    const denied = await create(body, options);
    expect(denied.status).toBe(403);
    expect((await data(denied)).error.code).toBe('DOMAIN_FORBIDDEN');
    expect(denied.headers.get('Idempotency-Replayed')).toBeNull();
    expect(await row(original.slug)).toEqual(stored);
    expect(await env.DB.prepare('SELECT COUNT(*) AS count FROM links').first('count')).toBe(1);

    await env.DB.prepare('UPDATE domains SET enabled=1 WHERE hostname=?').bind(publicHost).run();
    const replayed = await create(body, options);
    expect(replayed.status).toBe(200);
    expect(replayed.headers.get('Idempotency-Replayed')).toBe('true');
    expect((await data(replayed)).data).toEqual(original);
    expect(await row(original.slug)).toEqual(stored);
    expect(await env.DB.prepare('SELECT COUNT(*) AS count FROM links').first('count')).toBe(1);
    expect(await env.DB.prepare('SELECT COUNT(*) AS count FROM audit').first('count')).toBe(1);
  });

  it.each(['revoked', 'expired'])(
    'rejects an existing idempotency replay after its Token is %s without altering the permanent mapping',
    async (state) => {
      const body = {
        url: 'https://example.com/?q=a+b&q=a%20b&sig=a%2Bb#fragment',
        domain: publicHost,
      };
      const options = { headers: { 'Idempotency-Key': 'token-lifecycle-replay' } };
      const created = await create(body, options);
      expect(created.status).toBe(201);
      const original = (await data(created)).data;
      const stored = await row(original.slug);
      expect(stored).toMatchObject({
        url: body.url,
        token_id: 'token-1',
        idempotency_key: 'token-lifecycle-replay',
      });
      expect(stored.request_hash).toMatch(/^[a-f0-9]{64}$/);
      await env.DB.prepare(
        state === 'revoked'
          ? 'UPDATE tokens SET revoked_at=? WHERE id=?'
          : 'UPDATE tokens SET expires_at=? WHERE id=?',
      )
        .bind(Date.now() - 1, 'token-1')
        .run();

      const denied = await create(body, options);
      expect(denied.status).toBe(401);
      expect((await data(denied)).error.code).toBe('TOKEN_INVALID');
      expect(denied.headers.get('Idempotency-Replayed')).toBeNull();
      expect(await row(original.slug)).toEqual(stored);
      expect(await env.DB.prepare('SELECT COUNT(*) AS count FROM links').first('count')).toBe(1);
      expect(await env.DB.prepare('SELECT COUNT(*) AS count FROM audit').first('count')).toBe(1);
    },
  );

  it('enforces atomic per-token and per-domain windows with Retry-After under concurrency', async () => {
    await env.DB.prepare('UPDATE tokens SET rate_per_minute = 2').run();
    const responses = await Promise.all(Array.from({ length: 6 }, () => create()));
    expect(responses.filter((response) => response.status === 201)).toHaveLength(2);
    for (const response of responses.filter((response) => response.status === 429)) {
      expect(Number(response.headers.get('Retry-After'))).toBeGreaterThan(0);
      expect(Number(response.headers.get('Retry-After'))).toBeLessThanOrEqual(60);
    }
    await env.DB.prepare('DELETE FROM rate_windows').run();
    await env.DB.prepare('UPDATE tokens SET rate_per_minute = 60').run();
    await env.DB.prepare(
      "UPDATE settings SET value = '1' WHERE key = 'domain_rate_per_minute'",
    ).run();
    const domainResponses = await Promise.all([create(), create()]);
    expect(domainResponses.map((response) => response.status).sort()).toEqual([201, 429]);
  });

  it('returns safe stable errors without target, bearer, or exception details', async () => {
    const response = await create({
      url: 'https://example.com/?private=fixture',
      domain: publicHost,
      admin: true,
    });
    const output = await response.text();
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(output).not.toContain('private=fixture');
    expect(output).not.toContain(bearer);
    expect(output).toContain('request_id');
  });
});

describe('anonymous Turnstile gate', () => {
  const body = { url: 'https://example.com', turnstile_token: 'fixture-response' };
  function verify(result: unknown, contentType = 'application/json'): ReturnType<typeof vi.fn> {
    const mock = vi.fn(
      async () =>
        new Response(JSON.stringify(result), { headers: { 'Content-Type': contentType } }),
    );
    vi.stubGlobal('fetch', mock);
    return mock;
  }

  it('requires server validation and binds hostname plus action; sends secret only to fixed official host', async () => {
    const mock = verify({ success: true, hostname: publicHost, action: 'create' });
    const response = await create(body, { mode: 'anonymous' });
    expect(response.status).toBe(201);
    expect(mock).toHaveBeenCalledOnce();
    const [url, init] = mock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://challenges.cloudflare.com/turnstile/v0/siteverify');
    expect(init.redirect).toBe('manual');
    expect(String(init.body)).toContain('response=fixture-response');
    expect((await row((await data(response)).data.slug)).source).toBe('anonymous');
  });

  it.each([
    { success: false, hostname: publicHost, action: 'create' },
    { success: true, hostname: 'attacker.example', action: 'create' },
    { success: true, hostname: publicHost, action: 'login' },
  ])('refuses failed or misbound result %j', async (result) => {
    verify(result);
    const response = await create(body, { mode: 'anonymous' });
    expect(response.status).toBe(403);
    expect(await env.DB.prepare('SELECT COUNT(*) AS count FROM links').first('count')).toBe(0);
  });

  it('fails closed on network failure, HTML challenge, missing token and foreign Origin', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('fixture network error')));
    expect((await create(body, { mode: 'anonymous' })).status).toBe(503);
    verify({ success: true }, 'text/html');
    expect((await create(body, { mode: 'anonymous' })).status).toBe(503);
    verify(null);
    expect((await create(body, { mode: 'anonymous' })).status).toBe(503);
    expect((await create({ ...body, turnstile_token: '' }, { mode: 'anonymous' })).status).toBe(
      403,
    );
    expect(
      (await create(body, { mode: 'anonymous', headers: { Origin: 'https://attacker.example' } }))
        .status,
    ).toBe(403);
  });

  it('allows Workers dev frontend only with hostname-matched challenge and still emits registered public domain', async () => {
    verify({ success: true, hostname: env.WORKERS_DEV_HOSTNAME, action: 'create' });
    const response = await create(body, { mode: 'anonymous', host: env.WORKERS_DEV_HOSTNAME });
    expect(response.status).toBe(201);
    expect((await data(response)).data.domain).toBe(publicHost);
  });

  it('rechecks domain permissions after delayed external verification before committing', async () => {
    let resolveVerify!: (response: Response) => void;
    let started!: () => void;
    const reachedVerify = new Promise<void>((resolve) => {
      started = resolve;
    });
    vi.stubGlobal(
      'fetch',
      vi.fn(() => {
        started();
        return new Promise<Response>((resolve) => {
          resolveVerify = resolve;
        });
      }),
    );
    const pending = create(body, { mode: 'anonymous' });
    await reachedVerify;
    await env.DB.prepare('UPDATE domains SET enabled = 0').run();
    resolveVerify(
      new Response(JSON.stringify({ success: true, hostname: publicHost, action: 'create' }), {
        headers: { 'Content-Type': 'application/json' },
      }),
    );
    expect((await pending).status).toBe(403);
    expect(await env.DB.prepare('SELECT COUNT(*) AS count FROM links').first('count')).toBe(0);
  });
});

describe('target bytes, lifecycle and redirects', () => {
  it('merges additional names while preserving all original repeats, encoding and fragment bytes', () => {
    const target = 'https://example.com/%2F?q=a+b&q=a%20b&%78=%2b#fragment';
    expect(mergeQuery(target, '?q=ignored&x=ignored&y=%2f&y=a+b')).toBe(
      target.replace('#fragment', '&y=%2f&y=a+b#fragment'),
    );
    expect(mergeQuery('https://example.com/?#f', '?a=%20')).toBe('https://example.com/?a=%20#f');
    expect(mergeQuery('https://example.com/path#f', '?a=1')).toBe('https://example.com/path?a=1#f');
    expect(mergeQuery('https://example.com/?x=1&#f', '?a=1')).toBe(
      'https://example.com/?x=1&a=1#f',
    );
  });

  it('protects known signature params and supports explicit administrator preserve policy', () => {
    const target = 'https://example.com/?X-Amz-Signature=a%2Bb&x=1#f';
    expect(mergeQuery(target, '')).toBe(target);
    expect(mergeQuery(target, '?x=ignored')).toBe(target);
    expect(() => mergeQuery(target, '?new=1')).toThrow('签名');
    expect(mergeQuery(target, '?new=1', 'preserve')).toBe(target);
    expect(() => mergeQuery('https://example.com', '?x=%ZZ')).toThrow('编码');
  });

  it('redirects raw signed query without additional parameters and escapes Unicode only for HTTP transport', async () => {
    const target = 'https://example.com/路径/%2F?sig=a%2Bb&q=a+b&q=a%20b#片段';
    await create({ url: target, domain: publicHost, slug: 'raw' });
    const response = await redirect('raw');
    expect(response.status).toBe(302);
    expect(response.headers.get('Location')).toBe(
      'https://example.com/%E8%B7%AF%E5%BE%84/%2F?sig=a%2Bb&q=a+b&q=a%20b#%E7%89%87%E6%AE%B5',
    );
    expect((await redirect('raw', '?new=1')).status).toBe(400);
    expect((await row('raw')).url).toBe(target);
    expect(locationHeader('https://例子.测试/路径?q=%2F')).toBe(
      'https://xn--fsqu00a.xn--0zwm56d/%E8%B7%AF%E5%BE%84?q=%2F',
    );
  });

  it('checks disabled and expired before confirmation, escapes configured text and preserves mappings', async () => {
    await create({ url: 'https://example.com/?x=1#f', domain: publicHost, slug: 'lifecycle' });
    await env.DB.prepare(
      "UPDATE links SET confirm_enabled = 1, confirm_text = '<script>alert(1)</script>' WHERE slug = 'lifecycle'",
    ).run();
    const confirmation = await redirect('lifecycle', '?x=2&y=3');
    expect(confirmation.status).toBe(200);
    const html = await confirmation.text();
    expect(html).toContain('&lt;script&gt;');
    expect(html).not.toContain('<script>');
    expect(html).toContain('href="https://example.com/?x=1&amp;y=3#f"');
    expect(confirmation.headers.get('Content-Security-Policy')).toContain("frame-ancestors 'none'");
    await env.DB.prepare("UPDATE links SET expires_at = 1 WHERE slug = 'lifecycle'").run();
    expect((await redirect('lifecycle')).status).toBe(410);
    await env.DB.prepare(
      "UPDATE links SET expires_at = NULL, enabled = 0 WHERE slug = 'lifecycle'",
    ).run();
    expect((await redirect('lifecycle')).status).toBe(410);
    expect(await row('lifecycle')).toBeDefined();
  });

  it('does not interpret management-looking incoming query parameters', async () => {
    await create({ url: 'https://example.com/#f', domain: publicHost, slug: 'query' });
    const response = await redirect('query', '?enabled=0&admin=true&confirm=1');
    expect(response.status).toBe(302);
    expect(response.headers.get('Location')).toBe(
      'https://example.com/?enabled=0&admin=true&confirm=1#f',
    );
    expect((await row('query')).enabled).toBe(1);
    expect((await row('query')).confirm_enabled).toBe(0);
  });

  it('aggregates coarse visits asynchronously with no raw IP or UA and excludes HEAD', async () => {
    await create({ url: 'https://example.com', domain: publicHost, slug: 'stats' });
    const headers = {
      Referer: 'https://referrer.example/private?token=fixture',
      'User-Agent': 'fixture iPhone Mobile',
      'CF-Connecting-IP': '203.0.113.7',
    };
    await redirect('stats', '', 'GET', headers);
    await redirect('stats', '', 'HEAD', headers);
    await Promise.all(jobs);
    const stats = await env.DB.prepare('SELECT * FROM daily_stats').all();
    expect(stats.results).toHaveLength(1);
    expect(stats.results[0]).toMatchObject({
      count: 1,
      referrer: 'referrer.example',
      device: 'mobile',
      country: 'XX',
    });
    expect(JSON.stringify(stats.results)).not.toContain('private');
    expect(JSON.stringify(stats.results)).not.toContain('203.0.113.7');
  });

  it('bounds referrer cardinality atomically and groups IP literals as direct', async () => {
    await create({ url: 'https://example.com', domain: publicHost, slug: 'bounded' });
    const day = new Date().toISOString().slice(0, 10);
    await env.DB.batch(
      Array.from({ length: 100 }, (_, index) =>
        env.DB.prepare(
          'INSERT INTO daily_stats(day, domain, slug, country, device, referrer, count) VALUES (?, ?, ?, ?, ?, ?, 1)',
        ).bind(day, publicHost, 'bounded', 'XX', 'desktop', `ref${index}.example`),
      ),
    );
    await redirect('bounded', '', 'GET', { Referer: 'https://overflow.example/private' });
    await redirect('bounded', '', 'GET', { Referer: 'https://ref0.example/again' });
    await redirect('bounded', '', 'GET', { Referer: 'https://203.0.113.8/private' });
    await Promise.all(jobs);
    expect(
      await env.DB.prepare("SELECT count FROM daily_stats WHERE referrer = 'other'").first('count'),
    ).toBe(1);
    expect(
      await env.DB.prepare("SELECT count FROM daily_stats WHERE referrer = 'ref0.example'").first(
        'count',
      ),
    ).toBe(2);
    expect(
      await env.DB.prepare("SELECT count FROM daily_stats WHERE referrer = 'direct'").first(
        'count',
      ),
    ).toBe(1);
  });

  it('can redirect preserved legacy long ASCII keys while new creation refuses them', async () => {
    const slug = 'a'.repeat(128);
    await env.DB.prepare(
      "INSERT INTO links(id, domain, slug, url, created_at, source, creator) VALUES (?, ?, ?, ?, NULL, 'migration', 'legacy-kv')",
    )
      .bind('legacy-fixture', publicHost, slug, 'https://legacy.example/')
      .run();
    expect((await redirect(slug)).status).toBe(302);
    expect((await row(slug)).created_at).toBeNull();
    expect((await create({ url: 'https://new.example', domain: publicHost, slug })).status).toBe(
      400,
    );
    const routed = await route(new Request(`https://${publicHost}/${slug}`), env, ctx);
    expect(routed.status).toBe(302);
    expect(routed.headers.get('Location')).toBe('https://legacy.example/');
  });

  it('routes a valid api-prefixed slug without falling into unknown API namespace rejection', async () => {
    expect(
      (await create({ url: 'https://example.com/?raw=%2F#f', domain: publicHost, slug: 'api123' }))
        .status,
    ).toBe(201);
    const response = await route(new Request(`https://${publicHost}/api123`), env, ctx);
    expect(response.status).toBe(302);
    expect(response.headers.get('Location')).toBe('https://example.com/?raw=%2F#f');
  });

  it.each(['api', 'Admin', 'login', '../', 'a/b', '%2F', '%252F', 'аpi', '.', 'favicon.ico', ''])(
    'rejects reserved/unsafe slug %s',
    (slug) => {
      expect(() => validateSlug(slug)).toThrow();
    },
  );

  it.each([
    'javascript:alert(1)',
    'https://user:password@example.com',
    'https://@example.com',
    'https:///example.com',
    'https://example.com/\n',
    'https://example.com/%ZZ',
    'https://example.com\\path',
  ])('rejects unsafe URL %s', (url) => {
    expect(() => validateUrl(url)).toThrow();
  });

  it('does not mistake valid supplementary Unicode for an unpaired surrogate', () => {
    expect(validateUrl('https://example.com/😀#片段')).toBe('https://example.com/😀#片段');
    expect(() => validateUrl('https://example.com/\ud800')).toThrow();
    expect(() => parseJSONStrict('{"a":1,"a":2}')).toThrow();
  });

  it('classifies incompatible legacy URLs and reserved routes for review instead of importing broken mappings', async () => {
    const moduleUrl = new URL('../scripts/migrate-legacy.mjs', import.meta.url).href;
    const { classifyLegacy } = await import(moduleUrl);
    const incompatible = [
      'https://example.com\\path',
      'https://example.com/%ZZ',
      'https:///example.com',
      'https://@example.com',
      'https://example.com/\ud800',
    ];
    for (const target of incompatible) {
      expect(() => validateUrl(target)).toThrow();
      expect((await classifyLegacy('valid-slug', target, async () => null)).kind).toBe('unknown');
    }
    for (const slug of [
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
    ]) {
      expect((await classifyLegacy(slug, 'https://example.com', async () => null)).kind).toBe(
        'unknown',
      );
    }
    const target = 'https://example.com/路径/%2F?q=a+b&q=a%20b&sig=a%2Bb#😀';
    expect(validateUrl(target)).toBe(target);
    expect(await classifyLegacy('valid-slug', target, async () => null)).toMatchObject({
      kind: 'link',
      url: target,
    });
  });
});

describe('global public namespace', () => {
  const extraHost = 'second.example.test';
  async function addDomain(host = extraHost) {
    await env.DB.prepare(
      "INSERT INTO domains(hostname,enabled,bound,created_at,binding_state) VALUES(?,1,1,?,'verified')",
    )
      .bind(host, Date.now())
      .run();
  }
  async function grant(host = extraHost) {
    await env.DB.prepare('INSERT INTO token_domains(token_id,domain) VALUES(?,?)')
      .bind('token-1', host)
      .run();
  }
  it('resolves one existing mapping under later registered prefixes and attributes clicks to the real host', async () => {
    await create({
      url: 'https://example.test/raw?a=%2f&a=+&sig=s#f',
      domain: publicHost,
      slug: 'global-old',
    });
    await addDomain();
    const response = await route(new Request(`https://${extraHost}/global-old`), env, ctx);
    expect(response.status).toBe(302);
    expect(response.headers.get('Location')).toBe('https://example.test/raw?a=%2f&a=+&sig=s#f');
    await Promise.all(jobs);
    expect(await env.DB.prepare('SELECT domain FROM daily_stats').first('domain')).toBe(extraHost);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM links').first('n')).toBe(1);
    await env.DB.prepare("UPDATE links SET enabled=0 WHERE slug='global-old'").run();
    expect((await route(new Request(`https://${extraHost}/global-old`), env, ctx)).status).toBe(
      410,
    );
    expect((await redirect('global-old')).status).toBe(410);
  });
  it('enforces global shortcode conflicts under concurrent different domain requests', async () => {
    await addDomain();
    await grant();
    const responses = await Promise.all(
      [publicHost, extraHost].map((domain) =>
        create({ url: `https://example.test/${domain}`, domain, slug: 'cross-prefix' }),
      ),
    );
    expect(responses.map((r) => r.status).sort()).toEqual([201, 409]);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM links').first('n')).toBe(1);
    for (const host of [publicHost, extraHost])
      expect((await route(new Request(`https://${host}/cross-prefix`), env, ctx)).status).toBe(302);
  });
  it('selects the authorized response prefix without leaking other public prefixes to a machine Token', async () => {
    await addDomain();
    const first = await data(await create());
    expect(first.data).not.toHaveProperty('public_urls');
    expect((await create({ url: 'https://example.test/', domain: extraHost })).status).toBe(403);
    await grant();
    const other = await data(await create({ url: 'https://example.com/a', domain: extraHost }));
    expect(other.data.domain).toBe(extraHost);
    expect(other.data.short_url).toBe(`https://${extraHost}/${other.data.slug}`);
    expect(other.data.slug).not.toBe(first.data.slug);
    expect((await redirect(other.data.slug)).status).toBe(302);
  });
  it('returns only verified enabled registered prefixes to anonymous users', async () => {
    await addDomain();
    await addDomain('disabled.example.test');
    await env.DB.prepare(
      "UPDATE domains SET enabled=0 WHERE hostname='disabled.example.test'",
    ).run();
    await env.DB.prepare(
      "INSERT INTO domains(hostname,created_at) VALUES('pending.example.test',0)",
    ).run();
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      Response.json({ success: true, hostname: extraHost, action: 'create' }),
    );
    const response = await create(
      { url: 'https://example.test/', slug: 'anonymous-global', turnstile_token: 'fixture' },
      { mode: 'anonymous', host: extraHost },
    );
    expect(response.status).toBe(201);
    const result = await data(response);
    expect(result.data.public_urls.map((r: any) => r.domain)).toEqual(
      [extraHost, publicHost].sort(),
    );
    expect(result.data.domain).toBe(extraHost);
    expect((await redirect('anonymous-global')).status).toBe(302);
  });
  it('blocks disabled domains and all additional-domain admin and machine routes without deleting a mapping', async () => {
    await addDomain();
    await create({ url: 'https://example.test/', domain: publicHost, slug: 'domain-state' });
    for (const path of ['/admin', '/api/admin/links', '/api/shorten']) {
      await expect(
        route(new Request(`https://${extraHost}${path}`), env, ctx),
      ).rejects.toMatchObject({ status: 403 });
    }
    await env.DB.prepare('UPDATE domains SET enabled=0 WHERE hostname=?').bind(extraHost).run();
    const off = await route(new Request(`https://${extraHost}/domain-state`), env, ctx);
    expect(off.status).toBe(410);
    expect(await off.text()).toContain('该短链域名已停用');
    expect((await redirect('domain-state')).status).toBe(302);
    expect(
      (await route(new Request(`https://${extraHost}/api/public/config`), env, ctx)).status,
    ).toBe(403);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM links').first('n')).toBe(1);
  });
});
