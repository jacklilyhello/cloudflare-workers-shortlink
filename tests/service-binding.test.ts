import { createHash } from 'node:crypto';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { afterAll, beforeAll, beforeEach, expect, it } from 'vitest';
import { ADMIN_EMAILS } from '../src/auth';
import { bundleWorker, migrateTestDatabase } from './worker-runtime';

const publicHost = 'gfw.mom';
const adminHost = 'link-admin.lily.lat';
const endpoint = `https://${adminHost}/api/shorten`;
const tokenId = 'synthetic-binding-token';
const bearer = 'synthetic-service-binding-fixture-' + 'x'.repeat(16);
const target = 'https://example.test/path?q=a+b&q=a%20b#fragment';
const body = { url: target, domain: publicHost, slug: 'binding-link' };
let mf: Miniflare;
let caller: Awaited<ReturnType<Miniflare['getWorker']>>;
let db: D1Database;

function request({
  token = bearer,
  raw = JSON.stringify(body),
  key,
  method = 'POST',
}: { token?: string | null; raw?: string; key?: string; method?: string } = {}) {
  return {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token === null ? {} : { Authorization: `Bearer ${token}` }),
      ...(key === undefined ? {} : { 'Idempotency-Key': key }),
    },
    ...(method === 'GET' ? {} : { body: raw }),
  };
}

async function expectError(
  response: { status: number; json(): Promise<unknown> },
  status: number,
  code: string,
) {
  expect(response.status).toBe(status);
  expect(await response.json()).toMatchObject({ ok: false, error: { code } });
}

beforeAll(async () => {
  const script = await bundleWorker();
  const compatibilityDate = '2026-07-02';
  const outboundService = () => {
    throw new Error('Unexpected network request in Service Binding fixture');
  };
  mf = new Miniflare(
    convertV4MiniflareOptions({
      workers: [
        {
          name: 'shortlink',
          modules: true,
          compatibilityDate,
          script,
          bindings: {
            APP_ENV: 'production',
            PUBLIC_HOSTNAME: publicHost,
            ADMIN_HOSTNAME: adminHost,
            CF_ACCESS_TEAM_DOMAIN: 'lilyya.cloudflareaccess.com',
            CF_ACCESS_AUD: 'c'.repeat(64),
            ADMIN_EMAILS: ADMIN_EMAILS.join(','),
          },
          d1Databases: ['DB'],
          outboundService,
        },
        {
          name: 'caller',
          modules: true,
          compatibilityDate,
          script: `export default { async fetch(request, env) {
            const probe = request.headers.get('X-Fixture-Probe');
            if (probe === 'invalid') return env.SHORTLINK.createShortlink({ url: request.url });
            if (probe === 'fetch') {
              try {
                return await env.SHORTLINK.fetch(request);
              } catch {
                return new Response('Named entrypoint has no fetch handler', { status: 501 });
              }
            }
            return env.SHORTLINK.createShortlink(request);
          } };`,
          serviceBindings: { SHORTLINK: { name: 'shortlink', entrypoint: 'ShortlinkService' } },
          outboundService,
        },
      ],
    }),
  );
  caller = await mf.getWorker('caller');
  db = (await mf.getD1Database('DB', 'shortlink')) as unknown as D1Database;
  await migrateTestDatabase(db);
});

beforeEach(async () => {
  await db.batch([
    ...[
      'audit',
      'links',
      'deleted_links',
      'token_domains',
      'tokens',
      'domains',
      'rate_windows',
    ].map((table) => db.prepare(`DELETE FROM ${table}`)),
    db.prepare("UPDATE settings SET value='120' WHERE key='domain_rate_per_minute'"),
    ...[publicHost, 'gfw.lat'].map((host) =>
      db
        .prepare(
          "INSERT INTO domains(hostname,enabled,bound,created_at,binding_state) VALUES(?,1,1,?,'verified')",
        )
        .bind(host, Date.now()),
    ),
    db
      .prepare('INSERT INTO tokens(id,label,digest,created_at) VALUES(?,?,?,?)')
      .bind(tokenId, 'fixture', createHash('sha256').update(bearer).digest('hex'), Date.now()),
    db.prepare('INSERT INTO token_domains VALUES(?,?)').bind(tokenId, publicHost),
  ]);
});

afterAll(async () => {
  await mf?.dispose();
});

it('creates through the real named entrypoint and persists the machine Token attribution', async () => {
  const created = await caller.fetch(endpoint, request());
  expect(created.status).toBe(201);
  expect(await created.json()).toMatchObject({
    ok: true,
    data: { slug: body.slug, domain: publicHost, short_url: `https://${publicHost}/${body.slug}` },
  });
  const link = await db.prepare('SELECT id,url,source,creator,token_id FROM links').first();
  expect(link).toMatchObject({
    url: target,
    source: 'machine',
    creator: tokenId,
    token_id: tokenId,
  });
  expect(await db.prepare('SELECT actor,action,entity_id,detail FROM audit').first()).toEqual({
    actor: tokenId,
    action: 'link.create',
    entity_id: link?.id,
    detail: '{}',
  });
  const redirected = await mf.dispatchFetch(`https://${publicHost}/${body.slug}`, {
    redirect: 'manual',
  });
  expect(redirected.status).toBe(302);
  expect(redirected.headers.get('Location')).toBe(target);
});

it('requires a valid business Token and rechecks its current state even for replay', async () => {
  await expectError(await caller.fetch(endpoint, request({ token: null })), 401, 'TOKEN_REQUIRED');
  for (const token of ['bad-token', 'z'.repeat(43)])
    await expectError(await caller.fetch(endpoint, request({ token })), 401, 'TOKEN_INVALID');
  expect(await db.prepare('SELECT COUNT(*) AS count FROM links').first('count')).toBe(0);

  const key = 'binding-token-state';
  expect((await caller.fetch(endpoint, request({ key }))).status).toBe(201);
  for (const column of ['revoked_at', 'deleted_at', 'expires_at']) {
    await db
      .prepare(`UPDATE tokens SET ${column}=?`)
      .bind(Date.now() - 1)
      .run();
    await expectError(await caller.fetch(endpoint, request({ key })), 401, 'TOKEN_INVALID');
    await db.prepare(`UPDATE tokens SET ${column}=NULL`).run();
  }
  expect(await db.prepare('SELECT COUNT(*) AS count FROM links').first('count')).toBe(1);
});

it('enforces Token domain assignment and rejects replays for disabled or unverified domains', async () => {
  await expectError(
    await caller.fetch(endpoint, request({ raw: JSON.stringify({ ...body, domain: 'gfw.lat' }) })),
    403,
    'DOMAIN_FORBIDDEN',
  );
  const key = 'binding-domain-state';
  expect((await caller.fetch(endpoint, request({ key }))).status).toBe(201);
  for (const [update, restore] of [
    ['enabled=0', 'enabled=1'],
    ["binding_state='pending'", "binding_state='verified'"],
  ]) {
    await db.prepare(`UPDATE domains SET ${update} WHERE hostname=?`).bind(publicHost).run();
    await expectError(await caller.fetch(endpoint, request({ key })), 403, 'DOMAIN_FORBIDDEN');
    await db.prepare(`UPDATE domains SET ${restore} WHERE hostname=?`).bind(publicHost).run();
  }
  await db.prepare('DELETE FROM token_domains').run();
  await expectError(await caller.fetch(endpoint, request({ key })), 403, 'DOMAIN_FORBIDDEN');
});

it('applies the machine method, field, URL, slug, and request-size rules inside the binding', async () => {
  await expectError(
    await caller.fetch(endpoint, request({ method: 'GET' })),
    405,
    'METHOD_NOT_ALLOWED',
  );
  for (const [raw, status, code] of [
    [JSON.stringify({ ...body, enabled: false }), 400, 'UNKNOWN_FIELD'],
    [JSON.stringify({ ...body, url: 'javascript:alert(1)' }), 400, 'INVALID_URL'],
    [JSON.stringify({ ...body, slug: 'bad.slug' }), 400, 'INVALID_SLUG'],
    [JSON.stringify({ ...body, url: target + 'x'.repeat(16_384) }), 413, 'BODY_TOO_LARGE'],
  ] as const)
    await expectError(await caller.fetch(endpoint, request({ raw })), status, code);
  expect(await db.prepare('SELECT COUNT(*) AS count FROM links').first('count')).toBe(0);
});

it('keeps public HTTP and the named binding confined to their own entrypoint rules', async () => {
  const publicEndpoint = `https://${publicHost}/api/shorten`;
  await expectError(await caller.fetch(publicEndpoint, request()), 403, 'HOST_FORBIDDEN');
  await expectError(
    await caller.fetch(endpoint.replace('https:', 'http:'), request()),
    403,
    'HTTPS_REQUIRED',
  );
  await expectError(await caller.fetch(endpoint + '/', request()), 404, 'NOT_FOUND');
  const adminEndpoint = `https://${adminHost}/api/admin/links`;
  await expectError(await caller.fetch(adminEndpoint, request()), 404, 'NOT_FOUND');
  await expectError(await mf.dispatchFetch(adminEndpoint, request()), 401, 'ADMIN_REQUIRED');
  const spoofed = request();
  await expectError(
    await caller.fetch(endpoint, {
      ...spoofed,
      headers: { ...spoofed.headers, 'X-Fixture-Probe': 'invalid' },
    }),
    400,
    'INVALID_FIELD',
  );
  const namedFetch = await caller.fetch(endpoint, {
    ...spoofed,
    headers: { ...spoofed.headers, 'X-Fixture-Probe': 'fetch' },
  });
  expect(namedFetch.status).toBe(501);
  await expectError(
    await mf.dispatchFetch(publicEndpoint, {
      ...spoofed,
      headers: { ...spoofed.headers, 'X-Shortlink-Service-Binding': 'true' },
    }),
    403,
    'HOST_FORBIDDEN',
  );
  expect(await db.prepare('SELECT COUNT(*) AS count FROM links').first('count')).toBe(0);
});

it.each([`token:${tokenId}`, `domain:${publicHost}`])(
  'uses the same rate windows as the public machine API for %s',
  async (key) => {
    if (key.startsWith('token:')) await db.prepare('UPDATE tokens SET rate_per_minute=1').run();
    else await db.prepare("UPDATE settings SET value='1' WHERE key='domain_rate_per_minute'").run();
    const window = Math.floor(Date.now() / 60_000);
    // Seed the next window too so crossing a minute boundary cannot affect the assertions.
    await db
      .prepare('INSERT INTO rate_windows(key,window,count) VALUES(?,?,1),(?,?,1)')
      .bind(key, window, key, window + 1)
      .run();
    const responses = await Promise.all([
      caller.fetch(endpoint, request()),
      mf.dispatchFetch(endpoint, request()),
    ]);
    for (const response of responses) {
      await expectError(response, 429, 'RATE_LIMITED');
      expect(Number(response.headers.get('Retry-After'))).toBeGreaterThanOrEqual(1);
      expect(Number(response.headers.get('Retry-After'))).toBeLessThanOrEqual(60);
    }
    expect(
      await db
        .prepare('SELECT SUM(count) AS total FROM rate_windows WHERE key=?')
        .bind(key)
        .first('total'),
    ).toBe(4);
    expect(await db.prepare('SELECT COUNT(*) AS count FROM links').first('count')).toBe(0);
  },
);

it('shares concurrent idempotency, conflict checks, and one audit row across both machine transports', async () => {
  const key = 'binding-concurrent';
  const responses = await Promise.all(
    Array.from({ length: 8 }, (_, index) =>
      index % 2 === 0
        ? caller.fetch(endpoint, request({ key }))
        : mf.dispatchFetch(endpoint, request({ key })),
    ),
  );
  expect(responses.filter(({ status }) => status === 201)).toHaveLength(1);
  expect(responses.filter(({ status }) => status === 200)).toHaveLength(7);
  for (const response of responses) {
    expect(response.headers.get('Idempotency-Replayed')).toBe(
      response.status === 200 ? 'true' : null,
    );
    expect(await response.json()).toMatchObject({ ok: true, data: { slug: body.slug } });
  }
  const replay = await caller.fetch(endpoint, request({ key }));
  expect(replay.status).toBe(200);
  expect(replay.headers.get('Idempotency-Replayed')).toBe('true');
  await expectError(
    await caller.fetch(
      endpoint,
      request({ key, raw: JSON.stringify({ ...body, url: target + 'different' }) }),
    ),
    409,
    'IDEMPOTENCY_CONFLICT',
  );
  expect(await db.prepare('SELECT COUNT(*) AS count FROM links').first('count')).toBe(1);
  expect(await db.prepare('SELECT COUNT(*) AS count FROM audit').first('count')).toBe(1);
});

it('does not resurrect a permanently deleted link on an RPC retry', async () => {
  const key = 'binding-deleted';
  expect((await caller.fetch(endpoint, request({ key }))).status).toBe(201);
  await db.batch([
    db
      .prepare(
        `INSERT INTO deleted_links(slug,link_id,deleted_at,token_id,domain,idempotency_key,request_hash)
        SELECT slug,id,?,token_id,domain,idempotency_key,request_hash FROM links WHERE slug=?`,
      )
      .bind(Date.now(), body.slug),
    db.prepare('DELETE FROM links WHERE slug=?').bind(body.slug),
  ]);
  await expectError(await caller.fetch(endpoint, request({ key })), 410, 'LINK_DELETED');
  expect(await db.prepare('SELECT COUNT(*) AS count FROM links').first('count')).toBe(0);
  expect(await db.prepare('SELECT COUNT(*) AS count FROM audit').first('count')).toBe(1);
});
