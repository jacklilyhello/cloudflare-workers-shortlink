import { readFile, readdir } from 'node:fs/promises';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { handleAdmin } from '../src/admin';
import { csrfToken } from '../src/auth';
import { errorResponse, handleCreate, handleRedirect, hash } from '../src/core';
import worker from '../src/index';
import type { Env } from '../src/types';

const host = 'link-admin.lily.lat';
const domain = 'gfw.mom';
const email = 'admin@888888.mom';
const issuer = 'https://lilyya.cloudflareaccess.com';
const audience = 'f'.repeat(64);
const target = 'https://destination.example/path?x=a+b#part';
let mf: Miniflare;
let db: D1Database;
let env: Env;
let signingKey: CryptoKey;
let jobs: Promise<unknown>[] = [];
const ctx = {
  waitUntil(job: Promise<unknown>) {
    jobs.push(job);
  },
  passThroughOnException() {},
} as unknown as ExecutionContext;

beforeAll(async () => {
  mf = new Miniflare(
    convertV4MiniflareOptions({
      modules: true,
      script: 'export default { fetch() { return new Response("fixture"); } }',
      d1Databases: ['DB'],
    }),
  );
  db = (await mf.getD1Database('DB')) as unknown as D1Database;
  for (const file of (await readdir(new URL('../migrations/', import.meta.url)))
    .filter((file) => file.endsWith('.sql'))
    .sort()) {
    const sql = await readFile(new URL(`../migrations/${file}`, import.meta.url), 'utf8');
    await db.batch(
      sql
        .split(';')
        .filter((part) => part.trim())
        .map((part) => db.prepare(part)),
    );
  }
  env = {
    DB: db,
    APP_ENV: 'production',
    PUBLIC_HOSTNAME: domain,
    ADMIN_HOSTNAME: host,
    WORKERS_DEV_HOSTNAME: 'shortlink-new.fixture.workers.dev',
    ADMIN_EMAILS: 'lilyyaloveyou@gmail.com,admin@888888.mom,moshaoli688@gmail.com',
    CF_ACCESS_TEAM_DOMAIN: 'lilyya.cloudflareaccess.com',
    CF_ACCESS_AUD: audience,
    TURNSTILE_SITE_KEY: 'fixture-public',
    TURNSTILE_SECRET_KEY: 'fixture-private',
  };
  const pair = await generateKeyPair('RS256');
  signingKey = pair.privateKey;
  const jwk = {
    ...(await exportJWK(pair.publicKey)),
    kid: 'synthetic-token-deletion-key',
    alg: 'RS256',
    use: 'sig',
  };
  vi.stubGlobal('fetch', async (input: RequestInfo | URL) => {
    expect(input instanceof Request ? input.url : String(input)).toBe(
      `${issuer}/cdn-cgi/access/certs`,
    );
    return Response.json({ keys: [jwk] });
  });
});

beforeEach(async () => {
  jobs = [];
  await db.batch(
    [
      'DELETE FROM daily_stats',
      'DELETE FROM links',
      'DELETE FROM deleted_links',
      'DELETE FROM token_domains',
      'DELETE FROM tokens',
      'DELETE FROM audit',
      'DELETE FROM domains',
      'DELETE FROM rate_windows',
    ].map((sql) => db.prepare(sql)),
  );
  await db.batch(
    [domain, 'gfw.lat'].map((hostname) =>
      db
        .prepare(
          "INSERT INTO domains(hostname,enabled,bound,created_at,binding_state) VALUES(?,1,1,1,'verified')",
        )
        .bind(hostname),
    ),
  );
});
afterEach(async () => {
  await Promise.all(jobs);
});
afterAll(async () => {
  vi.unstubAllGlobals();
  await mf?.dispose();
});

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
      { email, csrf: 'fixture-only' },
    );
  } catch (error) {
    return errorResponse(error);
  }
}
async function output(response: Response, status = 200): Promise<any> {
  expect(response.status).toBe(status);
  return ((await response.json()) as any).data;
}
async function createToken(name = 'Deletion fixture'): Promise<{ id: string; token: string }> {
  return output(await call('tokens', 'POST', { name, domains: [domain] }), 201);
}
function removeToken(id: string, body: unknown = { confirm: true }) {
  return call(`tokens/${id}/delete`, 'POST', body);
}
function machine(token: string, slug: string, key?: string, appEnv = env): Promise<Response> {
  return handleCreate(
    new Request(`https://${host}/api/shorten`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        ...(key ? { 'Idempotency-Key': key } : {}),
      },
      body: JSON.stringify({ url: target, domain, slug }),
    }),
    appEnv,
    ctx,
    'machine',
  );
}
async function accessToken(overrides: Record<string, unknown> = {}) {
  return new SignJWT({ email, type: 'app', ...overrides })
    .setProtectedHeader({ alg: 'RS256', kid: 'synthetic-token-deletion-key' })
    .setIssuer(issuer)
    .setAudience(audience)
    .setSubject('synthetic-token-deletion-admin')
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(signingKey);
}

// Pause only at the relevant local DB boundary to model a request whose credential
// was accepted before another administrator removes its authority.
function capturedRequestEnv(
  boundary: 'lookup' | 'insert',
  transition: () => Promise<void>,
  missFirstLookup = false,
) {
  let changed = false;
  let insertPrepared = false;
  let lookups = 0;
  const mutate = async () => {
    if (!changed) {
      changed = true;
      await transition();
    }
  };
  const statement = (sql: string, prepared: D1PreparedStatement): D1PreparedStatement =>
    new Proxy(prepared, {
      get(current, key) {
        if (key === 'bind')
          return (...values: unknown[]) => statement(sql, current.bind(...values));
        if (key === 'first' && /\bFROM\s+links\b/i.test(sql) && sql.includes('idempotency_key'))
          return async (...args: unknown[]) => {
            lookups++;
            if (missFirstLookup && lookups === 1) return null;
            if (boundary === 'lookup' && lookups === 1) await mutate();
            return Reflect.apply(current.first, current, args);
          };
        const value = Reflect.get(current, key);
        return typeof value === 'function' ? value.bind(current) : value;
      },
    });
  return {
    env: {
      ...env,
      DB: new Proxy(db, {
        get(current, key) {
          if (key === 'prepare')
            return (sql: string) => {
              if (/\bINSERT\s+INTO\s+links\b/i.test(sql)) insertPrepared = true;
              return statement(sql, current.prepare(sql));
            };
          if (key === 'batch')
            return async (statements: D1PreparedStatement[]) => {
              if (boundary === 'insert' && insertPrepared) await mutate();
              return current.batch(statements);
            };
          const value = Reflect.get(current, key);
          return typeof value === 'function' ? value.bind(current) : value;
        },
      }),
    } as Env,
    changed: () => changed,
    lookups: () => lookups,
  };
}

describe('permanent business Token removal against actual local D1', () => {
  it('requires exact confirmation and a valid identifier without changing credentials or grants on rejected input', async () => {
    const token = await createToken();
    const before = await db.prepare('SELECT * FROM tokens WHERE id=?').bind(token.id).first();
    for (const body of [
      {},
      { confirm: false },
      { confirm: 'true' },
      { confirm: true, id: token.id },
    ])
      expect((await removeToken(token.id, body)).status).toBe(400);
    expect((await call(`tokens/${token.id}/delete`, 'POST')).status).toBe(415);
    expect((await removeToken('not-a-token-id')).status).toBe(400);
    expect((await removeToken('AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA')).status).toBe(400);
    expect((await removeToken(crypto.randomUUID())).status).toBe(404);
    expect(await db.prepare('SELECT * FROM tokens WHERE id=?').bind(token.id).first()).toEqual(
      before,
    );
    expect(await db.prepare('SELECT COUNT(*) AS count FROM token_domains').first('count')).toBe(1);
    expect(
      await db
        .prepare("SELECT COUNT(*) AS count FROM audit WHERE action='token.delete'")
        .first('count'),
    ).toBe(0);
  });

  it('erases credential authority while preserving live redirects, linked history and deleted-shortcode reservations', async () => {
    const token = await createToken('Historical deletion fixture');
    const digest = await hash(token.token);
    await output(await machine(token.token, 'kept-link', 'kept-request'), 201);
    await output(await machine(token.token, 'reserved-link', 'reserved-request'), 201);
    const live = await db.prepare("SELECT * FROM links WHERE slug='kept-link'").first<any>();
    const removed = await db
      .prepare("SELECT id FROM links WHERE slug='reserved-link'")
      .first<any>();
    await output(await call(`links/${removed.id}`, 'DELETE', {}));
    const reservation = await db
      .prepare("SELECT * FROM deleted_links WHERE slug='reserved-link'")
      .first();
    expect(await output(await removeToken(token.id))).toEqual({ deleted: true, id: token.id });
    const stored = await db.prepare('SELECT * FROM tokens WHERE id=?').bind(token.id).first<any>();
    expect(stored).toMatchObject({
      id: token.id,
      label: 'Historical deletion fixture',
      digest: `deleted:${token.id}`,
    });
    expect(stored.deleted_at).toBeGreaterThan(0);
    expect(stored.revoked_at).toBeGreaterThan(0);
    expect(stored.digest).not.toBe(digest);
    expect(await db.prepare('SELECT COUNT(*) AS count FROM token_domains').first('count')).toBe(0);
    expect(await db.prepare("SELECT * FROM links WHERE slug='kept-link'").first()).toEqual(live);
    expect(
      await db.prepare("SELECT * FROM deleted_links WHERE slug='reserved-link'").first(),
    ).toEqual(reservation);
    for (const publicDomain of [domain, 'gfw.lat']) {
      const response = await handleRedirect(
        new Request(`https://${publicDomain}/kept-link`),
        env,
        ctx,
        publicDomain,
        'kept-link',
      );
      expect(response.status).toBe(302);
      expect(response.headers.get('Location')).toBe(target);
    }
    for (const [slug, key] of [
      ['fresh-link', 'fresh-request'],
      ['kept-link', 'kept-request'],
      ['reserved-link', 'reserved-request'],
    ]) {
      const response = await machine(token.token, slug, key);
      expect(response.status).toBe(401);
      expect(((await response.json()) as any).error.code).toBe('TOKEN_INVALID');
    }
    for (const slug of ['kept-link', 'reserved-link'])
      expect((await call('links', 'POST', { domain, slug, url: target })).status).toBe(409);
    expect((await call(`tokens/${token.id}`, 'DELETE')).status).toBe(404);
    expect((await output(await call('tokens'))).items).toEqual([]);
    const history = await output(await call('audit'));
    expect(history.items.find((row: any) => row.action === 'token.delete')).toMatchObject({
      actor: email,
      entity_id: token.id,
    });
    expect(history.items.find((row: any) => row.actor === token.id).actor_identity).toMatchObject({
      type: 'business_token',
      name: 'Historical deletion fixture',
      token_id: token.id,
      created_by: email,
    });
    expect(
      (
        await output(
          await call(`audit?${new URLSearchParams({ q: 'Historical deletion fixture' })}`),
        )
      ).items,
    ).toHaveLength(2);
    const serialized =
      JSON.stringify(history) + JSON.stringify(await output(await call('audit/options')));
    expect(serialized).not.toContain(token.token);
    expect(serialized).not.toContain(digest);
    expect(serialized).not.toContain('"digest"');
    expect(await db.prepare('SELECT COUNT(*) AS count FROM links').first('count')).toBe(1);
  });

  it('supports revoked and expired Tokens and makes deletion retries and concurrent requests idempotent', async () => {
    const revoked = await createToken('Revoked fixture');
    await output(await call(`tokens/${revoked.id}`, 'DELETE'));
    const revokedAt = await db
      .prepare('SELECT revoked_at FROM tokens WHERE id=?')
      .bind(revoked.id)
      .first('revoked_at');
    const expired = await createToken('Expired fixture');
    await db
      .prepare('UPDATE tokens SET expires_at=1 WHERE id IN (?,?)')
      .bind(revoked.id, expired.id)
      .run();
    for (const token of [revoked, expired]) {
      await output(await removeToken(token.id));
      const deletedAt = await db
        .prepare('SELECT deleted_at FROM tokens WHERE id=?')
        .bind(token.id)
        .first('deleted_at');
      await output(await removeToken(token.id));
      expect(
        await db
          .prepare('SELECT deleted_at FROM tokens WHERE id=?')
          .bind(token.id)
          .first('deleted_at'),
      ).toBe(deletedAt);
    }
    expect(
      await db
        .prepare('SELECT revoked_at FROM tokens WHERE id=?')
        .bind(revoked.id)
        .first('revoked_at'),
    ).toBe(revokedAt);
    const active = await createToken('Concurrent fixture');
    const responses = await Promise.all(Array.from({ length: 4 }, () => removeToken(active.id)));
    for (const response of responses)
      expect(await output(response)).toEqual({ deleted: true, id: active.id });
    for (const token of [revoked, expired, active])
      expect(
        await db
          .prepare(
            "SELECT COUNT(*) AS count FROM audit WHERE action='token.delete' AND entity_id=?",
          )
          .bind(token.id)
          .first('count'),
      ).toBe(1);
    expect(await db.prepare('SELECT COUNT(*) AS count FROM token_domains').first('count')).toBe(0);
  });

  it('paginates visible Tokens after excluding deleted rows rather than consuming page slots', async () => {
    const visible: string[] = [];
    const statements = [];
    for (let index = 0; index < 63; index++) {
      const id = crypto.randomUUID();
      visible.push(id);
      statements.push(
        db
          .prepare('INSERT INTO tokens(id,label,digest,created_at) VALUES(?,?,?,1)')
          .bind(id, `Visible ${index}`, `fixture-visible-${index}`),
      );
      for (let removed = 0; removed < 2; removed++) {
        const deleted = crypto.randomUUID();
        statements.push(
          db
            .prepare(
              'INSERT INTO tokens(id,label,digest,created_at,revoked_at,deleted_at) VALUES(?,?,?,1,1,1)',
            )
            .bind(deleted, 'Deleted fixture', `deleted:${deleted}`),
        );
      }
    }
    await db.batch(statements);
    const first = await output(await call('tokens'));
    expect(first.items).toHaveLength(50);
    const second = await output(await call(`tokens?cursor=${first.next_cursor}`));
    expect(second.items).toHaveLength(13);
    expect(second.next_cursor).toBeNull();
    expect([...first.items, ...second.items].map((row: any) => row.id)).toEqual(visible.reverse());
  });

  it('keeps permanent deletion behind Access identity, exact role, Origin and JWT-bound CSRF', async () => {
    const token = await createToken();
    const jwt = await accessToken();
    const csrf = await csrfToken(jwt);
    const outsider = await accessToken({ email: 'outsider@example.test' });
    const send = (hostname: string, headers: Record<string, string>) =>
      worker.fetch(
        new Request(`https://${hostname}/api/admin/tokens/${token.id}/delete`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...headers },
          body: JSON.stringify({ confirm: true }),
        }),
        env,
        ctx,
      );
    const rejected: [Record<string, string>, number][] = [
      [{ Authorization: `Bearer ${token.token}` }, 401],
      [{ 'Cf-Access-Authenticated-User-Email': email }, 401],
      [{ 'Cf-Access-Jwt-Assertion': jwt }, 403],
      [
        { 'Cf-Access-Jwt-Assertion': jwt, Origin: 'https://other.example', 'X-CSRF-Token': csrf },
        403,
      ],
      [{ 'Cf-Access-Jwt-Assertion': jwt, Origin: `https://${host}`, 'X-CSRF-Token': 'wrong' }, 403],
      [
        {
          'Cf-Access-Jwt-Assertion': jwt,
          Origin: `https://${host}`,
          'X-CSRF-Token': csrf,
          'Sec-Fetch-Site': 'cross-site',
        },
        403,
      ],
      [
        {
          'Cf-Access-Jwt-Assertion': outsider,
          Origin: `https://${host}`,
          'X-CSRF-Token': await csrfToken(outsider),
        },
        403,
      ],
    ];
    for (const [headers, status] of rejected)
      expect((await send(host, headers)).status).toBe(status);
    const valid = {
      'Cf-Access-Jwt-Assertion': jwt,
      Origin: `https://${host}`,
      'X-CSRF-Token': csrf,
    };
    for (const hostname of [domain, env.WORKERS_DEV_HOSTNAME!])
      expect((await send(hostname, valid)).status).toBe(403);
    expect(
      await db
        .prepare('SELECT deleted_at FROM tokens WHERE id=?')
        .bind(token.id)
        .first('deleted_at'),
    ).toBeNull();
    expect(
      await db
        .prepare("SELECT COUNT(*) AS count FROM audit WHERE action='token.delete'")
        .first('count'),
    ).toBe(0);
    expect(await output(await send(host, valid))).toEqual({ deleted: true, id: token.id });
  });

  it('blocks a captured new request when Token deletion occurs before its atomic insert', async () => {
    const token = await createToken();
    const captured = capturedRequestEnv('insert', async () => {
      await output(await removeToken(token.id));
    });
    const response = await machine(
      token.token,
      'captured-new',
      'captured-new-request',
      captured.env,
    );
    expect(captured.changed()).toBe(true);
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(response.status).toBeLessThan(500);
    expect(await db.prepare('SELECT COUNT(*) AS count FROM links').first('count')).toBe(0);
    expect(
      await db
        .prepare("SELECT COUNT(*) AS count FROM audit WHERE action='link.create'")
        .first('count'),
    ).toBe(0);
  });

  for (const boundary of ['lookup', 'insert'] as const)
    it.each(['deleted', 'revoked', 'grant_removed'] as const)(
      `rechecks current authority at the ${boundary === 'lookup' ? 'initial' : 'post-insert'} idempotent lookup: %s`,
      async (change) => {
        const token = await createToken();
        await output(await machine(token.token, 'captured-replay', 'captured-key'), 201);
        const before = await db.prepare('SELECT * FROM links').first();
        const captured = capturedRequestEnv(
          boundary,
          async () => {
            if (change === 'deleted') await output(await removeToken(token.id));
            else if (change === 'revoked') await output(await call(`tokens/${token.id}`, 'DELETE'));
            else
              await db.prepare('DELETE FROM token_domains WHERE token_id=?').bind(token.id).run();
          },
          boundary === 'insert',
        );
        const response = await machine(
          token.token,
          'captured-replay',
          'captured-key',
          captured.env,
        );
        expect(captured.changed()).toBe(true);
        if (boundary === 'insert') expect(captured.lookups()).toBeGreaterThanOrEqual(2);
        expect(response.status).toBeGreaterThanOrEqual(400);
        expect(response.status).toBeLessThan(500);
        expect(response.headers.get('Idempotency-Replayed')).toBeNull();
        expect(await db.prepare('SELECT * FROM links').first()).toEqual(before);
        expect(await db.prepare('SELECT COUNT(*) AS count FROM links').first('count')).toBe(1);
        expect(
          await db
            .prepare("SELECT COUNT(*) AS count FROM audit WHERE action='link.create'")
            .first('count'),
        ).toBe(1);
      },
    );
});
