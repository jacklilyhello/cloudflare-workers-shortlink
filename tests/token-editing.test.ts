import { readFile, readdir } from 'node:fs/promises';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { handleAdmin } from '../src/admin';
import { csrfToken } from '../src/auth';
import { errorResponse, handleCreate } from '../src/core';
import worker from '../src/index';
import type { Env } from '../src/types';

const host = 'link-admin.lily.lat';
const domain = 'gfw.mom';
const email = 'admin@888888.mom';
const issuer = 'https://lilyya.cloudflareaccess.com';
const audience = 'e'.repeat(64);
const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
let mf: Miniflare;
let db: D1Database;
let env: Env;
let signingKey: CryptoKey;

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
    kid: 'synthetic-token-editing-key',
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
  await db.batch(
    [
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
afterAll(async () => {
  vi.unstubAllGlobals();
  await mf?.dispose();
});

async function call(path: string, method = 'GET', body?: unknown, appEnv = env) {
  try {
    return await handleAdmin(
      new Request(`https://${host}/api/admin/${path}`, {
        method,
        ...(body === undefined
          ? {}
          : { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
      }),
      appEnv,
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
async function createToken() {
  return output(await call('tokens', 'POST', { name: 'Editing fixture', domains: [domain] }), 201);
}
function machine(token: string, hostname: string, slug: string, key?: string) {
  return handleCreate(
    new Request(`https://${host}/api/shorten`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        ...(key ? { 'Idempotency-Key': key } : {}),
      },
      body: JSON.stringify({ url: 'https://destination.example/path', domain: hostname, slug }),
    }),
    env,
    ctx,
    'machine',
  );
}
function beforeTransaction(change: () => Promise<unknown>): Env {
  let changed = false;
  return {
    ...env,
    DB: new Proxy(db, {
      get(target, key) {
        if (key === 'batch')
          return async (statements: D1PreparedStatement[]) => {
            if (!changed) {
              changed = true;
              await change();
            }
            return db.batch(statements);
          };
        const value = Reflect.get(target, key);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    }),
  };
}

describe('business Token editing', () => {
  it('edits metadata and grants atomically while preserving the credential, identity, history and existing links', async () => {
    const token = await createToken();
    await output(await machine(token.token, domain, 'before-edit', 'retained-key'), 201);
    const credential = await db
      .prepare('SELECT digest,created_at FROM tokens WHERE id=?')
      .bind(token.id)
      .first();
    const existing = await db.prepare('SELECT * FROM links').first();
    const expires = Date.now() + 86_400_000;
    const updated = await output(
      await call(`tokens/${token.id}`, 'PATCH', {
        name: 'Renamed fixture',
        domains: ['gfw.lat', domain, domain],
        expires_at: expires,
        rate_per_minute: 75,
      }),
    );
    expect(updated).toMatchObject({
      id: token.id,
      name: 'Renamed fixture',
      domains: ['gfw.lat', domain],
      expires_at: expires,
      revoked_at: null,
      rate_per_minute: 75,
    });
    expect(updated).not.toHaveProperty('token');
    expect(updated).not.toHaveProperty('digest');
    expect(
      await db.prepare('SELECT digest,created_at FROM tokens WHERE id=?').bind(token.id).first(),
    ).toEqual(credential);
    expect(await db.prepare('SELECT * FROM links').first()).toEqual(existing);
    const replay = await machine(token.token, domain, 'before-edit', 'retained-key');
    expect(replay.status).toBe(200);
    expect(replay.headers.get('Idempotency-Replayed')).toBe('true');
    await output(await machine(token.token, 'gfw.lat', 'new-grant'), 201);
    const partial = await output(await call(`tokens/${token.id}`, 'PATCH', { expires_at: null }));
    expect(partial).toMatchObject({
      name: 'Renamed fixture',
      domains: ['gfw.lat', domain],
      expires_at: null,
      rate_per_minute: 75,
    });
    const audit = await db
      .prepare(
        "SELECT actor,detail FROM audit WHERE action='token.update' AND entity_id=? ORDER BY rowid",
      )
      .bind(token.id)
      .all<{ actor: string; detail: string }>();
    expect(audit.results).toHaveLength(2);
    expect(audit.results[0].actor).toBe(email);
    expect(JSON.parse(audit.results[0].detail)).toEqual({
      fields: ['name', 'domains', 'expires_at', 'rate_per_minute'],
    });
    expect(JSON.stringify(audit.results)).not.toContain(token.token);
  });

  it('applies grant removal to new requests and idempotent replay, and enforces the edited minute limit', async () => {
    const token = await createToken();
    await output(await machine(token.token, domain, 'old-grant', 'old-grant-key'), 201);
    await output(
      await call(`tokens/${token.id}`, 'PATCH', { domains: ['gfw.lat'], rate_per_minute: 2 }),
    );
    expect((await machine(token.token, domain, 'old-grant', 'old-grant-key')).status).toBe(403);
    expect((await machine(token.token, domain, 'denied-new')).status).toBe(403);
    await output(await machine(token.token, 'gfw.lat', 'allowed-new'), 201);
    expect((await machine(token.token, 'gfw.lat', 'over-minute-limit')).status).toBe(429);
    expect((await output(await call('tokens'))).items[0].rate_per_minute).toBe(2);
  });

  it('rejects invalid fields, domains and identifiers without changing credentials or grants', async () => {
    const token = await createToken();
    const row = await db.prepare('SELECT * FROM tokens WHERE id=?').bind(token.id).first();
    await db.prepare("UPDATE domains SET enabled=0 WHERE hostname='gfw.lat'").run();
    for (const body of [
      {},
      { name: '' },
      { name: ' ' },
      { name: 'x'.repeat(101) },
      { rate_per_minute: 0 },
      { rate_per_minute: 1001 },
      { rate_per_minute: 2.5 },
      { rate_per_minute: '12' },
      { expires_at: 1 },
      { expires_at: 'tomorrow' },
      { domains: [] },
      { domains: [42] },
      { digest: 'replacement' },
      { revoked_at: null },
      { deleted_at: null },
      { id: crypto.randomUUID() },
    ])
      expect((await call(`tokens/${token.id}`, 'PATCH', body)).status).toBe(400);
    for (const domains of [['gfw.lat'], ['unknown.example'], [host]])
      expect((await call(`tokens/${token.id}`, 'PATCH', { domains })).status).toBe(403);
    for (const id of ['-'.repeat(36), token.id.toUpperCase(), 'not-a-token'])
      expect((await call(`tokens/${id}`, 'PATCH', { name: 'Changed' })).status).toBe(400);
    expect((await call(`tokens/${crypto.randomUUID()}`, 'PATCH', { name: 'Changed' })).status).toBe(
      404,
    );
    expect(await db.prepare('SELECT * FROM tokens WHERE id=?').bind(token.id).first()).toEqual(row);
    expect((await output(await call('tokens'))).items[0].domains).toEqual([domain]);
    expect(
      await db
        .prepare("SELECT COUNT(*) AS count FROM audit WHERE action='token.update'")
        .first('count'),
    ).toBe(0);
  });

  it('allows expiry extension for an unrevoked Token while rejecting revoked and deleted Tokens', async () => {
    const token = await createToken();
    await db.prepare('UPDATE tokens SET expires_at=1 WHERE id=?').bind(token.id).run();
    await output(await call(`tokens/${token.id}`, 'PATCH', { expires_at: null }));
    await output(await machine(token.token, domain, 'extended-token'), 201);
    await output(await call(`tokens/${token.id}`, 'DELETE'));
    expect((await call(`tokens/${token.id}`, 'PATCH', { expires_at: null })).status).toBe(409);
    await output(await call(`tokens/${token.id}/delete`, 'POST', { confirm: true }));
    expect((await call(`tokens/${token.id}`, 'PATCH', { name: 'Cannot restore' })).status).toBe(
      404,
    );
  });

  it.each(['revoke', 'delete', 'domain'] as const)(
    'does not restore authority if %s changes immediately before the write transaction',
    async (change) => {
      const token = await createToken();
      const captured = beforeTransaction(async () => {
        if (change === 'revoke') await output(await call(`tokens/${token.id}`, 'DELETE'));
        else if (change === 'delete')
          await output(await call(`tokens/${token.id}/delete`, 'POST', { confirm: true }));
        else await db.prepare("UPDATE domains SET enabled=0 WHERE hostname='gfw.lat'").run();
      });
      expect(
        (
          await call(
            `tokens/${token.id}`,
            'PATCH',
            { name: 'Race fixture', domains: ['gfw.lat'] },
            captured,
          )
        ).status,
      ).toBe(409);
      expect(
        await db.prepare('SELECT label FROM tokens WHERE id=?').bind(token.id).first('label'),
      ).toBe('Editing fixture');
      const grants = await db
        .prepare('SELECT domain FROM token_domains WHERE token_id=?')
        .bind(token.id)
        .all<{ domain: string }>();
      expect(grants.results.map((g) => g.domain)).toEqual(change === 'delete' ? [] : [domain]);
      expect(
        await db
          .prepare("SELECT COUNT(*) AS count FROM audit WHERE action='token.update'")
          .first('count'),
      ).toBe(0);
    },
  );

  it('keeps edits behind administrator identity, exact Origin and JWT-bound CSRF', async () => {
    const token = await createToken();
    const jwt = await new SignJWT({ email, type: 'app' })
      .setProtectedHeader({ alg: 'RS256', kid: 'synthetic-token-editing-key' })
      .setIssuer(issuer)
      .setAudience(audience)
      .setSubject('synthetic-token-editing-admin')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(signingKey);
    const csrf = await csrfToken(jwt);
    const valid = {
      'Cf-Access-Jwt-Assertion': jwt,
      Origin: `https://${host}`,
      'X-CSRF-Token': csrf,
    };
    const send = (hostname: string, headers: Record<string, string>) =>
      worker.fetch(
        new Request(`https://${hostname}/api/admin/tokens/${token.id}`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json', ...headers },
          body: JSON.stringify({ name: 'Authorized update' }),
        }),
        env,
        ctx,
      );
    for (const [headers, status] of [
      [{ Authorization: `Bearer ${token.token}` }, 401],
      [{ 'Cf-Access-Authenticated-User-Email': email }, 401],
      [{ ...valid, 'X-CSRF-Token': 'wrong' }, 403],
      [{ ...valid, Origin: 'https://other.example' }, 403],
      [{ 'Cf-Access-Jwt-Assertion': jwt }, 403],
    ] as [Record<string, string>, number][])
      expect((await send(host, headers)).status).toBe(status);
    for (const hostname of [domain, env.WORKERS_DEV_HOSTNAME!])
      expect((await send(hostname, valid)).status).toBe(403);
    expect(
      await db.prepare('SELECT label FROM tokens WHERE id=?').bind(token.id).first('label'),
    ).toBe('Editing fixture');
    await output(await send(host, valid));
    expect(
      await db.prepare('SELECT label FROM tokens WHERE id=?').bind(token.id).first('label'),
    ).toBe('Authorized update');
  });
});
