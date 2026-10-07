import { beforeAll, describe, expect, it } from 'vitest';
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type JWTVerifyGetKey } from 'jose';
import { authorizeAdmin, csrfToken } from '../src/auth';
import worker from '../src/index';
import type { Env } from '../src/types';

const env = {
  APP_ENV: 'test',
  PUBLIC_HOSTNAME: 'test.gfw.mom',
  ADMIN_HOSTNAME: 'link-admin.lily.lat',
  WORKERS_DEV_HOSTNAME: 'shortlink-new.lilyya.workers.dev',
  CF_ACCESS_TEAM_DOMAIN: 'lilyya.cloudflareaccess.com',
  CF_ACCESS_AUD: 'a'.repeat(64),
  ADMIN_EMAILS: 'lilyyaloveyou@gmail.com,admin@888888.mom,moshaoli688@gmail.com',
  TURNSTILE_SITE_KEY: 'public-example',
  TURNSTILE_SECRET_KEY: '',
  ASSETS: {
    fetch: async () =>
      new Response('<html>UI</html>', { headers: { 'Content-Type': 'text/html' } }),
  },
  DB: {
    prepare: (sql: string) => ({
      hostname: '',
      bind(hostname: string) {
        this.hostname = hostname;
        return this;
      },
      async first() {
        return sql.includes('FROM domains') && this.hostname === 'test.gfw.mom'
          ? { hostname: 'test.gfw.mom', enabled: 1, bound: 1, binding_state: 'verified' }
          : null;
      },
      all: async () => ({ results: [] }),
    }),
  },
} as unknown as Env;
let key: CryptoKey, jwks: JWTVerifyGetKey;
beforeAll(async () => {
  const pair = await generateKeyPair('RS256', { extractable: true });
  key = pair.privateKey;
  const publicKey = await exportJWK(pair.publicKey);
  jwks = createLocalJWKSet({ keys: [{ ...publicKey, kid: 'test', alg: 'RS256', use: 'sig' }] });
});
async function token(overrides: Record<string, unknown> = {}) {
  return new SignJWT({ email: 'lilyyaloveyou@gmail.com', type: 'app', ...overrides })
    .setProtectedHeader({ alg: 'RS256', kid: 'test' })
    .setIssuer(String(overrides.iss ?? 'https://lilyya.cloudflareaccess.com'))
    .setAudience(String(overrides.aud ?? env.CF_ACCESS_AUD))
    .setSubject('test-subject')
    .setIssuedAt(Math.floor(Date.now() / 1000))
    .setExpirationTime((overrides.exp as number) ?? '1h')
    .sign(key);
}
function request(jwt: string, method = 'GET', headers: Record<string, string> = {}) {
  return new Request('https://link-admin.lily.lat/api/admin/session', {
    method,
    headers: { 'Cf-Access-Jwt-Assertion': jwt, ...headers },
  });
}
describe('administrator identity is a signed, scoped Access identity', () => {
  it('accepts all three administrators with the same signed identity and write checks', async () => {
    for (const email of ['lilyyaloveyou@gmail.com', 'admin@888888.mom', 'moshaoli688@gmail.com']) {
      const jwt = await token({ email });
      const csrf = await csrfToken(jwt);
      expect(await authorizeAdmin(request(jwt), env, jwks)).toEqual({
        email,
        csrf,
      });
      await expect(
        authorizeAdmin(
          request(jwt, 'POST', { Origin: 'https://link-admin.lily.lat', 'X-CSRF-Token': csrf }),
          env,
          jwks,
        ),
      ).resolves.toEqual({ email, csrf });
      await expect(authorizeAdmin(request(jwt, 'POST'), env, jwks)).rejects.toMatchObject({
        code: 'CSRF_REJECTED',
      });
    }
  });
  it.each(['intruder@example.com', 'moshaoli688@gmail.com.evil', 'MOSHAOLI688@gmail.com'])(
    'rejects a signed identity outside the exact administrator list: %s',
    async (email) => {
      await expect(
        authorizeAdmin(request(await token({ email })), env, jwks),
      ).rejects.toMatchObject({ code: 'ADMIN_FORBIDDEN', status: 403 });
    },
  );
  it.each([
    { email: 'intruder@example.com' },
    { iss: 'https://other.cloudflareaccess.com' },
    { aud: 'b'.repeat(64) },
    { exp: Math.floor(Date.now() / 1000) - 60 },
    { type: 'service_auth' },
  ])('rejects invalid identity %j', async (override) => {
    await expect(authorizeAdmin(request(await token(override)), env, jwks)).rejects.toThrow();
  });
  it('rejects forged signatures, unsigned JWTs, and trusted-looking email headers', async () => {
    const valid = await token();
    const changed = valid.slice(0, -16) + 'AAAAAAAAAAAAAAAA';
    for (const jwt of [
      changed,
      'eyJhbGciOiJub25lIn0.eyJlbWFpbCI6ImxpbHl5YWxvdmV5b3VAZ21haWwuY29tIn0.',
    ])
      await expect(authorizeAdmin(request(jwt), env, jwks)).rejects.toThrow();
    const forged = new Request('https://link-admin.lily.lat/api/admin/session', {
      headers: {
        'Cf-Access-Authenticated-User-Email': 'lilyyaloveyou@gmail.com',
        Authorization: 'Bearer sl_' + '1'.repeat(64),
      },
    });
    await expect(authorizeAdmin(forged, env, jwks)).rejects.toMatchObject({
      code: 'ADMIN_REQUIRED',
    });
  });
  it('enforces same Origin and JWT-bound CSRF for writes', async () => {
    const jwt = await token(),
      csrf = await csrfToken(jwt);
    await expect(
      authorizeAdmin(
        request(jwt, 'POST', { Origin: 'https://link-admin.lily.lat', 'X-CSRF-Token': csrf }),
        env,
        jwks,
      ),
    ).resolves.toMatchObject({ email: 'lilyyaloveyou@gmail.com' });
    for (const headers of [
      {},
      { Origin: 'https://evil.example', 'X-CSRF-Token': csrf },
      { Origin: 'https://link-admin.lily.lat', 'X-CSRF-Token': 'wrong' },
      {
        Origin: 'https://link-admin.lily.lat',
        'X-CSRF-Token': csrf,
        'Sec-Fetch-Site': 'cross-site',
      },
    ])
      await expect(
        authorizeAdmin(request(jwt, 'POST', headers as Record<string, string>), env, jwks),
      ).rejects.toMatchObject({ code: 'CSRF_REJECTED' });
  });
  it('rejects unsafe admin configuration and wrong hosts before verification', async () => {
    const jwt = await token();
    for (const emails of [
      'lilyyaloveyou@gmail.com,admin@888888.mom',
      'admin@888888.mom,moshaoli688@gmail.com',
      'lilyyaloveyou@gmail.com,moshaoli688@gmail.com',
      env.ADMIN_EMAILS + ',extra@example.com',
      env.ADMIN_EMAILS + ',moshaoli688@gmail.com',
    ])
      await expect(
        authorizeAdmin(request(jwt), { ...env, ADMIN_EMAILS: emails }, jwks),
      ).rejects.toMatchObject({ code: 'ADMIN_NOT_CONFIGURED' });
    await expect(
      authorizeAdmin(
        new Request('https://test.gfw.mom/api/admin/session', {
          headers: { 'Cf-Access-Jwt-Assertion': jwt },
        }),
        env,
        jwks,
      ),
    ).rejects.toMatchObject({ code: 'HOST_FORBIDDEN' });
  });
});
describe('public entry points cannot bypass machine or administration entry points', () => {
  const ctx = {
    waitUntil: () => {},
    passThroughOnException: () => {},
  } as unknown as ExecutionContext;
  it.each(['test.gfw.mom', 'shortlink-new.lilyya.workers.dev'])(
    'rejects protected APIs on %s',
    async (host) => {
      for (const path of ['/api/shorten', '/api/admin/session', '/api/admin/tokens']) {
        const response = await worker.fetch(
          new Request(`https://${host}${path}`, {
            method: path === '/api/shorten' ? 'POST' : 'GET',
            headers: { Authorization: 'Bearer sl_' + '2'.repeat(64) },
          }),
          env,
          ctx,
        );
        expect(response.status).toBe(403);
        expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
          'HOST_FORBIDDEN',
        );
      }
    },
  );
  it('machine errors stay JSON without an Access login page', async () => {
    const response = await worker.fetch(
      new Request('https://link-admin.lily.lat/api/shorten', { method: 'POST' }),
      env,
      ctx,
    );
    expect(response.status).toBe(401);
    expect(response.headers.get('Content-Type')).toContain('application/json');
    expect(response.headers.get('Location')).toBeNull();
    expect(await response.json()).toMatchObject({ ok: false, error: { code: 'TOKEN_REQUIRED' } });
  });
  it.each([
    '/api/shorten/',
    '/api/shorten/child',
    '/api/shortening',
    '/api/%73horten',
    '/api/shorten%2fchild',
  ])('similar paths remain protected: %s', async (path) => {
    const response = await worker.fetch(
      new Request(`https://link-admin.lily.lat${path}`, {
        method: 'POST',
        headers: { Authorization: 'Bearer sl_' + '2'.repeat(64) },
      }),
      env,
      ctx,
    );
    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ error: { code: 'ADMIN_REQUIRED' } });
  });
  it('serves anonymous config and assets with strict security headers', async () => {
    const response = await worker.fetch(new Request('https://test.gfw.mom/'), env, ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get('Content-Security-Policy')).toContain("frame-ancestors 'none'");
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    const config = await worker.fetch(
      new Request('https://test.gfw.mom/api/public/config'),
      env,
      ctx,
    );
    expect(await config.json()).toMatchObject({
      data: { domain: 'test.gfw.mom', site_key: 'public-example' },
    });
  });
  it('rejects unrecognized hosts and forwarded host spoofing', async () => {
    const response = await worker.fetch(
      new Request('https://unrelated.example/api/shorten', {
        method: 'POST',
        headers: { 'X-Forwarded-Host': 'link-admin.lily.lat' },
      }),
      env,
      ctx,
    );
    expect(response.status).toBe(403);
  });
});
