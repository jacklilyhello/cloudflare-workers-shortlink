import { readFile, readdir } from 'node:fs/promises';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { handleAdmin } from '../src/admin';
import { errorResponse, handleRedirect } from '../src/core';
import type { DomainRow, Env } from '../src/types';

const account = '9431815bdb8beb2272f6668e06b7d3be';
const ownerId = '00000000-0000-4000-8000-000000000051';
const databaseId = '00000000-0000-4000-8000-000000000052';
const primary = 'test.gfw.mom';
const hostname = 'registered-public.example';
const adminHost = 'link-admin.lily.lat';
const identity = { email: 'admin@example.test', csrf: 'fixture-only' };
const oldVerified = Date.parse('2026-10-01T02:03:04Z');
const prefix = `https://api.cloudflare.com/client/v4/accounts/${account}`;
let mf: Miniflare;
let env: Env;
let jobs: Promise<unknown>[];
let ctx: ExecutionContext;
let calls: { url: string; init?: RequestInit }[];
let responder: (url: string) => Response | Promise<Response>;

function json(value: unknown, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
function customBinding(changes: Record<string, unknown> = {}) {
  return {
    id: 'fixture-custom-domain',
    hostname,
    service: 'shortlink-new',
    environment: 'production',
    zone_id: 'fixture-zone',
    cert_id: 'fixture-certificate',
    enabled: true,
    ...changes,
  };
}
function validResponder(url: string): Response {
  if (url === `${prefix}/workers/domains?hostname=${hostname}`)
    return json({ success: true, result: [customBinding()], result_info: { total_pages: 1 } });
  if (url === `${prefix}/workers/scripts/shortlink-new/settings`)
    return json({
      success: true,
      result: {
        bindings: [
          { name: 'RESOURCE_OWNER_ID', type: 'plain_text', text: ownerId },
          { name: 'DB', type: 'd1', id: databaseId },
          { name: 'BACKUPS', type: 'r2_bucket', bucket_name: 'shortlink-new-backups' },
        ],
      },
    });
  const proof = new URL(url);
  expect(proof.hostname).toBe(hostname);
  expect(proof.pathname).toBe('/.well-known/shortlink-binding');
  return json({
    worker: 'shortlink-new',
    owner_id: ownerId,
    hostname,
    nonce: proof.searchParams.get('nonce'),
  });
}

beforeAll(async () => {
  mf = new Miniflare(
    convertV4MiniflareOptions({
      modules: true,
      script: 'export default { fetch() { return new Response("test"); } }',
      d1Databases: ['DB'],
    }),
  );
  env = {
    DB: (await mf.getD1Database('DB')) as unknown as D1Database,
    APP_ENV: 'test',
    PUBLIC_HOSTNAME: primary,
    ADMIN_HOSTNAME: adminHost,
    ADMIN_EMAILS: identity.email,
    TURNSTILE_SITE_KEY: 'fixture-public',
    TURNSTILE_SECRET_KEY: 'fixture-private',
    CLOUDFLARE_ACCOUNT_ID: account,
    WORKER_NAME: 'shortlink-new',
    RESOURCE_OWNER_ID: ownerId,
    D1_DATABASE_ID: databaseId,
    DOMAIN_BINDING_READ_TOKEN: 'fixture-independent-reader',
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
  await env.DB.prepare(
    'INSERT INTO delivery_ownership(singleton,project,owner_id,account_id,worker,created_at) VALUES(1,?,?,?,?,?)',
  )
    .bind('cloudflare-workers-shortlink', ownerId, account, 'shortlink-new', '2026-10-01T00:00:00Z')
    .run();
});

beforeEach(async () => {
  await env.DB.batch(
    [
      'DELETE FROM daily_stats',
      'DELETE FROM links',
      'DELETE FROM audit',
      'DELETE FROM domains',
    ].map((sql) => env.DB.prepare(sql)),
  );
  await env.DB.prepare(
    "INSERT INTO domains(hostname,created_at,bound,enabled,binding_state,last_verified_at,last_checked_at) VALUES(?,1,1,1,'verified',?,?)",
  )
    .bind(primary, oldVerified, oldVerified)
    .run();
  await env.DB.prepare(
    "INSERT INTO domains(hostname,created_at,bound,enabled,binding_state,last_verified_at,last_checked_at) VALUES(?,1,0,0,'unbound',NULL,NULL)",
  )
    .bind(hostname)
    .run();
  env.DOMAIN_BINDING_READ_TOKEN = 'fixture-independent-reader';
  jobs = [];
  ctx = {
    waitUntil(job: Promise<unknown>) {
      jobs.push(job);
    },
    passThroughOnException() {},
  } as unknown as ExecutionContext;
  calls = [];
  responder = validResponder;
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = input instanceof Request ? input.url : String(input);
      calls.push({ url, init });
      return responder(url);
    }),
  );
});

afterEach(async () => {
  await Promise.all(jobs);
  vi.unstubAllGlobals();
});
afterAll(async () => mf?.dispose());

async function call(path: string, method = 'GET', body?: unknown): Promise<Response> {
  const request = new Request(`https://${adminHost}/api/admin/domains${path}`, {
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
async function stored(host = hostname) {
  return (await env.DB.prepare('SELECT * FROM domains WHERE hostname=?')
    .bind(host)
    .first<DomainRow>())!;
}
async function previouslyVerified(enabled = false) {
  await env.DB.prepare(
    "UPDATE domains SET enabled=?,bound=1,binding_state='verified',last_verified_at=?,last_checked_at=?,binding_error=NULL WHERE hostname=?",
  )
    .bind(Number(enabled), oldVerified, oldVerified, hostname)
    .run();
}

describe('admin domain flow with real D1 migrations and SQL persistence', () => {
  it('registers an unbound disabled domain without any CF resource operation', async () => {
    const newHost = 'another-public.example';
    const response = await call('', 'POST', { hostname: newHost });
    expect(response.status).toBe(201);
    const data = ((await response.json()) as any).data;
    expect(data).toMatchObject({
      hostname: newHost,
      enabled: false,
      bound: false,
      binding_state: 'unbound',
      last_verified_at: null,
      last_checked_at: null,
    });
    expect(await stored(newHost)).toMatchObject({
      hostname: newHost,
      enabled: 0,
      bound: 0,
      binding_state: 'unbound',
    });
    expect(calls).toEqual([]);
  });

  it('persists successful verification and returns the actual row without enabling the domain', async () => {
    const start = Date.now();
    const response = await call(`/${hostname}/verify`, 'POST', {});
    expect(response.status).toBe(200);
    const row = await stored();
    expect(row).toMatchObject({
      bound: 1,
      enabled: 0,
      binding_state: 'verified',
      binding_error: null,
    });
    expect(row.last_checked_at).toBeGreaterThanOrEqual(start);
    expect(row.last_verified_at).toBe(row.last_checked_at);
    expect(((await response.json()) as any).data).toEqual({
      ...row,
      id: hostname,
      enabled: false,
      bound: true,
    });
    expect(calls).toHaveLength(3);
    expect(
      await env.DB.prepare(
        "SELECT COUNT(*) AS count FROM audit WHERE action='domain.verify'",
      ).first('count'),
    ).toBe(1);
  });

  it('records missing credentials as failed, advances checked time and retains the last success', async () => {
    await previouslyVerified();
    env.DOMAIN_BINDING_READ_TOKEN = undefined;
    const response = await call(`/${hostname}/verify`, 'POST', {});
    expect(response.status).toBe(503);
    expect(((await response.json()) as any).error.code).toBe('BINDING_READ_NOT_CONFIGURED');
    expect(await stored()).toMatchObject({
      enabled: 0,
      bound: 0,
      binding_state: 'failed',
      binding_error: 'BINDING_READ_NOT_CONFIGURED',
      last_verified_at: oldVerified,
    });
    expect((await stored()).last_checked_at).toBeGreaterThan(oldVerified);
    expect(calls).toEqual([]);
    expect(
      await env.DB.prepare(
        "SELECT COUNT(*) AS count FROM audit WHERE action='domain.verify_failed'",
      ).first('count'),
    ).toBe(1);
  });

  it('persists a wrong Worker binding as failed without replacing its last successful time', async () => {
    await previouslyVerified();
    responder = () =>
      json({ success: true, result: [customBinding({ service: 'another-worker' })] });
    const response = await call(`/${hostname}/verify`, 'POST', {});
    expect(response.status).toBe(409);
    expect(((await response.json()) as any).error.code).toBe('BINDING_WRONG_WORKER');
    expect(await stored()).toMatchObject({
      bound: 0,
      binding_state: 'failed',
      binding_error: 'BINDING_WRONG_WORKER',
      last_verified_at: oldVerified,
    });
  });

  it('returns and stores pending readiness without marking it completed or enabled', async () => {
    await previouslyVerified();
    responder = () => json({ success: true, result: [customBinding({ enabled: false })] });
    const response = await call(`/${hostname}/verify`, 'POST', {});
    expect(response.status).toBe(200);
    const row = await stored();
    expect(row).toMatchObject({
      bound: 0,
      enabled: 0,
      binding_state: 'pending',
      binding_error: 'BINDING_SERVICE_PENDING',
      last_verified_at: oldVerified,
    });
    expect(((await response.json()) as any).data).toEqual({
      ...row,
      id: hostname,
      enabled: false,
      bound: false,
    });
    expect((await call(`/${hostname}`, 'PATCH', { enabled: true })).status).toBe(409);
    expect(calls).toHaveLength(1);
  });

  it('disables business service while preserving the CF binding and shared link mapping', async () => {
    await previouslyVerified(true);
    await env.DB.prepare(
      "INSERT INTO links(id,domain,slug,url,created_at,source,creator) VALUES(?,?,'shared-code','https://example.com/target',1,'admin',?)",
    )
      .bind(crypto.randomUUID(), hostname, identity.email)
      .run();
    const response = await call(`/${hostname}`, 'PATCH', { enabled: false });
    expect(response.status).toBe(200);
    expect(((await response.json()) as any).data).toMatchObject({
      enabled: false,
      bound: true,
      binding_state: 'verified',
      last_verified_at: oldVerified,
    });
    expect(await stored()).toMatchObject({ enabled: 0, bound: 1, binding_state: 'verified' });
    expect(await env.DB.prepare('SELECT COUNT(*) AS count FROM links').first('count')).toBe(1);
    expect(calls).toEqual([]);
    const disabled = await handleRedirect(
      new Request(`https://${hostname}/shared-code`),
      env,
      ctx,
      hostname,
      'shared-code',
    );
    expect(disabled.status).toBe(410);
    expect(await disabled.text()).toContain('该短链域名已停用');
    const otherPrefix = await handleRedirect(
      new Request(`https://${primary}/shared-code`),
      env,
      ctx,
      primary,
      'shared-code',
    );
    expect(otherPrefix.status).toBe(302);
    expect(otherPrefix.headers.get('Location')).toBe('https://example.com/target');
  });

  it('re-enables only after a fresh live check and responds with the post-update row', async () => {
    await previouslyVerified();
    const response = await call(`/${hostname}`, 'PATCH', { enabled: true });
    expect(response.status).toBe(200);
    const row = await stored();
    expect(row).toMatchObject({ enabled: 1, bound: 1, binding_state: 'verified' });
    expect(row.last_verified_at).toBeGreaterThan(oldVerified);
    expect(((await response.json()) as any).data).toEqual({
      ...row,
      id: hostname,
      enabled: true,
      bound: true,
    });
    expect(calls).toHaveLength(3);
  });

  it('refuses to re-enable if the fresh CF read says the domain is unbound', async () => {
    await previouslyVerified();
    responder = () => json({ success: true, result: [], result_info: { total_pages: 1 } });
    const response = await call(`/${hostname}`, 'PATCH', { enabled: true });
    expect(response.status).toBe(409);
    expect(((await response.json()) as any).error.code).toBe('DOMAIN_NOT_BOUND');
    expect(await stored()).toMatchObject({
      enabled: 0,
      bound: 0,
      binding_state: 'unbound',
      last_verified_at: oldVerified,
      binding_error: null,
    });
    expect(calls).toHaveLength(1);
    expect(
      await env.DB.prepare(
        "SELECT COUNT(*) AS count FROM audit WHERE action='domain.update'",
      ).first('count'),
    ).toBe(0);
  });

  it.each([
    [403, 'BINDING_READ_PERMISSION'],
    [404, 'BINDING_READ_FAILED'],
    [503, 'BINDING_READ_FAILED'],
  ])('keeps read failure HTTP %i distinct from an unbound result', async (status, code) => {
    await previouslyVerified();
    responder = () => json({ success: false }, Number(status));
    const response = await call(`/${hostname}`, 'PATCH', { enabled: true });
    expect(response.status).toBe(503);
    expect(((await response.json()) as any).error.code).toBe(code);
    expect(await stored()).toMatchObject({
      enabled: 0,
      bound: 0,
      binding_state: 'failed',
      binding_error: code,
      last_verified_at: oldVerified,
    });
    expect(calls).toHaveLength(1);
  });

  it.each([adminHost, 'gfw.mom', 'shortlink-new.example.workers.dev'])(
    'rejects protected hostname %s at registration',
    async (host) => {
      const response = await call('', 'POST', { hostname: host });
      expect(response.status).toBe(400);
      expect(((await response.json()) as any).error.code).toBe('INVALID_DOMAIN');
      expect(
        await env.DB.prepare('SELECT hostname FROM domains WHERE hostname=?').bind(host).first(),
      ).toBeNull();
      expect(calls).toEqual([]);
    },
  );

  it('rejects unknown domains and extra verify fields before any CF request', async () => {
    expect((await call('/missing.example/verify', 'POST', {})).status).toBe(404);
    expect((await call(`/${hostname}/verify`, 'POST', { enabled: true })).status).toBe(400);
    expect(calls).toEqual([]);
    expect(await stored()).toMatchObject({
      bound: 0,
      enabled: 0,
      binding_state: 'unbound',
      last_checked_at: null,
    });
  });

  it('does not allow an older successful verification to overwrite a newer failed state or enable service', async () => {
    await previouslyVerified();
    responder = async (url) => {
      if (url.startsWith(`https://${hostname}/`)) {
        await env.DB.prepare(
          "UPDATE domains SET bound=0,binding_state='failed',binding_error='NEWER_READ_FAILURE',last_checked_at=? WHERE hostname=?",
        )
          .bind(Date.now() + 1000, hostname)
          .run();
      }
      return validResponder(url);
    };
    const response = await call(`/${hostname}`, 'PATCH', { enabled: true });
    expect(response.status).toBe(409);
    expect(((await response.json()) as any).error.code).toBe('DOMAIN_NOT_BOUND');
    expect(await stored()).toMatchObject({
      enabled: 0,
      bound: 0,
      binding_state: 'failed',
      binding_error: 'NEWER_READ_FAILURE',
      last_verified_at: oldVerified,
    });
  });
});
