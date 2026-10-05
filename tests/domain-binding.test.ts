import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { verifyDomainBinding } from '../src/domain-binding';
import type { Env } from '../src/types';

const account = '9431815bdb8beb2272f6668e06b7d3be';
const worker = 'shortlink-new';
const hostname = 'new-public.example';
const ownerId = '00000000-0000-4000-8000-000000000041';
const databaseId = '00000000-0000-4000-8000-000000000042';
const token = 'fixture-independent-domain-read-only';
const prefix = `https://api.cloudflare.com/client/v4/accounts/${account}`;
const domainURL = `${prefix}/workers/domains?hostname=${hostname}`;
const workerURL = `${prefix}/workers/scripts/${worker}/settings`;

type Binding = Record<string, unknown>;
type Owned = { owner_id: string; account_id: string; worker: string } | null;
let env: Env;
let ownership: Owned;
let prepare: ReturnType<typeof vi.fn>;
let calls: { url: string; init?: RequestInit }[];
let responder: (url: string, init?: RequestInit) => Response | Promise<Response>;

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
function domain(overrides: Binding = {}): Binding {
  return {
    id: 'fixture-custom-domain-id',
    hostname,
    service: worker,
    environment: 'production',
    zone_id: 'fixture-zone-id',
    cert_id: 'fixture-certificate-id',
    enabled: true,
    ...overrides,
  };
}
function bindings(): Binding[] {
  return [
    { name: 'RESOURCE_OWNER_ID', type: 'plain_text', text: ownerId },
    { name: 'DB', type: 'd1', id: databaseId },
    { name: 'BACKUPS', type: 'r2_bucket', bucket_name: 'shortlink-new-backups' },
  ];
}
function proof(url: string): Response {
  const parsed = new URL(url);
  expect(parsed.protocol).toBe('https:');
  expect(parsed.hostname).toBe(hostname);
  expect(parsed.pathname).toBe('/.well-known/shortlink-binding');
  expect(parsed.searchParams.get('nonce')).toMatch(/^[a-f0-9-]{36}$/);
  return json({ worker, owner_id: ownerId, hostname, nonce: parsed.searchParams.get('nonce') });
}
function validResponder(url: string): Response {
  if (url === domainURL) return json({ success: true, result: [domain()] });
  if (url === workerURL) return json({ success: true, result: { bindings: bindings() } });
  return proof(url);
}

beforeEach(() => {
  ownership = { owner_id: ownerId, account_id: account, worker };
  prepare = vi.fn((sql: string) => {
    expect(sql).toBe('SELECT owner_id,account_id,worker FROM delivery_ownership WHERE singleton=1');
    return { first: async () => ownership };
  });
  env = {
    APP_ENV: 'test',
    PUBLIC_HOSTNAME: 'test.gfw.mom',
    ADMIN_HOSTNAME: 'link-admin.lily.lat',
    WORKERS_DEV_HOSTNAME: 'shortlink-new.example.workers.dev',
    ADMIN_EMAILS: 'admin@example.test',
    TURNSTILE_SITE_KEY: 'fixture-public',
    TURNSTILE_SECRET_KEY: 'fixture-private',
    DB: { prepare } as unknown as D1Database,
    CLOUDFLARE_ACCOUNT_ID: account,
    WORKER_NAME: worker,
    RESOURCE_OWNER_ID: ownerId,
    D1_DATABASE_ID: databaseId,
    DOMAIN_BINDING_READ_TOKEN: token,
  };
  calls = [];
  responder = validResponder;
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = input instanceof Request ? input.url : String(input);
      calls.push({ url, init });
      return responder(url, init);
    }),
  );
});

afterEach(() => vi.unstubAllGlobals());

describe('read-only domain binding verification', () => {
  it('verifies a new public host against the fixed CF account, Worker, owner, DB and R2', async () => {
    expect(await verifyDomainBinding(env, hostname)).toEqual({
      binding_state: 'verified',
      bound: true,
      binding_error: null,
    });
    expect(calls.map((call) => call.url).slice(0, 2)).toEqual([domainURL, workerURL]);
    expect(calls).toHaveLength(3);
    for (const call of calls) {
      expect(call.init?.method).toBe('GET');
      expect(call.init?.body).toBeUndefined();
      expect(call.init?.redirect).toBe('manual');
      expect(call.init?.signal).toBeInstanceOf(AbortSignal);
    }
    for (const call of calls.slice(0, 2)) {
      expect(new Headers(call.init?.headers).get('Authorization')).toBe(`Bearer ${token}`);
    }
    const publicHeaders = new Headers(calls[2].init?.headers);
    expect(publicHeaders.get('Authorization')).toBeNull();
    expect(publicHeaders.get('Cookie')).toBeNull();
    expect(JSON.stringify(calls[2])).not.toContain(token);
  });

  it.each([
    ['DOMAIN_BINDING_READ_TOKEN', undefined],
    ['CLOUDFLARE_ACCOUNT_ID', 'wrong-account'],
    ['WORKER_NAME', 'short-link'],
    ['RESOURCE_OWNER_ID', ''],
    ['D1_DATABASE_ID', undefined],
  ])('rejects missing or wrong %s before any network request', async (key, value) => {
    Object.assign(env, { [key]: value });
    await expect(verifyDomainBinding(env, hostname)).rejects.toMatchObject({
      code: 'BINDING_READ_NOT_CONFIGURED',
      status: 503,
    });
    expect(calls).toEqual([]);
    expect(prepare).not.toHaveBeenCalled();
  });

  it.each(['link-admin.lily.lat', 'gfw.mom', 'shortlink-new.example.workers.dev'])(
    'rejects protected host %s',
    async (host) => {
      await expect(verifyDomainBinding(env, host)).rejects.toMatchObject({
        code: 'INVALID_DOMAIN',
      });
      expect(calls).toEqual([]);
    },
  );

  it.each([
    'https://new-public.example/',
    'new-public.example/path',
    'new-public.example:443',
    'user@new-public.example',
    'New-Public.example',
    '127.0.0.1',
    'new-public.example\n',
  ])('rejects malformed hostname %s before ownership or network access', async (host) => {
    await expect(verifyDomainBinding(env, host)).rejects.toMatchObject({ code: 'INVALID_DOMAIN' });
    expect(prepare).not.toHaveBeenCalled();
    expect(calls).toEqual([]);
  });

  it('does not fall back to a deployment or generic token when the independent reader is missing', async () => {
    env.DOMAIN_BINDING_READ_TOKEN = undefined;
    Object.assign(env, { CLOUDFLARE_API_TOKEN: 'fixture-other-purpose-secret' });
    await expect(verifyDomainBinding(env, hostname)).rejects.toMatchObject({
      code: 'BINDING_READ_NOT_CONFIGURED',
    });
    expect(calls).toEqual([]);
  });

  it.each([
    null,
    { owner_id: 'someone-else', account_id: account, worker },
    { owner_id: ownerId, account_id: 'wrong-account', worker },
    { owner_id: ownerId, account_id: account, worker: 'another-worker' },
  ])('rejects D1 ownership mismatch before contacting CF', async (value) => {
    ownership = value;
    await expect(verifyDomainBinding(env, hostname)).rejects.toMatchObject({
      code: 'BINDING_OWNERSHIP_FAILED',
    });
    expect(calls).toEqual([]);
  });

  it('returns unbound only after a successful complete read with no exact binding', async () => {
    responder = () =>
      json({
        success: true,
        result: [domain({ hostname: 'other.example' })],
        result_info: { total_pages: 1 },
      });
    expect(await verifyDomainBinding(env, hostname)).toEqual({
      binding_state: 'unbound',
      bound: false,
      binding_error: null,
    });
    expect(calls).toHaveLength(1);
  });

  it.each([
    [401, 'BINDING_READ_PERMISSION'],
    [403, 'BINDING_READ_PERMISSION'],
    [404, 'BINDING_READ_FAILED'],
    [429, 'BINDING_READ_FAILED'],
    [503, 'BINDING_READ_FAILED'],
  ])('does not turn CF HTTP %i into an unbound state', async (status, code) => {
    responder = () => json({ success: false }, Number(status));
    await expect(verifyDomainBinding(env, hostname)).rejects.toMatchObject({ code, status: 503 });
    expect(calls).toHaveLength(1);
  });

  it('rejects a CF network failure without a probe or subsequent request', async () => {
    responder = () => {
      throw new TypeError('fixture connection unavailable');
    };
    await expect(verifyDomainBinding(env, hostname)).rejects.toMatchObject({
      code: 'BINDING_NETWORK_FAILED',
    });
    expect(calls).toHaveLength(1);
  });

  it('rejects a CF cross-origin redirect before a second request could receive credentials', async () => {
    responder = () =>
      new Response(null, { status: 302, headers: { Location: 'https://third-party.example/' } });
    await expect(verifyDomainBinding(env, hostname)).rejects.toMatchObject({
      code: 'BINDING_NETWORK_FAILED',
    });
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe(domainURL);
  });

  it.each([
    () => new Response('<html>challenge</html>', { headers: { 'Content-Type': 'text/html' } }),
    () => new Response('{broken', { headers: { 'Content-Type': 'application/json' } }),
    () => new Response(new Uint8Array([0xff]), { headers: { 'Content-Type': 'application/json' } }),
    () => json({ success: false, result: [] }),
    () => json({ success: true, result: {} }),
    () => json({ success: true, result: [], result_info: { total_pages: 2 } }),
  ])('rejects invalid, non-JSON, incomplete or unsuccessful CF reads', async (response) => {
    responder = response;
    await expect(verifyDomainBinding(env, hostname)).rejects.toMatchObject({
      code: 'BINDING_READ_FAILED',
    });
    expect(calls).toHaveLength(1);
  });

  it('bounds the response body to 2 MiB and cancels an oversized stream', async () => {
    const cancel = vi.fn();
    responder = () =>
      new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(new Uint8Array(2 * 1024 * 1024 + 1));
          },
          cancel,
        }),
        { headers: { 'Content-Type': 'application/json' } },
      );
    await expect(verifyDomainBinding(env, hostname)).rejects.toMatchObject({
      code: 'BINDING_READ_FAILED',
    });
    expect(cancel).toHaveBeenCalledOnce();
    expect(calls).toHaveLength(1);
  });

  it.each([domainURL, workerURL])(
    'classifies interrupted CF response streams as network failures at %s',
    async (failedURL) => {
      let pulls = 0;
      responder = (url) =>
        url !== failedURL
          ? validResponder(url)
          : new Response(
              new ReadableStream({
                pull(controller) {
                  if (pulls++ === 0)
                    controller.enqueue(new TextEncoder().encode('{"success":true,"result":'));
                  else controller.error(new Error('fixture private upstream details'));
                },
              }),
              { headers: { 'Content-Type': 'application/json' } },
            );
      const error = await verifyDomainBinding(env, hostname).catch((failure) => failure);
      expect(error).toMatchObject({ code: 'BINDING_NETWORK_FAILED', status: 503 });
      expect(error.message).not.toContain('fixture private upstream details');
      expect(pulls).toBeGreaterThan(1);
      expect(calls).toHaveLength(failedURL === domainURL ? 1 : 2);
    },
  );

  it('keeps a public host pending if its unauthenticated identity-proof stream breaks', async () => {
    responder = (url) =>
      url === domainURL || url === workerURL
        ? validResponder(url)
        : new Response(
            new ReadableStream({
              start(controller) {
                controller.error(new TypeError('fixture proof connection interrupted'));
              },
            }),
            { headers: { 'Content-Type': 'application/json' } },
          );
    expect(await verifyDomainBinding(env, hostname)).toEqual({
      binding_state: 'pending',
      bound: false,
      binding_error: 'BINDING_SERVICE_PENDING',
    });
    expect(calls).toHaveLength(3);
    expect(new Headers(calls[2].init?.headers).get('Authorization')).toBeNull();
  });

  it.each([
    { service: 'short-link' },
    { environment: 'preview' },
    { zone_id: undefined },
    { id: undefined },
  ])('rejects a wrong Worker, environment or incomplete domain identity', async (changes) => {
    responder = () => json({ success: true, result: [domain(changes)] });
    await expect(verifyDomainBinding(env, hostname)).rejects.toMatchObject({
      code: 'BINDING_WRONG_WORKER',
    });
    expect(calls).toHaveLength(1);
  });

  it('rejects duplicate exact custom-domain records', async () => {
    responder = () => json({ success: true, result: [domain(), domain({ id: 'second-record' })] });
    await expect(verifyDomainBinding(env, hostname)).rejects.toMatchObject({
      code: 'BINDING_WRONG_WORKER',
    });
    expect(calls).toHaveLength(1);
  });

  it.each([{ enabled: false }, { cert_id: null }, { cert_id: '' }])(
    'keeps disabled or uncertified CF bindings pending',
    async (changes) => {
      responder = () => json({ success: true, result: [domain(changes)] });
      expect(await verifyDomainBinding(env, hostname)).toEqual({
        binding_state: 'pending',
        bound: false,
        binding_error: 'BINDING_SERVICE_PENDING',
      });
      expect(calls).toHaveLength(1);
    },
  );

  it.each([
    { name: 'RESOURCE_OWNER_ID', type: 'plain_text', text: 'wrong-owner' },
    { name: 'DB', type: 'd1', id: 'another-database' },
    { name: 'DB', type: 'd1', id: databaseId, database_id: 'another-database' },
    { name: 'BACKUPS', type: 'r2_bucket', bucket_name: 'unrelated-backups' },
  ])('rejects Worker owner, database or R2 mismatches before the public probe', async (changed) => {
    responder = (url) =>
      url === domainURL
        ? validResponder(url)
        : json({
            success: true,
            result: {
              bindings: bindings().map((item) => (item.name === changed.name ? changed : item)),
            },
          });
    await expect(verifyDomainBinding(env, hostname)).rejects.toMatchObject({
      code: 'BINDING_OWNERSHIP_FAILED',
    });
    expect(calls).toHaveLength(2);
  });

  it.each(['RESOURCE_OWNER_ID', 'DB', 'BACKUPS'])(
    'rejects duplicate %s Worker bindings',
    async (name) => {
      responder = (url) =>
        url === domainURL
          ? validResponder(url)
          : json({
              success: true,
              result: { bindings: [...bindings(), bindings().find((item) => item.name === name)] },
            });
      await expect(verifyDomainBinding(env, hostname)).rejects.toMatchObject({
        code: 'BINDING_OWNERSHIP_FAILED',
      });
      expect(calls).toHaveLength(2);
    },
  );

  it.each(['RESOURCE_OWNER_ID', 'DB', 'BACKUPS'])(
    'rejects a missing %s Worker binding',
    async (name) => {
      responder = (url) =>
        url === domainURL
          ? validResponder(url)
          : json({
              success: true,
              result: { bindings: bindings().filter((item) => item.name !== name) },
            });
      await expect(verifyDomainBinding(env, hostname)).rejects.toMatchObject({
        code: 'BINDING_OWNERSHIP_FAILED',
      });
      expect(calls).toHaveLength(2);
    },
  );

  it.each([
    (url: string) => json({ worker, owner_id: ownerId, hostname, nonce: 'wrong-nonce' }),
    (url: string) =>
      json({
        worker: 'another-worker',
        owner_id: ownerId,
        hostname,
        nonce: new URL(url).searchParams.get('nonce'),
      }),
    (url: string) =>
      json({
        worker,
        owner_id: 'another-owner',
        hostname,
        nonce: new URL(url).searchParams.get('nonce'),
      }),
    (url: string) =>
      json({
        worker,
        owner_id: ownerId,
        hostname: 'another.example',
        nonce: new URL(url).searchParams.get('nonce'),
      }),
    () =>
      new Response(null, { status: 302, headers: { Location: 'https://third-party.example/' } }),
    () => new Response('<html>not ready</html>', { headers: { 'Content-Type': 'text/html' } }),
    () => {
      throw new TypeError('fixture TLS unavailable');
    },
  ])(
    'keeps a CF-bound host pending until its unauthenticated HTTPS identity proof matches',
    async (response) => {
      responder = (url) =>
        url === domainURL || url === workerURL ? validResponder(url) : response(url);
      expect(await verifyDomainBinding(env, hostname)).toEqual({
        binding_state: 'pending',
        bound: false,
        binding_error: 'BINDING_SERVICE_PENDING',
      });
      expect(calls).toHaveLength(3);
      expect(new Headers(calls[2].init?.headers).get('Authorization')).toBeNull();
    },
  );
});
