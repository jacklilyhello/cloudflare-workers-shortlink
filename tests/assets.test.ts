import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { build } from 'vite';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import worker from '../src/index';
import type { Env } from '../src/types';

const publicHost = 'test.gfw.mom';
const workersHost = 'shortlink-new.example.workers.dev';
const adminHost = 'link-admin.lily.lat';
const issuer = 'https://lilyya.cloudflareaccess.com';
const audience = 'b'.repeat(64);
const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
let directory: string;
let mf: Miniflare;
let env: Env;
let assertion: string;
let html: string;
let assetConfig: { html_handling: 'none'; run_worker_first: true; binding: string };

beforeAll(async () => {
  directory = await mkdtemp(join(tmpdir(), 'shortlink-assets-'));
  await build({
    configFile: fileURLToPath(new URL('../vite.config.ts', import.meta.url)),
    build: { outDir: directory, emptyOutDir: true },
    logLevel: 'silent',
  });
  html = await readFile(join(directory, 'index.html'), 'utf8');
  const { deploymentConfiguration } = await import(
    new URL('../scripts/deploy.mjs', import.meta.url).href
  );
  const config = deploymentConfiguration(
    {
      d1: { id: '00000000-0000-4000-8000-000000000001' },
      security: { apps: { admin: { aud: audience } } },
    },
    workersHost,
  );
  assetConfig = config.assets;
  mf = new Miniflare(
    convertV4MiniflareOptions({
      modules: true,
      script: 'export default { fetch(request, env) { return env.ASSETS.fetch(request); } }',
      compatibilityDate: config.compatibility_date,
      assets: {
        directory,
        binding: assetConfig.binding,
        run_worker_first: assetConfig.run_worker_first,
        assetConfig: { html_handling: assetConfig.html_handling },
      },
    }),
  );
  const bindings = await mf.getBindings<{ ASSETS: Fetcher }>();
  env = {
    ASSETS: bindings.ASSETS,
    PUBLIC_HOSTNAME: publicHost,
    ADMIN_HOSTNAME: adminHost,
    WORKERS_DEV_HOSTNAME: workersHost,
    APP_ENV: 'test',
    CF_ACCESS_TEAM_DOMAIN: 'lilyya.cloudflareaccess.com',
    CF_ACCESS_AUD: audience,
    ADMIN_EMAILS: 'lilyyaloveyou@gmail.com,admin@888888.mom',
    TURNSTILE_SITE_KEY: 'fixture-public',
    DB: {
      prepare: () => ({
        bind() {
          return this;
        },
        first: async () => null,
      }),
    },
  } as unknown as Env;
  const { privateKey, publicKey } = await generateKeyPair('RS256');
  const jwk = await exportJWK(publicKey);
  const key = { ...jwk, kid: 'local-assets-fixture', alg: 'RS256', use: 'sig' };
  assertion = await new SignJWT({ email: 'admin@888888.mom', type: 'app' })
    .setProtectedHeader({ alg: 'RS256', kid: key.kid })
    .setIssuer(issuer)
    .setAudience(audience)
    .setSubject('local-assets-admin')
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(privateKey);
  vi.stubGlobal('fetch', async (input: RequestInfo | URL) => {
    const url = input instanceof Request ? input.url : String(input);
    expect(url).toBe(`${issuer}/cdn-cgi/access/certs`);
    return new Response(JSON.stringify({ keys: [key] }), {
      headers: { 'Content-Type': 'application/json' },
    });
  });
});

afterAll(async () => {
  vi.unstubAllGlobals();
  await mf?.dispose();
  if (directory) await rm(directory, { recursive: true, force: true });
});

function request(host: string, path: string, admin = false) {
  return worker.fetch(
    new Request(`https://${host}${path}`, {
      redirect: 'manual',
      headers: admin ? { 'Cf-Access-Jwt-Assertion': assertion } : {},
    }),
    env,
    ctx,
  );
}

describe('built UI against the real Miniflare asset binding', () => {
  it('reproduces the default HTML redirect that would loop behind the current Worker', async () => {
    const defaults = new Miniflare(
      convertV4MiniflareOptions({
        modules: true,
        script: 'export default { fetch(request, env) { return env.ASSETS.fetch(request); } }',
        assets: { directory, binding: 'ASSETS', run_worker_first: true },
      }),
    );
    try {
      const bindings = await defaults.getBindings<{ ASSETS: Fetcher }>();
      const response = await worker.fetch(
        new Request(`https://${publicHost}/`, { redirect: 'manual' }),
        { ...env, ASSETS: bindings.ASSETS },
        ctx,
      );
      expect(response.status).toBe(307);
      expect(response.headers.get('Location')).toBe('/');
    } finally {
      await defaults.dispose();
    }
  });

  it('uses explicit HTML files while preserving Worker-first authentication', () => {
    expect(assetConfig.html_handling).toBe('none');
    expect(assetConfig.run_worker_first).toBe(true);
  });

  it.each([publicHost, workersHost])('serves %s root as HTML without redirects', async (host) => {
    const response = await request(host, '/');
    expect(response.status).toBe(200);
    expect(response.headers.get('Content-Type')).toContain('text/html');
    expect(response.headers.get('Location')).toBeNull();
    expect(response.headers.get('Content-Security-Policy')).toContain("script-src 'self'");
    expect(await response.text()).toBe(html);
  });

  it('retains the admin root redirect and serves the protected admin page', async () => {
    const root = await request(adminHost, '/', true);
    expect(root.status).toBe(302);
    expect(root.headers.get('Location')).toBe('/admin');
    for (const path of ['/admin', '/admin/']) {
      const response = await request(adminHost, path, true);
      expect(response.status).toBe(200);
      expect(response.headers.get('Location')).toBeNull();
      expect(response.headers.get('Content-Type')).toContain('text/html');
      expect(await response.text()).toBe(html);
    }
    const denied = await request(adminHost, '/admin');
    expect(denied.status).toBe(401);
  });

  it('serves the actual Vite JS and CSS files and keeps admin assets protected', async () => {
    const paths = [...html.matchAll(/(?:src|href)="(\/assets\/[^\"]+\.(?:js|css))"/g)].map(
      (match) => match[1],
    );
    expect(paths.some((path) => path.endsWith('.js'))).toBe(true);
    expect(paths.some((path) => path.endsWith('.css'))).toBe(true);
    for (const path of paths) {
      const content = await readFile(join(directory, path.slice(1)), 'utf8');
      for (const host of [publicHost, workersHost, adminHost]) {
        const response = await request(host, path, host === adminHost);
        expect(response.status).toBe(200);
        expect(response.headers.get('Location')).toBeNull();
        expect(response.headers.get('Content-Type')).toMatch(
          path.endsWith('.js') ? /javascript/ : /text\/css/,
        );
        expect(await response.text()).toBe(content);
      }
      expect((await request(adminHost, path)).status).toBe(401);
    }
  });
});
