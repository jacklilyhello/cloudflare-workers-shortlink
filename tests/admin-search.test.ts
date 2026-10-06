import { readFile, readdir } from 'node:fs/promises';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import worker from '../src/index';
import type { Env } from '../src/types';

const domain = 'test.gfw.mom';
const otherDomain = 'registered-public.example';
const host = 'link-admin.lily.lat';
const issuer = 'https://lilyya.cloudflareaccess.com';
const audience = 'e'.repeat(64);
const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
let mf: Miniflare;
let db: D1Database;
let env: Env;
let assertion: string;
let preparedQueries = 0;

// Managed D1 limits LIKE/GLOB patterns to 50 UTF-8 bytes. Local SQLite can allow
// longer patterns, so enforce that documented platform boundary independently
// of the search implementation while executing every accepted query in real D1.
function platformStatement(
  sql: string,
  statement: D1PreparedStatement,
  values: unknown[] = [],
): D1PreparedStatement {
  return new Proxy(statement, {
    get(target, property) {
      if (property === 'bind')
        return (...args: unknown[]) => platformStatement(sql, target.bind(...args), args);
      const value = Reflect.get(target, property);
      if (['all', 'first', 'run', 'raw'].includes(String(property)))
        return (...args: unknown[]) => {
          for (const match of sql.matchAll(/\b(?:LIKE|GLOB)\s+\?/gi)) {
            const index = (sql.slice(0, match.index).match(/\?/g) || []).length;
            if (typeof values[index] === 'string' && Buffer.byteLength(values[index]) > 50)
              throw new Error('D1_ERROR: LIKE or GLOB pattern too complex');
          }
          return Reflect.apply(value, target, args);
        };
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
}

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
        .filter((statement) => statement.trim())
        .map((statement) => db.prepare(statement)),
    );
  }
  env = {
    DB: new Proxy(db, {
      get(target, property) {
        if (property === 'prepare')
          return (sql: string) => {
            preparedQueries++;
            return platformStatement(sql, target.prepare(sql));
          };
        const value = Reflect.get(target, property);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    }),
    APP_ENV: 'test',
    PUBLIC_HOSTNAME: domain,
    ADMIN_HOSTNAME: host,
    ADMIN_EMAILS: 'lilyyaloveyou@gmail.com,admin@888888.mom',
    CF_ACCESS_TEAM_DOMAIN: 'lilyya.cloudflareaccess.com',
    CF_ACCESS_AUD: audience,
    TURNSTILE_SITE_KEY: 'fixture-public',
    TURNSTILE_SECRET_KEY: 'fixture-private',
  };
  const { privateKey, publicKey } = await generateKeyPair('RS256');
  const jwk = {
    ...(await exportJWK(publicKey)),
    kid: 'synthetic-search-key',
    alg: 'RS256',
    use: 'sig',
  };
  assertion = await new SignJWT({ email: 'admin@888888.mom', type: 'app' })
    .setProtectedHeader({ alg: 'RS256', kid: jwk.kid })
    .setIssuer(issuer)
    .setAudience(audience)
    .setSubject('synthetic-search-admin')
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(privateKey);
  vi.stubGlobal('fetch', async (input: RequestInfo | URL) => {
    const url = input instanceof Request ? input.url : String(input);
    expect(url).toBe(`${issuer}/cdn-cgi/access/certs`);
    return Response.json({ keys: [jwk] });
  });
});

beforeEach(async () => {
  await db.batch(['DELETE FROM links', 'DELETE FROM domains'].map((sql) => db.prepare(sql)));
  await db.batch(
    [domain, otherDomain].map((hostname) =>
      db
        .prepare(
          "INSERT INTO domains(hostname,enabled,bound,created_at,binding_state) VALUES (?,1,1,?,'verified')",
        )
        .bind(hostname, Date.now()),
    ),
  );
  preparedQueries = 0;
});

afterAll(async () => {
  vi.unstubAllGlobals();
  await mf?.dispose();
});

async function seed(
  slug: string,
  url = 'https://example.test/',
  options: { domain?: string; enabled?: number; expiresAt?: number | null } = {},
) {
  const id = crypto.randomUUID();
  await db
    .prepare(
      "INSERT INTO links(id,domain,slug,url,created_at,source,creator,enabled,expires_at) VALUES (?,?,?,?,?,'migration','synthetic-search-fixture',?,?)",
    )
    .bind(
      id,
      options.domain || domain,
      slug,
      url,
      Date.now(),
      options.enabled ?? 1,
      options.expiresAt ?? null,
    )
    .run();
  return id;
}

function search(
  query: string,
  filters: Record<string, string> = {},
  authenticated = true,
  hostname = host,
) {
  const url = new URL(`https://${hostname}/api/admin/links`);
  url.searchParams.set('q', query);
  for (const [key, value] of Object.entries(filters)) url.searchParams.set(key, value);
  return worker.fetch(
    new Request(url, {
      headers: authenticated ? { 'Cf-Access-Jwt-Assertion': assertion } : {},
    }),
    env,
    ctx,
  );
}

async function found(query: string, filters: Record<string, string> = {}) {
  const response = await search(query, filters);
  expect(response.status).toBe(200);
  expect(response.headers.get('Cache-Control')).toBe('no-store');
  return ((await response.json()) as any).data;
}

describe('authenticated administrator search against real D1 with managed pattern limits', () => {
  it('enforces the platform pattern limit for LIKE/GLOB without limiting ordinary bound text', async () => {
    const fifty = 'a'.repeat(50),
      fiftyOne = fifty + 'a';
    expect(
      await env.DB.prepare('SELECT ? LIKE ? AS matched').bind(fifty, fifty).first('matched'),
    ).toBe(1);
    for (const operator of ['LIKE', 'GLOB']) {
      await expect(async () =>
        env.DB.prepare(`SELECT ? ${operator} ? AS matched`).bind(fiftyOne, fiftyOne).first(),
      ).rejects.toThrow('pattern too complex');
    }
    expect(
      await env.DB.prepare('SELECT length(?) AS length').bind('a'.repeat(200)).first('length'),
    ).toBe(200);
  });

  it('finds a complete 64-character short code and a long literal URL substring', async () => {
    const slug = 'goal-1006-anon-' + 'A'.repeat(49);
    const needle = 'signed-path-' + 'b'.repeat(100);
    expect(slug.length).toBe(64);
    const id = await seed(slug, `https://example.test/${needle}?same=+&same=%20#fragment`);
    await seed('different-link', 'https://other.test/');
    for (const query of [slug, needle]) {
      expect((await found(query)).items.map((item: any) => item.id)).toEqual([id]);
    }
  });

  it('matches UTF-8 search text longer than 50 bytes without changing Unicode case semantics', async () => {
    const needle = '界'.repeat(20);
    expect(Buffer.byteLength(needle)).toBeGreaterThan(50);
    const id = await seed('unicode-link', `https://example.test/前${needle}後`);
    await seed('upper-unicode', 'https://example.test/ÄToken');
    const lower = await seed('lower-unicode', 'https://example.test/äToken');
    expect((await found(needle)).items.map((item: any) => item.id)).toEqual([id]);
    expect((await found('äTOKEN')).items.map((item: any) => item.id)).toEqual([lower]);
  });

  it('preserves ASCII case-insensitive matching in short codes and URLs', async () => {
    const first = await seed('MiXeD-Code', 'https://example.test/no-match');
    const second = await seed('url-case', 'https://example.test/PaTh-AlPhA?raw=1');
    expect((await found('mIxEd-CoDe')).items.map((item: any) => item.id)).toEqual([first]);
    expect((await found('path-alpha')).items.map((item: any) => item.id)).toEqual([second]);
  });

  it('treats percent, underscore, backslash and SQL-like text literally', async () => {
    const target = await seed('meta-target', 'https://example.test/?tag=50%_\\done');
    await seed('meta-decoy', 'https://example.test/?tag=50XYdone');
    const percent = await seed('meta-percent', 'https://example.test/?tag=50%Z\\done');
    expect((await found('50%_\\done')).items.map((item: any) => item.id)).toEqual([target]);
    expect((await found('%')).items.map((item: any) => item.id)).toEqual([percent, target]);
    expect((await found('_')).items.map((item: any) => item.id)).toEqual([target]);
    expect((await found('\\')).items.map((item: any) => item.id)).toEqual([percent, target]);
    expect((await found("' OR 1=1 --")).items).toEqual([]);
  });

  it('keeps domain/status filters and descending rowid pagination while searching long text', async () => {
    const query = 'page-' + 'A'.repeat(48);
    const expected: string[] = [];
    for (let index = 0; index < 53; index++) {
      const slug = `${query}-${index}`;
      expected.unshift(slug);
      await seed(slug);
    }
    await seed(`${query}-disabled`, undefined, { enabled: 0 });
    await seed(`${query}-expired`, undefined, { expiresAt: 1 });
    await seed(`${query}-other`, undefined, { domain: otherDomain });
    const filters = { domain, status: 'active' };
    const first = await found(query, filters);
    expect(first.items).toHaveLength(50);
    expect(first.next_cursor).toMatch(/^\d+$/);
    const last = await found(query, { ...filters, cursor: first.next_cursor });
    expect(last.items).toHaveLength(3);
    expect(last.next_cursor).toBeNull();
    const slugs = [...first.items, ...last.items].map((item: any) => item.slug);
    expect(slugs).toEqual(expected);
    expect(new Set(slugs).size).toBe(53);
    expect(
      (await found(query, { domain, status: 'disabled' })).items.map((item: any) => item.slug),
    ).toEqual([`${query}-disabled`]);
    expect(
      (await found(query, { domain, status: 'expired' })).items.map((item: any) => item.slug),
    ).toEqual([`${query}-expired`]);
    expect((await search(query, { cursor: 'invalid' })).status).toBe(400);
  });

  it('accepts 200 characters but rejects 201 before executing a search', async () => {
    for (const character of ['x', '界']) {
      const query = character.repeat(200);
      const id = await seed(
        `bound-${character === 'x' ? 'ascii' : 'unicode'}`,
        `https://example.test/${query}`,
      );
      expect((await found(query)).items.map((item: any) => item.id)).toEqual([id]);
      const before = preparedQueries;
      const rejected = await search(query + character);
      expect(rejected.status).toBe(400);
      expect(((await rejected.json()) as any).error.code).toBe('INVALID_FIELD');
      expect(preparedQueries).toBe(before);
    }
  });

  it('requires signed Access identity and forbids the public host before searching', async () => {
    const query = 'A'.repeat(64);
    expect((await search(query, {}, false)).status).toBe(401);
    expect(preparedQueries).toBe(0);
    expect((await search(query, {}, true, domain)).status).toBe(403);
  });
});
