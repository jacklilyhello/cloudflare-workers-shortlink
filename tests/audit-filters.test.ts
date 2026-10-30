import { readFile, readdir } from 'node:fs/promises';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { handleAdmin } from '../src/admin';
import { errorResponse } from '../src/core';
import worker from '../src/index';
import type { Env } from '../src/types';

const host = 'link-admin.lily.lat';
const email = 'admin@888888.mom';
const tokenId = '00000000-0000-4000-8000-000000000001';
const missingId = '00000000-0000-4000-8000-000000000002';
const time = Date.parse('2026-10-21T05:32:40.500Z');
const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
let mf: Miniflare;
let db: D1Database;
let env: Env;

// Enforce managed D1's pattern limit while running accepted queries in real local D1.
function managedStatement(
  sql: string,
  statement: D1PreparedStatement,
  values: unknown[] = [],
): D1PreparedStatement {
  return new Proxy(statement, {
    get(target, key) {
      if (key === 'bind')
        return (...args: unknown[]) => managedStatement(sql, target.bind(...args), args);
      const method = Reflect.get(target, key);
      if (['all', 'first', 'run', 'raw'].includes(String(key)))
        return (...args: unknown[]) => {
          expect(values.length).toBeLessThanOrEqual(100);
          for (const match of sql.matchAll(/\b(?:LIKE|GLOB)\s+\?/gi)) {
            const index = (sql.slice(0, match.index).match(/\?/g) || []).length;
            if (typeof values[index] === 'string' && Buffer.byteLength(values[index]) > 50)
              throw new Error('Managed D1 pattern limit exceeded');
          }
          return Reflect.apply(method, target, args);
        };
      return typeof method === 'function' ? method.bind(target) : method;
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
        .filter((part) => part.trim())
        .map((part) => db.prepare(part)),
    );
  }
  env = {
    DB: new Proxy(db, {
      get(target, key) {
        if (key === 'prepare') return (sql: string) => managedStatement(sql, target.prepare(sql));
        const value = Reflect.get(target, key);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    }),
    APP_ENV: 'production',
    PUBLIC_HOSTNAME: 'gfw.mom',
    ADMIN_HOSTNAME: host,
    ADMIN_EMAILS: 'lilyyaloveyou@gmail.com,admin@888888.mom,moshaoli688@gmail.com',
    CF_ACCESS_TEAM_DOMAIN: 'lilyya.cloudflareaccess.com',
    CF_ACCESS_AUD: 'a'.repeat(64),
    TURNSTILE_SITE_KEY: 'fixture-public',
    TURNSTILE_SECRET_KEY: 'fixture-private',
  };
});
beforeEach(async () => {
  await db.batch(
    ['DELETE FROM audit', 'DELETE FROM token_domains', 'DELETE FROM tokens'].map((sql) =>
      db.prepare(sql),
    ),
  );
});
afterAll(async () => {
  await mf?.dispose();
});

function audit(actor: string, action: string, entity = crypto.randomUUID(), created = time) {
  return db
    .prepare('INSERT INTO audit(id,actor,action,entity_id,created_at) VALUES(?,?,?,?,?)')
    .bind(crypto.randomUUID(), actor, action, entity, created);
}
async function request(query = '', options = false) {
  try {
    return await handleAdmin(
      new Request(
        `https://${host}/api/admin/audit${options ? '/options' : ''}${query ? `?${query}` : ''}`,
      ),
      env,
      ctx,
      { email, csrf: 'fixture-only' },
    );
  } catch (error) {
    return errorResponse(error);
  }
}
async function data(query = '', options = false): Promise<any> {
  const response = await request(query, options);
  expect(response.status).toBe(200);
  return ((await response.json()) as any).data;
}
async function seedToken(label = 'Fixture robot') {
  await db
    .prepare(
      'INSERT INTO tokens(id,label,digest,created_at,revoked_at,expires_at) VALUES(?,?,?,1,2,3)',
    )
    .bind(tokenId, label, 'fixture-digest-not-a-credential')
    .run();
}

describe('read-only audit search and filters against local D1', () => {
  it('preserves raw fields, identities and unfiltered ordering without rewriting records', async () => {
    await db.batch([
      audit(email, 'token.create', tokenId),
      audit('system:scheduled', 'backup.create'),
      audit('anonymous', 'link.create'),
    ]);
    const before = (await db.prepare('SELECT rowid,* FROM audit ORDER BY rowid').all()).results;
    const result = await data();
    expect(result.filtering_supported).toBe(true);
    expect(result.next_cursor).toBeNull();
    expect(result.items.map((row: any) => row.id)).toEqual(
      [...before].reverse().map((row) => row.id),
    );
    expect(result.items[0]).toMatchObject({
      actor: 'anonymous',
      action: 'link.create',
      created_at: time,
      detail: '{}',
      actor_identity: { type: 'anonymous' },
    });
    expect((await db.prepare('SELECT rowid,* FROM audit ORDER BY rowid').all()).results).toEqual(
      before,
    );
  });

  it('searches literal operator, action, object and revoked Token names without pattern expansion or creator attribution', async () => {
    const label = `${'中文'.repeat(35)}_% Robot`;
    await seedToken(label);
    await db.batch([
      audit('creator@example.test', 'token.create', tokenId),
      audit(tokenId, 'link.create', 'needle_OBJECT_%'),
      audit(email, 'settings.update', 'settings'),
      audit(email, 'fixture.event', 'unrelated'),
    ]);
    for (const query of [label, 'needle_object_%', tokenId]) {
      const result = await data(new URLSearchParams({ q: query }).toString());
      expect(result.items.length).toBeGreaterThan(0);
      expect(result.items.some((row: any) => row.actor === tokenId)).toBe(true);
    }
    expect((await data('q=SETTINGS.UPDATE')).items).toHaveLength(1);
    expect(
      (await data(new URLSearchParams({ q: email.toUpperCase() }).toString())).items,
    ).toHaveLength(2);
    expect(
      (await data(new URLSearchParams({ q: 'creator@example.test' }).toString())).items.map(
        (row: any) => row.action,
      ),
    ).toEqual(['token.create']);
    expect((await data(new URLSearchParams({ q: "' OR 1=1 --" }).toString())).items).toEqual([]);
    expect((await data('q=%25')).items).toHaveLength(1);
    const serialized = JSON.stringify(await data());
    expect(serialized).not.toContain('fixture-digest-not-a-credential');
    expect(serialized).not.toContain('"digest"');
  });

  it('includes both exact millisecond boundaries and supports one-sided time ranges', async () => {
    await db.batch([
      audit(email, 'fixture.before', 'before', time - 1),
      audit(email, 'fixture.start', 'start', time),
      audit(email, 'fixture.end', 'end', time + 1000),
      audit(email, 'fixture.after', 'after', time + 1001),
    ]);
    expect(
      (await data(`from=${time}&to=${time + 1000}`)).items.map((row: any) => row.entity_id),
    ).toEqual(['end', 'start']);
    expect((await data(`from=${time + 1001}`)).items.map((row: any) => row.entity_id)).toEqual([
      'after',
    ]);
    expect((await data(`to=${time - 1}`)).items.map((row: any) => row.entity_id)).toEqual([
      'before',
    ]);
    expect((await data('from=0&to=8640000000000000')).items).toHaveLength(4);
  });

  it('filters exact historical actors and only the two verified system identities', async () => {
    await seedToken();
    await db.batch([
      audit(email, 'settings.update'),
      audit('former-admin@example.test', 'settings.update'),
      audit('system:scheduled', 'backup.create'),
      audit('system:production-migration', 'backup.create'),
      audit('system:unrecognized', 'fixture.event'),
      audit(tokenId, 'link.create'),
      audit(missingId, 'link.create'),
    ]);
    const system = await data('system_only=1');
    expect(system.items.map((row: any) => row.actor)).toEqual([
      'system:production-migration',
      'system:scheduled',
    ]);
    expect(
      (await data(new URLSearchParams({ actor: 'former-admin@example.test' }).toString())).items,
    ).toHaveLength(1);
    expect(
      (await data(new URLSearchParams({ actor: missingId }).toString())).items[0].actor_identity
        .type,
    ).toBe('business_token');
    expect(
      (await data(new URLSearchParams({ actor: email, system_only: '1' }).toString())).items,
    ).toEqual([]);
    expect(
      (await data(new URLSearchParams({ actor: 'system:scheduled', system_only: '1' }).toString()))
        .items,
    ).toHaveLength(1);
  });

  it('combines search, time, exact actor and multiple exclusions without deleting logs', async () => {
    await db.batch([
      audit(email, 'link.create', 'match'),
      audit(email, 'token.create', 'match'),
      audit(email, 'settings.update', 'match'),
      audit('other@example.test', 'settings.update', 'match'),
      audit(email, 'settings.update', 'outside', time - 1),
    ]);
    const params = new URLSearchParams({
      q: 'match',
      actor: email,
      from: String(time),
      to: String(time),
    });
    params.append('exclude_action', 'link.create');
    params.append('exclude_action', 'token.create');
    params.append('exclude_action', 'link.create');
    params.append('exclude_action', 'future.safe_action');
    expect((await data(params.toString())).items.map((row: any) => row.action)).toEqual([
      'settings.update',
    ]);
    expect(await db.prepare('SELECT COUNT(*) AS count FROM audit').first('count')).toBe(5);
    expect(
      (
        await data(
          'exclude_action=settings.update&exclude_action=link.create&exclude_action=token.create',
        )
      ).items,
    ).toEqual([]);
  });

  it('paginates matching rows across intervening non-matches without duplicates or missing records', async () => {
    const statements = [];
    for (let index = 0; index < 72; index++) {
      statements.push(audit(email, 'settings.update', `page-match-${index}`));
      statements.push(audit(email, 'link.create', `page-match-excluded-${index}`));
      statements.push(audit('other@example.test', 'settings.update', `page-match-other-${index}`));
    }
    await db.batch(statements);
    const params = new URLSearchParams({
      actor: email,
      q: 'page-match',
      from: String(time),
      to: String(time),
      exclude_action: 'link.create',
    });
    const first = await data(params.toString());
    expect(first.items).toHaveLength(50);
    params.set('cursor', first.next_cursor);
    const second = await data(params.toString());
    expect(second.items).toHaveLength(22);
    expect(second.next_cursor).toBeNull();
    const items = [...first.items, ...second.items];
    expect(new Set(items.map((row: any) => row.id)).size).toBe(72);
    expect(items.map((row: any) => row.entity_id)).toEqual(
      Array.from({ length: 72 }, (_, i) => `page-match-${71 - i}`),
    );
  });

  it('offers actors and action codes from retained history, including older, revoked and missing Token identities', async () => {
    await seedToken('<b>same name</b>');
    await db.batch([
      audit(email, 'token.create', tokenId, 1),
      audit('system:production-migration', 'backup.create'),
      audit('system:unrecognized', 'fixture.event'),
      audit(missingId, 'link.create'),
      audit('former-admin@example.test', 'settings.update'),
      ...Array.from({ length: 52 }, () => audit(tokenId, 'link.create')),
    ]);
    expect((await data()).items.every((row: any) => row.actor === tokenId)).toBe(true);
    const response = await data('', true);
    const actors = new Map(
      response.actors.map((option: any) => [option.actor, option.actor_identity]),
    );
    expect(response.actors).toHaveLength(6);
    expect(actors.get(email)).toMatchObject({ type: 'admin', name: email });
    expect(actors.get(tokenId)).toMatchObject({
      type: 'business_token',
      name: '<b>same name</b>',
      token_id: tokenId,
      created_by: null,
    });
    expect(actors.get(missingId)).toMatchObject({ type: 'business_token', name: null });
    expect(actors.get('system:production-migration')).toMatchObject({ type: 'system' });
    expect(actors.get('system:unrecognized')).toMatchObject({ type: 'unknown' });
    expect(response.actions).toEqual([
      'backup.create',
      'fixture.event',
      'link.create',
      'settings.update',
      'token.create',
    ]);
    expect(response.actors_truncated).toBe(false);
    expect(response.actions_truncated).toBe(false);
    expect(JSON.stringify(response)).not.toContain('fixture-digest-not-a-credential');
    expect(await db.prepare('SELECT COUNT(*) AS count FROM audit').first('count')).toBe(57);
  });

  it('bounds filter options while still querying actors and actions beyond the options limit', async () => {
    await db.batch(
      Array.from({ length: 205 }, (_, i) =>
        audit(
          `person-${String(i).padStart(3, '0')}@example.test`,
          `fixture.action_${String(i).padStart(3, '0')}`,
        ),
      ),
    );
    const options = await data('', true);
    expect(options.actors).toHaveLength(200);
    expect(options.actions).toHaveLength(100);
    expect(options.actors_truncated).toBe(true);
    expect(options.actions_truncated).toBe(true);
    expect(
      (await data(new URLSearchParams({ actor: 'person-204@example.test' }).toString())).items,
    ).toHaveLength(1);
    expect((await data('q=fixture.action_204')).items).toHaveLength(1);
  });

  it('rejects ambiguous, oversized, malformed or reversed filters', async () => {
    const invalid = [
      'q=a&q=b',
      'actor=a&actor=b',
      'from=1&from=2',
      'to=1&to=2',
      'system_only=1&system_only=1',
      'cursor=1&cursor=2',
      'from=-1',
      'from=1.5',
      'from=Infinity',
      'to=8640000000000001',
      'from=2&to=1',
      'system_only=0',
      'actor=',
      'actor=%0A',
      'exclude_action=',
      'exclude_action=%27%20OR%201%3D1',
      new URLSearchParams({ q: 'x'.repeat(201) }).toString(),
      new URLSearchParams({ actor: 'x'.repeat(201) }).toString(),
      new URLSearchParams({ exclude_action: 'a'.repeat(81) }).toString(),
      Array.from({ length: 21 }, () => 'exclude_action=link.create').join('&'),
    ];
    for (const query of invalid) expect((await request(query)).status, query).toBe(400);
    expect(
      (
        await request(
          Array.from({ length: 20 }, (_, i) => `exclude_action=fixture.action_${i}`).join('&'),
        )
      ).status,
    ).toBe(200);
  });

  it('keeps both read endpoints behind administrator authentication', async () => {
    for (const path of ['audit?system_only=1', 'audit/options']) {
      const response = await worker.fetch(
        new Request(`https://${host}/api/admin/${path}`, {
          headers: { Authorization: 'Bearer fixture-not-an-admin' },
        }),
        env,
        ctx,
      );
      expect(response.status).toBe(401);
      expect(((await response.json()) as any).error.code).toBe('ADMIN_REQUIRED');
    }
  });
});
