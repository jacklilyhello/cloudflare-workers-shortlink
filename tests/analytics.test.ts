import { readFile, readdir } from 'node:fs/promises';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { browserRankings, classifyBrowser } from '../src/analytics';
import { handleAdmin } from '../src/admin';
import { handleRedirect } from '../src/core';
import { maintenance, startBackup } from '../src/maintenance';
import type { Env } from '../src/types';
import { countryFlag, trendEntries } from '../ui/analytics-data';

describe('coarse browser classification and honest historical presentation', () => {
  it.each([
    ['Mozilla/5.0 Chrome/130.0 Safari/537.36 Edg/130.0', 'edge'],
    ['Mozilla/5.0 Android Mobile Chrome/130.0 Safari/537.36 SamsungBrowser/26.0', 'samsung'],
    ['Mozilla/5.0 Chrome/130.0 Safari/537.36 OPR/115.0', 'opera'],
    ['Mozilla/5.0 iPhone Mobile CriOS/130.0 Safari/604.1', 'chrome_mobile'],
    ['Mozilla/5.0 Chrome/130.0 Safari/537.36', 'chrome'],
    ['Mozilla/5.0 iPhone Version/18.0 Mobile/15 Safari/604.1', 'safari_mobile'],
    ['Mozilla/5.0 Macintosh Version/18.0 Safari/605.1.15', 'safari'],
    ['Mozilla/5.0 iPhone Mobile FxiOS/132.0', 'firefox_mobile'],
    ['Mozilla/5.0 Gecko/20100101 Firefox/132.0', 'firefox'],
    ['Mozilla/5.0 Chrome/130.0 Mobile MicroMessenger/8.0', 'wechat'],
    ['Mozilla/5.0 HeadlessChrome/130.0', 'bot'],
    ['Googlebot/2.1', 'bot'],
    ['Private client without a recognized signature', 'other'],
    ['', 'unknown'],
  ])('classifies %s as %s without retaining input', (agent, family) => {
    expect(classifyBrowser(agent)).toBe(family);
  });

  it('adds unrecorded history to unknown without pretending to recover old browsers', () => {
    expect(
      browserRankings(
        [
          { name: 'chrome', count: 3 },
          { name: 'unknown', count: 1 },
        ],
        10,
      ),
    ).toEqual([
      { name: 'unknown', count: 7 },
      { name: 'chrome', count: 3 },
    ]);
    expect(browserRankings([], 0)).toEqual([]);
  });

  it('uses real flags and fills missing UTC dates without rebucketing data', () => {
    expect(countryFlag('SG')).toBe('🇸🇬');
    expect(countryFlag('XX')).toBe('🌐');
    expect(countryFlag('<script>')).toBe('🌐');
    const now = Date.parse('2026-10-30T20:00:00Z');
    expect(trendEntries([{ date: '2026-10-29', visits: 8 }], 2, 'UTC', now)).toEqual([
      { date: '2026-10-29', visits: 8 },
      { date: '2026-10-30', visits: 0 },
    ]);
  });
});

describe('browser aggregates with actual local D1 transactions', () => {
  let mf: Miniflare;
  let env: Env;
  let pending: Promise<unknown>[];
  const identity = { email: 'fixture@example.test', csrf: 'fixture' };
  const ctx = {
    waitUntil(job: Promise<unknown>) {
      pending.push(job);
    },
    passThroughOnException() {},
  } as unknown as ExecutionContext;
  const day = new Date().toISOString().slice(0, 10);

  beforeAll(async () => {
    mf = new Miniflare(
      convertV4MiniflareOptions({
        modules: true,
        script: 'export default { fetch() { return new Response("fixture"); } }',
        d1Databases: ['DB'],
        r2Buckets: ['BACKUPS'],
      }),
    );
    env = {
      DB: await mf.getD1Database('DB'),
      BACKUPS: await mf.getR2Bucket('BACKUPS'),
      APP_ENV: 'production',
      PUBLIC_HOSTNAME: 'gfw.mom',
      ADMIN_HOSTNAME: 'link-admin.lily.lat',
      ADMIN_EMAILS: identity.email,
      TURNSTILE_SITE_KEY: 'fixture',
      TURNSTILE_SECRET_KEY: 'fixture',
    } as unknown as Env;
    for (const file of (await readdir(new URL('../migrations/', import.meta.url)))
      .filter((name) => name.endsWith('.sql'))
      .sort()) {
      const sql = await readFile(new URL(`../migrations/${file}`, import.meta.url), 'utf8');
      await env.DB.batch(
        sql
          .split(';')
          .filter((statement) => statement.trim())
          .map((statement) => env.DB.prepare(statement)),
      );
    }
    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO domains(hostname,enabled,bound,created_at,binding_state) VALUES('gfw.mom',1,1,1,'verified')",
      ),
      env.DB.prepare(
        "INSERT INTO links(id,domain,slug,url,created_at,source,creator) VALUES('fixture','gfw.mom','browser','https://example.test/',1,'admin','fixture')",
      ),
      env.DB.prepare("UPDATE settings SET value='0' WHERE key='backup_enabled'"),
    ]);
  });
  beforeEach(async () => {
    pending = [];
    await env.DB.batch([
      env.DB.prepare('DELETE FROM daily_stats'),
      env.DB.prepare('DELETE FROM daily_browser_stats'),
      env.DB.prepare('DELETE FROM backup_rows'),
      env.DB.prepare('DELETE FROM backup_jobs'),
      env.DB.prepare("UPDATE settings SET value='90' WHERE key='analytics_retention_days'"),
    ]);
  });
  afterAll(async () => {
    await mf?.dispose();
  });

  async function stats() {
    const response = await handleAdmin(
      new Request('https://link-admin.lily.lat/api/admin/stats?days=7'),
      env,
      ctx,
      identity,
    );
    return (
      (await response.json()) as {
        data: { browsers: { name: string; count: number }[]; totals: { visits: number } };
      }
    ).data;
  }
  async function redirect(method = 'GET') {
    const response = await handleRedirect(
      new Request('https://gfw.mom/browser', {
        method,
        headers: { 'User-Agent': 'Mozilla/5.0 Chrome/130.0 Safari/537.36 Edg/130.0' },
      }),
      env,
      ctx,
      'gfw.mom',
      'browser',
    );
    expect(response.status).toBe(302);
    await Promise.all(pending);
  }

  it('counts GET once in both dimensions, excludes HEAD, and labels old-only visits unknown', async () => {
    await env.DB.prepare(
      "INSERT INTO daily_stats VALUES(?,'gfw.mom','historical','XX','desktop','direct',4)",
    )
      .bind(day)
      .run();
    await redirect();
    await redirect('HEAD');
    expect(await stats()).toMatchObject({
      totals: { visits: 5 },
      browsers: [
        { name: 'unknown', count: 4 },
        { name: 'edge', count: 1 },
      ],
    });
    const aggregate = await env.DB.prepare('SELECT * FROM daily_browser_stats').all();
    expect(aggregate.results).toEqual([{ day, domain: 'gfw.mom', browser: 'edge', count: 1 }]);
    expect(JSON.stringify(aggregate.results)).not.toContain('Mozilla');
  });

  it('rolls back geographic counts when browser aggregation fails', async () => {
    await env.DB.prepare(
      "CREATE TRIGGER browser_fixture_failure BEFORE INSERT ON daily_browser_stats BEGIN SELECT RAISE(ABORT,'fixture failure'); END",
    ).run();
    try {
      await redirect();
      expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM daily_stats').first('n')).toBe(0);
    } finally {
      await env.DB.prepare('DROP TRIGGER browser_fixture_failure').run();
    }
  });

  it('includes browser families in consistent snapshots and respects aggregate retention 0', async () => {
    await env.DB.prepare(
      "INSERT INTO daily_browser_stats VALUES('2000-01-01','gfw.mom','firefox',2)",
    ).run();
    const backup = await startBackup(env, identity.email);
    const row = await env.DB.prepare(
      "SELECT payload FROM backup_rows WHERE backup_id=? AND json_extract(payload,'$.table')='daily_browser_stats'",
    )
      .bind(backup)
      .first<string>('payload');
    expect(JSON.parse(row!)).toMatchObject({
      table: 'daily_browser_stats',
      data: { browser: 'firefox', count: 2 },
    });
    await env.DB.prepare(
      "UPDATE settings SET value='0' WHERE key='analytics_retention_days'",
    ).run();
    await maintenance(env);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM daily_browser_stats').first('n')).toBe(
      1,
    );
    await env.DB.prepare(
      "UPDATE settings SET value='90' WHERE key='analytics_retention_days'",
    ).run();
    await maintenance(env);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM daily_browser_stats').first('n')).toBe(
      0,
    );
  });
});
