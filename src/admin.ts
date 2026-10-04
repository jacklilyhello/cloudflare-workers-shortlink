import type { Env, LinkRow, DomainRow, TokenRow } from './types';
import { encodeLegacySlug } from './legacy-slug.mjs';
import {
  ApiError,
  json,
  parseJSONBody,
  validateDomain,
  validateSlug,
  validateUrl,
  hash,
} from './core';
import {
  auditStatement,
  settings,
  SETTING_DEFAULTS,
  startBackup,
  advanceBackup,
} from './maintenance';

const ok = (data: unknown, status = 200) =>
  json({ ok: true, data, request_id: crypto.randomUUID() }, status);
const LINK_ID =
  /^(?:[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}|legacy:[a-f0-9]{64})$/;
function fields(body: Record<string, unknown>, allowed: string[]) {
  if (Object.keys(body).some((k) => !allowed.includes(k)))
    throw new ApiError(400, 'UNKNOWN_FIELD', '请求包含不允许的字段');
}
function text(value: unknown, max = 2000): string {
  if (
    typeof value !== 'string' ||
    value.length > max ||
    /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value)
  )
    throw new ApiError(400, 'INVALID_FIELD', '文字格式无效');
  return value;
}
function expiry(value: unknown): number | null {
  if (value === null) return null;
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > 8640000000000000
  )
    throw new ApiError(400, 'INVALID_FIELD', '时间须为 Unix 毫秒，永久请设为 null');
  return value;
}
function boolean(value: unknown): number {
  if (typeof value !== 'boolean') throw new ApiError(400, 'INVALID_FIELD', '状态须为 boolean');
  return value ? 1 : 0;
}
export function linkDTO(row: LinkRow) {
  return {
    id: row.id,
    domain: row.domain,
    slug: row.slug,
    url: row.url,
    short_url: `https://${row.domain}/${encodeLegacySlug(row.slug)}`,
    created_at: row.created_at,
    expires_at: row.expires_at,
    enabled: !!row.enabled,
    confirmation_enabled: !!row.confirm_enabled,
    confirmation_text: row.confirm_text,
    query_policy: row.query_mode,
    source: row.source,
  };
}
function cursor(url: URL): number {
  const value = url.searchParams.get('cursor');
  if (value === null) return Number.MAX_SAFE_INTEGER;
  if (!/^\d{1,16}$/.test(value) || !Number.isSafeInteger(Number(value)))
    throw new ApiError(400, 'INVALID_CURSOR', '游标无效');
  return Number(value);
}
async function listLinks(env: Env, url: URL) {
  const where = ['rowid<?'];
  const args: (string | number)[] = [cursor(url)];
  const query = url.searchParams.get('q');
  if (query) {
    if (query.length > 200) throw new ApiError(400, 'INVALID_FIELD', '搜索条件过长');
    where.push("(slug LIKE ? ESCAPE '\\' OR url LIKE ? ESCAPE '\\')");
    const escaped = `%${query.replace(/[\\%_]/g, '\\$&')}%`;
    args.push(escaped, escaped);
  }
  const domain = url.searchParams.get('domain');
  if (domain) {
    where.push('domain=?');
    args.push(validateDomain(domain));
  }
  const status = url.searchParams.get('status');
  if (status === 'active') {
    where.push('(enabled=1 AND (expires_at IS NULL OR expires_at>?))');
    args.push(Date.now());
  } else if (status === 'disabled') where.push('enabled=0');
  else if (status === 'expired') {
    where.push('(expires_at IS NOT NULL AND expires_at<=?)');
    args.push(Date.now());
  } else if (status && status !== 'all') throw new ApiError(400, 'INVALID_FIELD', '筛选条件无效');
  const rows = await env.DB.prepare(
    `SELECT rowid AS cursor,* FROM links WHERE ${where.join(' AND ')} ORDER BY rowid DESC LIMIT 51`,
  )
    .bind(...args)
    .all<LinkRow & { cursor: number }>();
  const page = rows.results.slice(0, 50);
  return ok({
    items: page.map(linkDTO),
    next_cursor: rows.results.length > 50 ? String(page[49].cursor) : null,
  });
}
async function createLink(request: Request, env: Env, email: string) {
  const body = await parseJSONBody(request);
  fields(body, ['url', 'domain', 'slug']);
  const url = validateUrl(body.url),
    domain = validateDomain(body.domain);
  if (domain !== env.PUBLIC_HOSTNAME)
    throw new ApiError(403, 'DOMAIN_FORBIDDEN', '域名尚未绑定到本环境');
  const registered = await env.DB.prepare(
    'SELECT hostname FROM domains WHERE hostname=? AND enabled=1 AND bound=1',
  )
    .bind(domain)
    .first();
  if (!registered) throw new ApiError(403, 'DOMAIN_FORBIDDEN', '域名未启用或未绑定');
  const custom = body.slug !== undefined ? validateSlug(body.slug) : null;
  for (let attempt = 0; attempt < 5; attempt++) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';
    const slug =
      custom ||
      Array.from(crypto.getRandomValues(new Uint8Array(10)), (b) => alphabet[b & 63]).join('');
    const id = crypto.randomUUID();
    const rows = await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO links(id,domain,slug,url,created_at,source,creator) SELECT ?,?,?,?,?, 'admin',? FROM domains WHERE hostname=? AND bound=1 AND enabled=1 ON CONFLICT(domain,slug) DO NOTHING RETURNING *",
      ).bind(id, domain, slug, url, Date.now(), email, domain),
      env.DB.prepare(
        "INSERT INTO audit(id,actor,action,entity_id,detail,created_at) SELECT ?,?,'link.create',?,'{}',? WHERE EXISTS(SELECT 1 FROM links WHERE id=?)",
      ).bind(crypto.randomUUID(), email, id, Date.now(), id),
    ]);
    if (rows[0].results.length) return ok(linkDTO(rows[0].results[0] as unknown as LinkRow), 201);
    if (custom) throw new ApiError(409, 'SLUG_CONFLICT', '短码已被占用');
  }
  throw new ApiError(503, 'SLUG_GENERATION_EXHAUSTED', '无法分配短码，请稍后重试');
}
async function updateLink(request: Request, env: Env, email: string, id: string) {
  const body = await parseJSONBody(request);
  fields(body, [
    'enabled',
    'expires_at',
    'confirmation_enabled',
    'confirmation_text',
    'query_policy',
  ]);
  const updates: string[] = [],
    args: (string | number | null)[] = [];
  for (const [key, value] of Object.entries(body)) {
    if (key === 'enabled') {
      updates.push('enabled=?');
      args.push(boolean(value));
    }
    if (key === 'expires_at') {
      updates.push('expires_at=?');
      args.push(expiry(value));
    }
    if (key === 'confirmation_enabled') {
      updates.push('confirm_enabled=?');
      args.push(boolean(value));
    }
    if (key === 'confirmation_text') {
      updates.push('confirm_text=?');
      args.push(text(value));
    }
    if (key === 'query_policy') {
      if (value !== 'merge' && value !== 'preserve')
        throw new ApiError(400, 'INVALID_FIELD', '参数策略无效');
      updates.push('query_mode=?');
      args.push(value);
    }
  }
  if (!updates.length) throw new ApiError(400, 'INVALID_FIELD', '没有要修改的字段');
  if (!(await env.DB.prepare('SELECT id FROM links WHERE id=?').bind(id).first()))
    throw new ApiError(404, 'NOT_FOUND', '链接不存在');
  await env.DB.batch([
    env.DB.prepare(`UPDATE links SET ${updates.join(',')} WHERE id=?`).bind(...args, id),
    auditStatement(env, email, 'link.update', id, { fields: Object.keys(body) }),
  ]);
  return ok(
    linkDTO((await env.DB.prepare('SELECT * FROM links WHERE id=?').bind(id).first<LinkRow>())!),
  );
}
async function bulkLinks(request: Request, env: Env, email: string) {
  const body = await parseJSONBody(request);
  fields(body, ['ids', 'action', 'expires_at']);
  if (
    !Array.isArray(body.ids) ||
    !body.ids.length ||
    body.ids.length > 100 ||
    body.ids.some((id) => typeof id !== 'string' || !LINK_ID.test(id))
  )
    throw new ApiError(400, 'INVALID_FIELD', '一次可选择 1–100 个链接');
  let clause: string;
  let value: number | null;
  if (body.action === 'enable' || body.action === 'disable') {
    if (body.expires_at !== undefined)
      throw new ApiError(400, 'UNKNOWN_FIELD', '此操作不接受到期时间');
    clause = 'enabled=?';
    value = body.action === 'enable' ? 1 : 0;
  } else if (body.action === 'expiry') {
    clause = 'expires_at=?';
    value = expiry(body.expires_at);
  } else throw new ApiError(400, 'INVALID_FIELD', '批量操作无效');
  const ids = [...new Set(body.ids as string[])];
  const results = await env.DB.batch([
    env.DB.prepare(`UPDATE links SET ${clause} WHERE id IN (${ids.map(() => '?').join(',')})`).bind(
      value,
      ...ids,
    ),
    auditStatement(env, email, `link.bulk.${body.action}`, 'batch', { count: ids.length }),
  ]);
  return ok({ updated: results[0].meta.changes });
}
async function domains(request: Request, env: Env, email: string, url: URL) {
  const id = url.pathname.slice('/api/admin/domains/'.length);
  if (request.method === 'GET') {
    const rows = await env.DB.prepare('SELECT * FROM domains ORDER BY hostname').all<DomainRow>();
    return ok({
      items: rows.results.map((r) => ({
        ...r,
        id: r.hostname,
        enabled: !!r.enabled,
        bound: !!r.bound,
      })),
      next_cursor: null,
    });
  }
  const body = await parseJSONBody(request);
  if (request.method === 'POST' && url.pathname === '/api/admin/domains') {
    fields(body, ['hostname']);
    const hostname = validateDomain(body.hostname);
    if (hostname === env.ADMIN_HOSTNAME || hostname.endsWith('.workers.dev'))
      throw new ApiError(400, 'INVALID_DOMAIN', '此域名不能登记为短链域名');
    if (
      await env.DB.prepare('SELECT hostname FROM domains WHERE hostname=?').bind(hostname).first()
    )
      throw new ApiError(409, 'DOMAIN_CONFLICT', '域名已登记');
    await env.DB.batch([
      env.DB.prepare('INSERT INTO domains(hostname,created_at) VALUES(?,?)').bind(
        hostname,
        Date.now(),
      ),
      auditStatement(env, email, 'domain.register', hostname),
    ]);
    return ok({ id: hostname, hostname, enabled: false, bound: false }, 201);
  }
  if (request.method === 'PATCH' && id) {
    fields(body, ['enabled']);
    const hostname = validateDomain(id),
      enabled = boolean(body.enabled);
    const row = await env.DB.prepare('SELECT * FROM domains WHERE hostname=?')
      .bind(hostname)
      .first<DomainRow>();
    if (!row) throw new ApiError(404, 'NOT_FOUND', '域名不存在');
    if (enabled && !row.bound)
      throw new ApiError(409, 'DOMAIN_NOT_BOUND', '须先经手动 Actions 完成绑定核验');
    await env.DB.batch([
      env.DB.prepare('UPDATE domains SET enabled=? WHERE hostname=?').bind(enabled, hostname),
      auditStatement(env, email, 'domain.update', hostname, { enabled: !!enabled }),
    ]);
    return ok({ id: hostname, ...row, enabled: !!enabled, bound: !!row.bound });
  }
  throw new ApiError(405, 'METHOD_NOT_ALLOWED', '方法不支持');
}
async function tokens(request: Request, env: Env, email: string, url: URL) {
  if (request.method === 'GET' && url.pathname === '/api/admin/tokens') {
    const rows = await env.DB.prepare(
      'SELECT rowid AS cursor,id,label,created_at,expires_at,revoked_at,rate_per_minute FROM tokens WHERE rowid<? ORDER BY rowid DESC LIMIT 51',
    )
      .bind(cursor(url))
      .all<TokenRow & { cursor: number }>();
    const page = rows.results.slice(0, 50),
      ids = page.map((r) => r.id);
    const grants = ids.length
      ? await env.DB.prepare(
          `SELECT token_id,domain FROM token_domains WHERE token_id IN (${ids.map(() => '?').join(',')})`,
        )
          .bind(...ids)
          .all<{ token_id: string; domain: string }>()
      : { results: [] };
    return ok({
      items: page.map((r) => ({
        id: r.id,
        name: r.label,
        prefix: r.id.slice(0, 8),
        created_at: r.created_at,
        expires_at: r.expires_at,
        revoked_at: r.revoked_at,
        rate_per_minute: r.rate_per_minute,
        domains: grants.results.filter((g) => g.token_id === r.id).map((g) => g.domain),
      })),
      next_cursor: rows.results.length > 50 ? String(page[49].cursor) : null,
    });
  }
  if (request.method === 'POST' && url.pathname === '/api/admin/tokens') {
    const body = await parseJSONBody(request);
    fields(body, ['name', 'domains', 'expires_at', 'rate_per_minute']);
    const name = text(body.name, 100);
    if (!name.trim()) throw new ApiError(400, 'INVALID_FIELD', '名称不能为空');
    if (!Array.isArray(body.domains) || !body.domains.length || body.domains.length > 20)
      throw new ApiError(400, 'INVALID_FIELD', '请选择允许的域名');
    const grants = [...new Set(body.domains.map(validateDomain))];
    for (const domain of grants)
      if (
        !(await env.DB.prepare(
          'SELECT hostname FROM domains WHERE hostname=? AND enabled=1 AND bound=1',
        )
          .bind(domain)
          .first())
      )
        throw new ApiError(403, 'DOMAIN_FORBIDDEN', '域名未绑定或未启用');
    const expires = body.expires_at === undefined ? null : expiry(body.expires_at);
    if (expires !== null && expires <= Date.now())
      throw new ApiError(400, 'INVALID_FIELD', 'Token 到期时间须为未来');
    const rate = body.rate_per_minute ?? 60;
    if (typeof rate !== 'number' || !Number.isInteger(rate) || rate < 1 || rate > 1000)
      throw new ApiError(400, 'INVALID_FIELD', '速率须在 1–1000 之间');
    const token = `sl_${Array.from(crypto.getRandomValues(new Uint8Array(32)), (b) => b.toString(16).padStart(2, '0')).join('')}`;
    const id = crypto.randomUUID(),
      now = Date.now(),
      digest = await hash(token);
    await env.DB.batch([
      env.DB.prepare(
        'INSERT INTO tokens(id,label,digest,created_at,expires_at,rate_per_minute) VALUES(?,?,?,?,?,?)',
      ).bind(id, name, digest, now, expires, rate),
      ...grants.map((domain) =>
        env.DB.prepare('INSERT INTO token_domains(token_id,domain) VALUES(?,?)').bind(id, domain),
      ),
      auditStatement(env, email, 'token.create', id, { domains: grants }),
    ]);
    return ok(
      {
        id,
        name,
        prefix: id.slice(0, 8),
        token,
        domains: grants,
        created_at: now,
        expires_at: expires,
        revoked_at: null,
        rate_per_minute: rate,
      },
      201,
    );
  }
  const id = url.pathname.slice('/api/admin/tokens/'.length);
  if (request.method === 'DELETE' && /^[a-f0-9-]{36}$/.test(id)) {
    if (!(await env.DB.prepare('SELECT id FROM tokens WHERE id=?').bind(id).first()))
      throw new ApiError(404, 'NOT_FOUND', 'Token 不存在');
    await env.DB.batch([
      env.DB.prepare('UPDATE tokens SET revoked_at=COALESCE(revoked_at,?) WHERE id=?').bind(
        Date.now(),
        id,
      ),
      auditStatement(env, email, 'token.revoke', id),
    ]);
    return ok({ revoked: true });
  }
  throw new ApiError(405, 'METHOD_NOT_ALLOWED', '方法不支持');
}
async function statistics(env: Env, url: URL) {
  const days = Number(url.searchParams.get('days') ?? 30);
  if (!Number.isInteger(days) || days < 1 || days > 90)
    throw new ApiError(400, 'INVALID_FIELD', '统计范围为 1–90 天');
  const since = new Date(Date.now() - (days - 1) * 86400000).toISOString().slice(0, 10);
  const queries = [
    'SELECT day AS date,SUM(count) AS visits FROM daily_stats WHERE day>=? GROUP BY day ORDER BY day',
    ...['country', 'device', 'referrer'].map(
      (field) =>
        `SELECT ${field} AS name,SUM(count) AS count FROM daily_stats WHERE day>=? GROUP BY ${field} ORDER BY count DESC LIMIT 50`,
    ),
    'SELECT COUNT(*) AS links,SUM(CASE WHEN enabled=1 AND (expires_at IS NULL OR expires_at>?) THEN 1 ELSE 0 END) AS active_links FROM links',
    'SELECT COALESCE(SUM(count),0) AS visits FROM daily_stats WHERE day>=?',
  ];
  const result = await env.DB.batch(
    queries.map((sql, i) => env.DB.prepare(sql).bind(i === 4 ? Date.now() : since)),
  );
  return ok({
    daily: result[0].results,
    countries: result[1].results,
    devices: result[2].results,
    referrers: result[3].results,
    totals: {
      ...(result[4].results[0] as Record<string, unknown>),
      ...(result[5].results[0] as Record<string, unknown>),
    },
    days,
    approximate: true,
    meaning:
      'GET 请求次数（包括确认页展示），可能包含机器人；后台异步聚合失败可能少计，非独立访客。地区来自边缘元数据，设备由 UA 推断。',
  });
}
export async function handleAdmin(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  identity: { email: string; csrf: string },
): Promise<Response> {
  const url = new URL(request.url),
    path = url.pathname,
    method = request.method,
    email = identity.email;
  if (path === '/api/admin/session' && method === 'GET') return ok(identity);
  if (path === '/api/admin/links') {
    if (method === 'GET') return listLinks(env, url);
    if (method === 'POST') return createLink(request, env, email);
  }
  if (path === '/api/admin/links/bulk' && method === 'POST') return bulkLinks(request, env, email);
  if (/^\/api\/admin\/links\/[^/]+$/.test(path) && method === 'PATCH') {
    let id: string;
    try {
      id = decodeURIComponent(path.split('/').pop()!);
    } catch {
      throw new ApiError(400, 'INVALID_FIELD', '链接标识无效');
    }
    if (!LINK_ID.test(id)) throw new ApiError(400, 'INVALID_FIELD', '链接标识无效');
    return updateLink(request, env, email, id);
  }
  if (path === '/api/admin/domains' || /^\/api\/admin\/domains\/[^/]+$/.test(path))
    return domains(request, env, email, url);
  if (path === '/api/admin/tokens' || /^\/api\/admin\/tokens\/[^/]+$/.test(path))
    return tokens(request, env, email, url);
  if (path === '/api/admin/stats' && method === 'GET') return statistics(env, url);
  if (path === '/api/admin/settings') {
    if (method === 'GET') return ok(await settings(env));
    if (method === 'PUT') {
      const body = await parseJSONBody(request);
      fields(body, Object.keys(SETTING_DEFAULTS));
      const statements = [];
      for (const [key, value] of Object.entries(body)) {
        let output: string;
        if (key.startsWith('error_')) output = text(value, 500);
        else {
          const num = typeof value === 'number' ? value : Number(value);
          const max = key.includes('rate_') ? 1000 : key === 'backup_interval_hours' ? 720 : 3650;
          if (
            (typeof value !== 'string' && typeof value !== 'number') ||
            !Number.isInteger(num) ||
            num < 1 ||
            num > max
          )
            throw new ApiError(400, 'INVALID_FIELD', '设置数值无效');
          output = String(num);
        }
        statements.push(
          env.DB.prepare(
            'INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
          ).bind(key, output),
        );
      }
      if (!statements.length) throw new ApiError(400, 'INVALID_FIELD', '没有设置');
      await env.DB.batch([
        ...statements,
        auditStatement(env, email, 'settings.update', 'settings', { fields: Object.keys(body) }),
      ]);
      return ok(await settings(env));
    }
  }
  if (path === '/api/admin/backups') {
    if (method === 'GET') {
      const rows = await env.DB.prepare(
        'SELECT id,created_at,status,size,records,completed_at FROM backup_jobs WHERE retired_at IS NULL ORDER BY created_at DESC LIMIT 100',
      ).all();
      return ok({ items: rows.results, next_cursor: null });
    }
    if (method === 'POST') {
      const body = await parseJSONBody(request);
      fields(body, []);
      const id = await startBackup(env, email);
      ctx.waitUntil(advanceBackup(env));
      return ok({ id, status: 'pending' }, 202);
    }
  }
  if (/^\/api\/admin\/backups\/[a-f0-9-]{36}\/download$/.test(path) && method === 'GET') {
    const id = path.split('/')[4];
    const job = await env.DB.prepare(
      "SELECT id FROM backup_jobs WHERE id=? AND status='complete' AND retired_at IS NULL",
    )
      .bind(id)
      .first();
    const object = job && (await env.BACKUPS?.get(`backups/${id}.ndjson`));
    if (!object) throw new ApiError(404, 'NOT_FOUND', '备份尚未完成或不存在');
    return new Response(object.body, {
      headers: {
        'Content-Type': 'application/x-ndjson',
        'Cache-Control': 'no-store',
        'Content-Disposition': `attachment; filename="shortlink-${id}.ndjson"`,
        'X-Content-Type-Options': 'nosniff',
      },
    });
  }
  if (path === '/api/admin/export' && method === 'GET') {
    const start = cursor(url);
    const rows = await env.DB.prepare(
      'SELECT rowid AS cursor,* FROM links WHERE rowid<? ORDER BY rowid DESC LIMIT 501',
    )
      .bind(start)
      .all<LinkRow & { cursor: number }>();
    const page = rows.results.slice(0, 500);
    return new Response(
      JSON.stringify({
        schema_version: 1,
        links: page.map(linkDTO),
        next_cursor: rows.results.length > 500 ? String(page[499].cursor) : null,
      }),
      {
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store',
          'Content-Disposition': 'attachment; filename="shortlink-export.json"',
        },
      },
    );
  }
  if (path === '/api/admin/audit' && method === 'GET') {
    const result = await env.DB.prepare(
      'SELECT rowid AS cursor,* FROM audit WHERE rowid<? ORDER BY rowid DESC LIMIT 51',
    )
      .bind(cursor(url))
      .all<{ cursor: number }>();
    return ok({
      items: result.results.slice(0, 50),
      next_cursor: result.results.length > 50 ? String(result.results[49].cursor) : null,
    });
  }
  if (path === '/api/admin/migrations' && method === 'GET') {
    const run = await env.DB.prepare(
      'SELECT id,state,processed,imported,unchanged,skipped,conflicts,unknown,digest,updated_at FROM legacy_migration_runs ORDER BY started_at DESC,id DESC LIMIT 1',
    ).first<{ id: string; state: string; updated_at: number }>();
    const result = run
      ? await env.DB.prepare(
          'SELECT status,reason,COUNT(*) AS count FROM legacy_migration_items WHERE run_id=? GROUP BY status,reason ORDER BY status,reason',
        )
          .bind(run.id)
          .all()
      : { results: [] };
    return ok({
      items: result.results.map((row) => ({ ...(row as object), updated_at: run?.updated_at })),
      run,
      next_cursor: null,
    });
  }
  throw new ApiError(404, 'NOT_FOUND', '接口不存在');
}
