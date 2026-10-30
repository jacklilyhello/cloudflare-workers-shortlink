import type { Env, LinkRow, DomainRow, TokenRow, AuditRow } from './types';
import { auditFilterOptions, auditIdentities } from './audit';
import { auditQuery } from './audit-query';
import { browserRankings } from './analytics';
import { verifyDomainBinding } from './domain-binding';
import { encodeLegacySlug } from './legacy-slug.mjs';
import {
  ERROR_PAGE_KEYS,
  ERROR_PAGE_HTML_MAX_BYTES,
  isErrorPageKey,
  validErrorPageHtml,
  type ErrorPage,
  type ErrorPageKey,
} from './error-page-config';
import { errorPagePreview } from './error-page-response';
import { INTERSTITIAL_BODY_MAX_BYTES, validPageContent } from './interstitial';
import {
  ApiError,
  json,
  parseJSONBody,
  validateDomain,
  validateSlug,
  validateUrl,
  hash,
  isPublicHostname,
  publicDomains,
} from './core';
import {
  auditStatement,
  settings,
  SETTING_DEFAULTS,
  startBackup,
  advanceBackup,
  getBackupStatus,
  getMigrationStatus,
} from './maintenance';

const ok = (data: unknown, status = 200) =>
  json({ ok: true, data, request_id: crypto.randomUUID() }, status);
const LINK_ID =
  /^(?:[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}|legacy:[a-f0-9]{64})$/;
const TOKEN_ID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
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
export function linkDTO(row: LinkRow, domains: readonly string[]) {
  const public_urls = domains.map((domain) => ({
    domain,
    short_url: `https://${domain}/${encodeLegacySlug(row.slug)}`,
  }));
  return {
    id: row.id,
    domain: row.domain,
    source_domain: row.domain,
    current_domain: public_urls[0]?.domain ?? null,
    slug: row.slug,
    url: row.url,
    short_url: public_urls[0]?.short_url ?? null,
    public_urls,
    created_at: row.created_at,
    expires_at: row.expires_at,
    enabled: !!row.enabled,
    confirmation_enabled: !!row.confirm_enabled,
    confirmation_text: row.confirm_text,
    confirmation_mode: row.confirm_mode ?? 'text',
    query_policy: row.target_origin_only ? 'origin' : row.query_mode,
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
    where.push('(instr(lower(slug),lower(?))>0 OR instr(lower(url),lower(?))>0)');
    args.push(query, query);
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
  const confirmation = url.searchParams.get('confirmation');
  if (confirmation === 'enabled') where.push('confirm_enabled=1');
  else if (confirmation && confirmation !== 'all')
    throw new ApiError(400, 'INVALID_FIELD', '确认页筛选条件无效');
  const rows = await env.DB.prepare(
    `SELECT rowid AS cursor,* FROM links WHERE ${where.join(' AND ')} ORDER BY rowid DESC LIMIT 51`,
  )
    .bind(...args)
    .all<LinkRow & { cursor: number }>();
  const page = rows.results.slice(0, 50);
  const domains = await publicDomains(env);
  return ok({
    items: page.map((row) => linkDTO(row, domains)),
    domain_filter: 'source_domain',
    next_cursor: rows.results.length > 50 ? String(page[49].cursor) : null,
  });
}
async function createLink(request: Request, env: Env, email: string) {
  const body = await parseJSONBody(request);
  fields(body, ['url', 'domain', 'slug']);
  const url = validateUrl(body.url),
    domain = validateDomain(body.domain);
  if (!isPublicHostname(domain, env))
    throw new ApiError(403, 'DOMAIN_FORBIDDEN', '该主机不能作为公共短链入口');
  const registered = await env.DB.prepare(
    "SELECT hostname FROM domains WHERE hostname=? AND enabled=1 AND bound=1 AND binding_state='verified'",
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
        "INSERT INTO links(id,domain,slug,url,created_at,source,creator) SELECT ?,?,?,?,?, 'admin',? FROM domains WHERE hostname=? AND bound=1 AND binding_state='verified' AND enabled=1 AND NOT EXISTS(SELECT 1 FROM deleted_links WHERE slug=?) ON CONFLICT DO NOTHING RETURNING *",
      ).bind(id, domain, slug, url, Date.now(), email, domain, slug),
      env.DB.prepare(
        "INSERT INTO audit(id,actor,action,entity_id,detail,created_at) SELECT ?,?,'link.create',?,'{}',? WHERE EXISTS(SELECT 1 FROM links WHERE id=?)",
      ).bind(crypto.randomUUID(), email, id, Date.now(), id),
    ]);
    if (rows[0].results.length)
      return ok(linkDTO(rows[0].results[0] as unknown as LinkRow, await publicDomains(env)), 201);
    if (custom) throw new ApiError(409, 'SLUG_CONFLICT', '短码已被占用');
  }
  throw new ApiError(503, 'SLUG_GENERATION_EXHAUSTED', '无法分配短码，请稍后重试');
}
async function updateLink(request: Request, env: Env, email: string, id: string) {
  const body = await parseJSONBody(request, INTERSTITIAL_BODY_MAX_BYTES);
  fields(body, [
    'enabled',
    'expires_at',
    'confirmation_enabled',
    'confirmation_text',
    'confirmation_mode',
    'query_policy',
  ]);
  const updates: string[] = [],
    args: (string | number | null)[] = [];
  let previous: Pick<LinkRow, 'confirm_mode' | 'confirm_text'> | null = null;
  if (body.confirmation_text !== undefined || body.confirmation_mode !== undefined) {
    previous = await env.DB.prepare('SELECT confirm_mode,confirm_text FROM links WHERE id=?')
      .bind(id)
      .first<Pick<LinkRow, 'confirm_mode' | 'confirm_text'>>();
    if (!previous) throw new ApiError(404, 'NOT_FOUND', '链接不存在或已彻底删除');
    const mode =
      body.confirmation_mode !== undefined ? body.confirmation_mode : previous.confirm_mode;
    const content =
      body.confirmation_text !== undefined ? body.confirmation_text : previous.confirm_text;
    if ((mode !== 'text' && mode !== 'html') || !validPageContent(content, mode))
      throw new ApiError(
        400,
        'INVALID_FIELD',
        '确认页须为有效文字（最多 2000 字）或 HTML（最多 128 KiB）',
      );
    updates.push('confirm_mode=?', 'confirm_text=?');
    args.push(mode, content);
  }
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
    if (key === 'query_policy') {
      if (value !== 'merge' && value !== 'preserve' && value !== 'origin')
        throw new ApiError(400, 'INVALID_FIELD', '参数策略无效');
      updates.push('query_mode=?', 'target_origin_only=?');
      args.push(value === 'origin' ? 'preserve' : value, value === 'origin' ? 1 : 0);
    }
  }
  if (!updates.length) throw new ApiError(400, 'INVALID_FIELD', '没有要修改的字段');
  const result = await env.DB.batch([
    env.DB.prepare(
      `UPDATE links SET ${updates.join(',')} WHERE id=?${previous ? ' AND confirm_mode=? AND confirm_text=?' : ''} RETURNING *`,
    ).bind(...args, id, ...(previous ? [previous.confirm_mode!, previous.confirm_text] : [])),
    env.DB.prepare(
      "INSERT INTO audit(id,actor,action,entity_id,detail,created_at) SELECT ?,?,'link.update',id,?,? FROM links WHERE id=? AND changes()>0",
    ).bind(
      crypto.randomUUID(),
      email,
      JSON.stringify({ fields: Object.keys(body) }),
      Date.now(),
      id,
    ),
  ]);
  const row = result[0].results[0] as unknown as LinkRow | undefined;
  if (!row) {
    if (previous && (await env.DB.prepare('SELECT id FROM links WHERE id=?').bind(id).first()))
      throw new ApiError(409, 'EDIT_CONFLICT', '确认页已被其他操作修改，请刷新后重试');
    throw new ApiError(404, 'NOT_FOUND', '链接不存在或已彻底删除');
  }
  return ok(linkDTO(row, await publicDomains(env)));
}
async function bulkLinks(request: Request, env: Env, email: string) {
  const body = await parseJSONBody(request, INTERSTITIAL_BODY_MAX_BYTES);
  fields(body, [
    'ids',
    'action',
    'expires_at',
    'confirmation_enabled',
    'confirmation_mode',
    'confirmation_text',
  ]);
  if (
    !Array.isArray(body.ids) ||
    !body.ids.length ||
    body.ids.length > 100 ||
    body.ids.some((id) => typeof id !== 'string' || !LINK_ID.test(id))
  )
    throw new ApiError(400, 'INVALID_FIELD', '一次可选择 1–100 个链接');
  let clause: string;
  let values: (number | string | null)[];
  const confirmationFields = ['confirmation_enabled', 'confirmation_mode', 'confirmation_text'];
  if (body.action !== 'confirmation' && confirmationFields.some((key) => body[key] !== undefined))
    throw new ApiError(400, 'UNKNOWN_FIELD', '此操作不接受确认页字段');
  if (body.action === 'enable' || body.action === 'disable') {
    if (body.expires_at !== undefined)
      throw new ApiError(400, 'UNKNOWN_FIELD', '此操作不接受到期时间');
    clause = 'enabled=?';
    values = [body.action === 'enable' ? 1 : 0];
  } else if (body.action === 'expiry') {
    clause = 'expires_at=?';
    values = [expiry(body.expires_at)];
  } else if (body.action === 'confirmation') {
    if (body.expires_at !== undefined)
      throw new ApiError(400, 'UNKNOWN_FIELD', '此操作不接受到期时间');
    const updates: string[] = [];
    values = [];
    if (body.confirmation_enabled !== undefined) {
      updates.push('confirm_enabled=?');
      values.push(boolean(body.confirmation_enabled));
    }
    if (body.confirmation_mode !== undefined || body.confirmation_text !== undefined) {
      const mode = body.confirmation_mode;
      if ((mode !== 'text' && mode !== 'html') || !validPageContent(body.confirmation_text, mode))
        throw new ApiError(400, 'INVALID_FIELD', '批量编辑须同时指定有效的确认页格式和内容');
      updates.push('confirm_mode=?', 'confirm_text=?');
      values.push(mode, body.confirmation_text);
    }
    if (!updates.length) throw new ApiError(400, 'INVALID_FIELD', '没有要修改的确认页字段');
    clause = updates.join(',');
  } else throw new ApiError(400, 'INVALID_FIELD', '批量操作无效');
  const ids = [...new Set(body.ids as string[])];
  const statements = [];
  const chunkSize = 100 - values.length;
  for (let offset = 0; offset < ids.length; offset += chunkSize) {
    const chunk = ids.slice(offset, offset + chunkSize);
    statements.push(
      env.DB.prepare(
        `UPDATE links SET ${clause} WHERE id IN (${chunk.map(() => '?').join(',')})`,
      ).bind(...values, ...chunk),
    );
  }
  const results = await env.DB.batch([
    ...statements,
    auditStatement(env, email, `link.bulk.${body.action}`, 'batch', { count: ids.length }),
  ]);
  return ok({
    updated: results
      .slice(0, statements.length)
      .reduce((sum, result) => sum + result.meta.changes, 0),
  });
}
async function refreshDomain(env: Env, email: string, hostname: string) {
  if (!isPublicHostname(hostname, env))
    throw new ApiError(403, 'DOMAIN_FORBIDDEN', '此域名已停止提供公共短链服务');
  const row = await env.DB.prepare('SELECT * FROM domains WHERE hostname=?')
    .bind(hostname)
    .first<DomainRow>();
  if (!row) throw new ApiError(404, 'NOT_FOUND', '域名不存在');
  const now = Date.now();
  try {
    const result = await verifyDomainBinding(env, hostname);
    const updates = await env.DB.batch([
      env.DB.prepare(
        'UPDATE domains SET bound=?,binding_state=?,binding_error=?,last_checked_at=?,last_verified_at=CASE WHEN ?=1 THEN ? ELSE last_verified_at END WHERE hostname=? AND (last_checked_at IS NULL OR last_checked_at<=?) RETURNING *',
      ).bind(
        result.bound ? 1 : 0,
        result.binding_state,
        result.binding_error,
        now,
        result.bound ? 1 : 0,
        now,
        hostname,
        now,
      ),
      auditStatement(env, email, 'domain.verify', hostname, { state: result.binding_state }),
    ]);
    const current =
      (updates[0].results[0] as unknown as DomainRow | undefined) ??
      (await env.DB.prepare('SELECT * FROM domains WHERE hostname=?')
        .bind(hostname)
        .first<DomainRow>());
    if (!current) throw new ApiError(404, 'NOT_FOUND', '域名不存在');
    return domainDTO(current);
  } catch (error) {
    const code = error instanceof ApiError ? error.code : 'BINDING_READ_FAILED';
    await env.DB.batch([
      env.DB.prepare(
        "UPDATE domains SET bound=0,binding_state='failed',binding_error=?,last_checked_at=? WHERE hostname=? AND (last_checked_at IS NULL OR last_checked_at<=?)",
      ).bind(code, now, hostname, now),
      auditStatement(env, email, 'domain.verify_failed', hostname, { code }),
    ]);
    throw error;
  }
}
function domainDTO(row: DomainRow) {
  return {
    ...row,
    id: row.hostname,
    enabled: !!row.enabled,
    bound: !!row.bound,
    interstitial_enabled: !!row.interstitial_enabled,
    interstitial_delay: row.interstitial_delay ?? 5,
    interstitial_html: row.interstitial_html ?? '',
  };
}
async function domains(request: Request, env: Env, email: string, url: URL) {
  const id = url.pathname.slice('/api/admin/domains/'.length);
  if (request.method === 'POST' && id.endsWith('/verify')) {
    const hostname = validateDomain(id.slice(0, -'/verify'.length));
    const body = await parseJSONBody(request);
    fields(body, []);
    return ok(await refreshDomain(env, email, hostname));
  }
  if (request.method === 'GET') {
    const rows = await env.DB.prepare('SELECT * FROM domains ORDER BY hostname').all<DomainRow>();
    return ok({
      items: rows.results.map((r) => ({
        ...domainDTO(r),
        public_service_allowed: isPublicHostname(r.hostname, env),
      })),
      next_cursor: null,
    });
  }
  const body = await parseJSONBody(request, INTERSTITIAL_BODY_MAX_BYTES);
  if (request.method === 'POST' && url.pathname === '/api/admin/domains') {
    fields(body, ['hostname']);
    const hostname = validateDomain(body.hostname);
    if (!isPublicHostname(hostname, env))
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
    return ok(
      {
        id: hostname,
        hostname,
        enabled: false,
        bound: false,
        binding_state: 'unbound',
        last_verified_at: null,
        last_checked_at: null,
        binding_error: null,
        interstitial_enabled: false,
        interstitial_delay: 5,
        interstitial_html: '',
      },
      201,
    );
  }
  if (request.method === 'PATCH' && id) {
    fields(body, ['enabled', 'interstitial_enabled', 'interstitial_delay', 'interstitial_html']);
    if (!Object.keys(body).length) throw new ApiError(400, 'INVALID_FIELD', '没有要修改的域名配置');
    const hostname = validateDomain(id);
    const enabled = body.enabled === undefined ? undefined : boolean(body.enabled);
    const updates: string[] = [];
    const args: (string | number)[] = [];
    if (enabled !== undefined) {
      updates.push('enabled=?');
      args.push(enabled);
    }
    if (body.interstitial_enabled !== undefined) {
      updates.push('interstitial_enabled=?');
      args.push(boolean(body.interstitial_enabled));
    }
    if (body.interstitial_delay !== undefined) {
      const delay = body.interstitial_delay;
      if (typeof delay !== 'number' || !Number.isInteger(delay) || delay < 0 || delay > 300)
        throw new ApiError(400, 'INVALID_FIELD', '中间页展示时间须为 0–300 秒的整数');
      updates.push('interstitial_delay=?');
      args.push(delay);
    }
    if (body.interstitial_html !== undefined) {
      if (!validPageContent(body.interstitial_html, 'html'))
        throw new ApiError(400, 'INVALID_FIELD', '中间页 HTML 格式无效或超过 128 KiB');
      updates.push('interstitial_html=?');
      args.push(body.interstitial_html);
    }
    if (enabled && !isPublicHostname(hostname, env))
      throw new ApiError(403, 'DOMAIN_FORBIDDEN', '此域名已停止提供公共短链服务');
    const row = await env.DB.prepare('SELECT * FROM domains WHERE hostname=?')
      .bind(hostname)
      .first<DomainRow>();
    if (!row) throw new ApiError(404, 'NOT_FOUND', '域名不存在');
    if (enabled && (!row.bound || row.binding_state !== 'verified'))
      throw new ApiError(409, 'DOMAIN_NOT_BOUND', '请先在 Worker 面板手动绑定，再点击刷新绑定状态');
    if (enabled && !row.enabled) {
      const fresh = await refreshDomain(env, email, hostname);
      if (!fresh.bound || fresh.binding_state !== 'verified')
        throw new ApiError(409, 'DOMAIN_NOT_BOUND', '绑定尚未就绪，无法启用');
    }
    const updated = await env.DB.batch([
      env.DB.prepare(
        `UPDATE domains SET ${updates.join(',')} WHERE hostname=? AND (?=0 OR (bound=1 AND binding_state='verified')) RETURNING *`,
      ).bind(...args, hostname, enabled === 1 ? 1 : 0),
      env.DB.prepare(
        "INSERT INTO audit(id,actor,action,entity_id,detail,created_at) SELECT ?,?,'domain.update',hostname,?,? FROM domains WHERE hostname=? AND changes()>0",
      ).bind(
        crypto.randomUUID(),
        email,
        JSON.stringify({ fields: Object.keys(body) }),
        Date.now(),
        hostname,
      ),
    ]);
    const current = updated[0].results[0] as unknown as DomainRow | undefined;
    if (!current) throw new ApiError(409, 'DOMAIN_NOT_BOUND', '绑定状态已改变，请刷新后再试');
    return ok(domainDTO(current));
  }
  throw new ApiError(405, 'METHOD_NOT_ALLOWED', '方法不支持');
}
async function tokens(request: Request, env: Env, email: string, url: URL) {
  if (request.method === 'GET' && url.pathname === '/api/admin/tokens') {
    const rows = await env.DB.prepare(
      'SELECT rowid AS cursor,id,label,created_at,expires_at,revoked_at,rate_per_minute FROM tokens WHERE rowid<? AND deleted_at IS NULL ORDER BY rowid DESC LIMIT 51',
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
    for (const domain of grants) {
      if (!isPublicHostname(domain, env))
        throw new ApiError(403, 'DOMAIN_FORBIDDEN', '此域名不能授权机器短链服务');
      if (
        !(await env.DB.prepare(
          "SELECT hostname FROM domains WHERE hostname=? AND enabled=1 AND bound=1 AND binding_state='verified'",
        )
          .bind(domain)
          .first())
      )
        throw new ApiError(403, 'DOMAIN_FORBIDDEN', '域名未绑定或未启用');
    }
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
  const editing = /^\/api\/admin\/tokens\/([^/]+)$/.exec(url.pathname);
  if (request.method === 'PATCH' && editing) {
    const id = editing[1];
    if (!TOKEN_ID.test(id)) throw new ApiError(400, 'INVALID_FIELD', 'Token 标识无效');
    const body = await parseJSONBody(request);
    fields(body, ['name', 'domains', 'expires_at', 'rate_per_minute']);
    if (!Object.keys(body).length) throw new ApiError(400, 'INVALID_FIELD', '没有要修改的字段');
    const assignments: string[] = [];
    const values: (string | number | null)[] = [];
    if (body.name !== undefined) {
      const name = text(body.name, 100);
      if (!name.trim()) throw new ApiError(400, 'INVALID_FIELD', '名称不能为空');
      assignments.push('label=?');
      values.push(name);
    }
    if (body.expires_at !== undefined) {
      const expires = expiry(body.expires_at);
      if (expires !== null && expires <= Date.now())
        throw new ApiError(400, 'INVALID_FIELD', 'Token 到期时间须为未来');
      assignments.push('expires_at=?');
      values.push(expires);
    }
    if (body.rate_per_minute !== undefined) {
      const rate = body.rate_per_minute;
      if (typeof rate !== 'number' || !Number.isInteger(rate) || rate < 1 || rate > 1000)
        throw new ApiError(400, 'INVALID_FIELD', '速率须在 1–1000 之间');
      assignments.push('rate_per_minute=?');
      values.push(rate);
    }
    let grants: string[] | undefined;
    if (body.domains !== undefined) {
      if (!Array.isArray(body.domains) || !body.domains.length || body.domains.length > 20)
        throw new ApiError(400, 'INVALID_FIELD', '请选择允许的域名');
      grants = [...new Set(body.domains.map(validateDomain))];
      for (const domain of grants) {
        if (!isPublicHostname(domain, env))
          throw new ApiError(403, 'DOMAIN_FORBIDDEN', '此域名不能授权机器短链服务');
        if (
          !(await env.DB.prepare(
            "SELECT hostname FROM domains WHERE hostname=? AND enabled=1 AND bound=1 AND binding_state='verified'",
          )
            .bind(domain)
            .first())
        )
          throw new ApiError(403, 'DOMAIN_FORBIDDEN', '域名未绑定或未启用');
      }
    }
    if (!assignments.length) assignments.push('label=label');
    const current = await env.DB.prepare('SELECT revoked_at,deleted_at FROM tokens WHERE id=?')
      .bind(id)
      .first<{ revoked_at: number | null; deleted_at: number | null }>();
    if (!current || current.deleted_at !== null)
      throw new ApiError(404, 'NOT_FOUND', 'Token 不存在');
    if (current.revoked_at !== null)
      throw new ApiError(409, 'TOKEN_REVOKED', '已撤销的 Token 不能编辑');
    // Repeat all authority predicates inside one transaction so an in-flight edit
    // cannot restore grants after deletion/revocation or a domain state change.
    const grantGuard = grants
      ? ` AND (SELECT COUNT(*) FROM domains WHERE hostname IN (${grants.map(() => '?').join(',')}) AND enabled=1 AND bound=1 AND binding_state='verified')=?`
      : '';
    const predicate = `id=? AND deleted_at IS NULL AND revoked_at IS NULL${grantGuard}`;
    const guards: (string | number)[] = [id, ...(grants ?? []), ...(grants ? [grants.length] : [])];
    const statements = [
      env.DB.prepare(
        `UPDATE tokens SET ${assignments.join(',')} WHERE ${predicate} RETURNING id,label,created_at,expires_at,revoked_at,rate_per_minute`,
      ).bind(...values, ...guards),
    ];
    if (grants) {
      statements.push(
        env.DB.prepare(
          `DELETE FROM token_domains WHERE token_id=? AND EXISTS(SELECT 1 FROM tokens WHERE ${predicate})`,
        ).bind(id, ...guards),
        ...grants.map((domain) =>
          env.DB.prepare(
            `INSERT INTO token_domains(token_id,domain) SELECT ?,? WHERE EXISTS(SELECT 1 FROM tokens WHERE ${predicate})`,
          ).bind(id, domain, ...guards),
        ),
      );
    }
    statements.push(
      env.DB.prepare(
        `INSERT INTO audit(id,actor,action,entity_id,detail,created_at) SELECT ?,?,'token.update',id,?,? FROM tokens WHERE ${predicate}`,
      ).bind(
        crypto.randomUUID(),
        email,
        JSON.stringify({ fields: Object.keys(body) }),
        Date.now(),
        ...guards,
      ),
      env.DB.prepare('SELECT domain FROM token_domains WHERE token_id=? ORDER BY domain').bind(id),
    );
    const result = await env.DB.batch(statements);
    const updated = result[0].results[0] as unknown as TokenRow | undefined;
    if (!updated)
      throw new ApiError(409, 'TOKEN_STATE_CHANGED', 'Token 或域名状态已改变，请刷新后再试');
    return ok({
      id: updated.id,
      name: updated.label,
      prefix: updated.id.slice(0, 8),
      created_at: updated.created_at,
      expires_at: updated.expires_at,
      revoked_at: updated.revoked_at,
      rate_per_minute: updated.rate_per_minute,
      domains: result[result.length - 1].results.map((row) => (row as { domain: string }).domain),
    });
  }
  const deletion = /^\/api\/admin\/tokens\/([^/]+)\/delete$/.exec(url.pathname);
  if (request.method === 'POST' && deletion) {
    const id = deletion[1];
    if (!TOKEN_ID.test(id)) throw new ApiError(400, 'INVALID_FIELD', 'Token 标识无效');
    const body = await parseJSONBody(request);
    fields(body, ['confirm']);
    if (body.confirm !== true)
      throw new ApiError(400, 'INVALID_FIELD', '永久删除 Token 需要明确确认');
    const now = Date.now();
    // One transaction records only the first transition, erases the credential,
    // and removes grants while retaining IDs referenced by historical links.
    const result = await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO audit(id,actor,action,entity_id,created_at) SELECT ?,?,'token.delete',id,? FROM tokens WHERE id=? AND deleted_at IS NULL",
      ).bind(crypto.randomUUID(), email, now, id),
      env.DB.prepare(
        'UPDATE tokens SET digest=?,revoked_at=COALESCE(revoked_at,?),deleted_at=? WHERE id=? AND deleted_at IS NULL',
      ).bind(`deleted:${id}`, now, now, id),
      env.DB.prepare(
        'DELETE FROM token_domains WHERE token_id=? AND EXISTS(SELECT 1 FROM tokens WHERE id=? AND deleted_at IS NOT NULL)',
      ).bind(id, id),
      env.DB.prepare('SELECT id,deleted_at FROM tokens WHERE id=?').bind(id),
    ]);
    const deleted = result[3].results[0] as { id: string; deleted_at: number | null } | undefined;
    if (!deleted) throw new ApiError(404, 'NOT_FOUND', 'Token 不存在');
    if (deleted.deleted_at === null)
      throw new ApiError(503, 'TEMPORARILY_UNAVAILABLE', 'Token 删除结果未确认，请刷新后核对');
    return ok({ deleted: true, id });
  }
  const id = url.pathname.slice('/api/admin/tokens/'.length);
  if (request.method === 'DELETE' && /^[a-f0-9-]{36}$/.test(id)) {
    const result = await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO audit(id,actor,action,entity_id,created_at) SELECT ?,?,'token.revoke',id,? FROM tokens WHERE id=? AND deleted_at IS NULL AND revoked_at IS NULL",
      ).bind(crypto.randomUUID(), email, Date.now(), id),
      env.DB.prepare(
        'UPDATE tokens SET revoked_at=COALESCE(revoked_at,?) WHERE id=? AND deleted_at IS NULL RETURNING id',
      ).bind(Date.now(), id),
    ]);
    if (!result[1].results.length) throw new ApiError(404, 'NOT_FOUND', 'Token 不存在');
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
        `SELECT ${field} AS name,SUM(count) AS count FROM daily_stats WHERE day>=? GROUP BY ${field} ORDER BY count DESC`,
    ),
    'SELECT COUNT(*) AS links,SUM(CASE WHEN enabled=1 AND (expires_at IS NULL OR expires_at>?) THEN 1 ELSE 0 END) AS active_links FROM links',
    'SELECT COALESCE(SUM(count),0) AS visits FROM daily_stats WHERE day>=?',
    'SELECT browser AS name,SUM(count) AS count FROM daily_browser_stats WHERE day>=? GROUP BY browser ORDER BY count DESC,browser',
  ];
  const result = await env.DB.batch(
    queries.map((sql, i) => env.DB.prepare(sql).bind(i === 4 ? Date.now() : since)),
  );
  return ok({
    daily: result[0].results,
    countries: result[1].results,
    devices: result[2].results,
    referrers: result[3].results,
    browsers: browserRankings(
      result[6].results as { name: string; count: number }[],
      Number((result[5].results[0] as { visits: number }).visits),
    ),
    totals: {
      ...(result[4].results[0] as Record<string, unknown>),
      ...(result[5].results[0] as Record<string, unknown>),
    },
    days,
    approximate: true,
    timezone: 'Asia/Singapore',
    daily_timezone: 'UTC',
    meaning:
      'GET 请求次数（包括确认页展示），可能包含机器人；后台异步聚合失败可能少计，非独立访客。地区来自边缘元数据，设备和浏览器由 UA 推断，未保存原始 UA；上线前的浏览器数据归为未知。',
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
  if (path === '/api/admin/error-pages/preview' && method === 'GET') return errorPagePreview();
  if (path === '/api/admin/error-pages') {
    if (method === 'GET') {
      const config = await settings(env);
      return ok(
        Object.fromEntries(
          ERROR_PAGE_KEYS.map((key) => [
            key,
            {
              mode: config[`${key}_mode`] === 'html' ? 'html' : 'text',
              text: config[key],
              html: config[`${key}_html`] ?? '',
            } satisfies ErrorPage,
          ]),
        ) as Record<ErrorPageKey, ErrorPage>,
      );
    }
    if (method === 'PUT') {
      // JSON can encode each source character as a six-byte Unicode escape.
      const body = await parseJSONBody(request, ERROR_PAGE_HTML_MAX_BYTES * 6 + 4096);
      fields(body, ['key', 'mode', 'text', 'html']);
      if (!isErrorPageKey(body.key) || (body.mode !== 'text' && body.mode !== 'html'))
        throw new ApiError(400, 'INVALID_FIELD', '错误页类型或模式无效');
      const copy = text(body.text, 500);
      if (!validErrorPageHtml(body.html) || (body.mode === 'html' && !body.html.trim()))
        throw new ApiError(
          400,
          'INVALID_FIELD',
          'HTML 须为非空文字，且 UTF-8 文件不能超过 128 KiB',
        );
      const entries = [
        [body.key, copy],
        [`${body.key}_mode`, body.mode],
        [`${body.key}_html`, body.html],
      ];
      await env.DB.batch([
        ...entries.map(([key, value]) =>
          env.DB.prepare(
            'INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
          ).bind(key, value),
        ),
        auditStatement(env, email, 'error_page.update', body.key, {
          mode: body.mode,
          html_bytes: new TextEncoder().encode(body.html).byteLength,
        }),
      ]);
      return ok({
        key: body.key,
        mode: body.mode,
        text: copy,
        html: body.html,
      } satisfies ErrorPage & {
        key: ErrorPageKey;
      });
    }
  }
  if (path === '/api/admin/links') {
    if (method === 'GET') return listLinks(env, url);
    if (method === 'POST') return createLink(request, env, email);
  }
  if (path === '/api/admin/links/bulk' && method === 'POST') return bulkLinks(request, env, email);
  if (/^\/api\/admin\/links\/[^/]+$/.test(path) && method === 'DELETE') {
    let id: string;
    try {
      id = decodeURIComponent(path.split('/').pop()!);
    } catch {
      throw new ApiError(400, 'INVALID_FIELD', '链接标识无效');
    }
    if (!LINK_ID.test(id)) throw new ApiError(400, 'INVALID_FIELD', '链接标识无效');
    const body = await parseJSONBody(request);
    fields(body, []);
    const results = await env.DB.batch([
      env.DB.prepare(
        'INSERT INTO deleted_links(slug,link_id,deleted_at,token_id,domain,idempotency_key,request_hash) SELECT slug,id,?,token_id,domain,idempotency_key,request_hash FROM links WHERE id=? ON CONFLICT DO NOTHING RETURNING slug',
      ).bind(Date.now(), id),
      env.DB.prepare(
        "INSERT INTO audit(id,actor,action,entity_id,detail,created_at) SELECT ?,?,'link.delete',id,json_object('slug',slug,'scope','all_public_prefixes'),? FROM links WHERE id=?",
      ).bind(crypto.randomUUID(), email, Date.now(), id),
      env.DB.prepare(
        'DELETE FROM links WHERE id=? AND EXISTS(SELECT 1 FROM deleted_links WHERE link_id=?)',
      ).bind(id, id),
    ]);
    const tomb = results[0].results[0] as { slug: string } | undefined;
    if (!tomb) throw new ApiError(404, 'NOT_FOUND', '链接不存在或已彻底删除');
    return ok({ deleted: true, slug: tomb.slug, all_public_prefixes: true });
  }
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
  if (path === '/api/admin/domains' || /^\/api\/admin\/domains\/[^/]+(?:\/verify)?$/.test(path))
    return domains(request, env, email, url);
  if (path === '/api/admin/tokens' || /^\/api\/admin\/tokens\/[^/]+(?:\/delete)?$/.test(path))
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
          const switchKey = key === 'backup_enabled' || key === 'migration_enabled';
          const min = switchKey || key.endsWith('_retention_days') ? 0 : 1;
          const max = switchKey
            ? 1
            : key.includes('rate_')
              ? 1000
              : key.endsWith('_interval_hours')
                ? 720
                : 3650;
          if (
            (typeof value !== 'string' && typeof value !== 'number') ||
            (typeof value === 'string' && !/^[0-9]{1,4}$/.test(value)) ||
            !Number.isInteger(num) ||
            num < min ||
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
        'SELECT id,created_at,status,size,records,completed_at,started_at,last_attempt_at,attempts,retry_at,last_error_code,duration_ms,snapshot_digest,object_digest FROM backup_jobs WHERE retired_at IS NULL ORDER BY created_at DESC LIMIT 100',
      ).all();
      return ok({ items: rows.results, schedule: await getBackupStatus(env), next_cursor: null });
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
  if (path === '/api/admin/export/download' && method === 'GET') {
    const links: ReturnType<typeof linkDTO>[] = [];
    const domains = await publicDomains(env);
    let start = Number.MAX_SAFE_INTEGER;
    while (true) {
      const rows = await env.DB.prepare(
        'SELECT rowid AS cursor,* FROM links WHERE rowid<? ORDER BY rowid DESC LIMIT 501',
      )
        .bind(start)
        .all<LinkRow & { cursor: number }>();
      const page = rows.results.slice(0, 500);
      links.push(...page.map((row) => linkDTO(row, domains)));
      if (rows.results.length <= 500) break;
      start = page[499].cursor;
    }
    const body = JSON.stringify({ schema_version: 1, links });
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `shortlink-export-${timestamp}-${crypto.randomUUID()}.json`;
    return new Response(body, {
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        'Content-Disposition': `attachment; filename="${filename}"`,
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
    const domains = await publicDomains(env);
    return new Response(
      JSON.stringify({
        schema_version: 1,
        links: page.map((row) => linkDTO(row, domains)),
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
  if (path === '/api/admin/audit/options' && method === 'GET')
    return ok(await auditFilterOptions(env));
  if (path === '/api/admin/audit' && method === 'GET') {
    const query = auditQuery(url);
    const result = await env.DB.prepare(query.sql)
      .bind(...query.params)
      .all<AuditRow>();
    return ok({
      items: await auditIdentities(env, result.results.slice(0, 50)),
      next_cursor: result.results.length > 50 ? String(result.results[49].cursor) : null,
      filtering_supported: true,
    });
  }
  if (path === '/api/admin/migrations' && method === 'GET') {
    const run = await env.DB.prepare(
      'SELECT id,state,processed,imported,unchanged,skipped,conflicts,unknown,digest,started_at,updated_at,completed_at,last_error_code,attempts,retry_at FROM legacy_migration_runs ORDER BY started_at DESC,id DESC LIMIT 1',
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
      schedule: await getMigrationStatus(env),
      next_cursor: null,
    });
  }
  throw new ApiError(404, 'NOT_FOUND', '接口不存在');
}
