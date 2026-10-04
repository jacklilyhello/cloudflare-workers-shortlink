import type { Env, LinkRow, TokenRow } from './types';
import { edgeFetch } from './edge-fetch';
import { encodeLegacySlug, isNewSlug, isSafeLegacySlug } from './legacy-slug.mjs';

const encoder = new TextEncoder();
const BODY_LIMIT = 16 * 1024;
const URL_LIMIT = 8 * 1024;
const SIGNATURE_NAMES = new Set([
  'sig',
  'signature',
  'hmac',
  'x-amz-signature',
  'x-goog-signature',
  'awsaccesskeyid',
  'key-pair-id',
  'policy',
]);

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public headers?: HeadersInit,
  ) {
    super(message);
  }
}

export function json(data: unknown, status = 200, headers?: HeadersInit): Response {
  const output = new Headers(headers);
  output.set('Content-Type', 'application/json; charset=utf-8');
  output.set('Cache-Control', 'no-store');
  output.set('X-Content-Type-Options', 'nosniff');
  return new Response(JSON.stringify(data), { status, headers: output });
}

export function errorResponse(error: unknown, requestId = crypto.randomUUID()): Response {
  const known = error instanceof ApiError;
  return json(
    {
      ok: false,
      error: {
        code: known ? error.code : 'INTERNAL_ERROR',
        message: known ? error.message : '服务暂时不可用',
      },
      request_id: requestId,
    },
    known ? error.status : 500,
    known ? error.headers : undefined,
  );
}

export async function hash(value: string): Promise<string> {
  return Array.from(
    new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value))),
    (byte) => byte.toString(16).padStart(2, '0'),
  ).join('');
}

function invalidJSON(): never {
  throw new ApiError(400, 'INVALID_JSON', '请求必须是有效 JSON，字段不能重复');
}

/** Parse JSON with member uniqueness at every depth, before property access. */
export function parseJSONStrict(text: string): unknown {
  let cursor = 0;
  const space = () => {
    while (/[\x20\t\r\n]/.test(text[cursor] ?? '') && cursor < text.length) cursor++;
  };
  const string = (): string => {
    if (text[cursor] !== '"') invalidJSON();
    const start = cursor++;
    while (cursor < text.length) {
      const character = text[cursor++];
      if (character === '"') {
        try {
          return JSON.parse(text.slice(start, cursor)) as string;
        } catch {
          invalidJSON();
        }
      }
      if (character === '\\') cursor++;
      else if (character.charCodeAt(0) < 32) invalidJSON();
    }
    invalidJSON();
  };
  const value = (depth: number): unknown => {
    if (depth > 32) invalidJSON();
    space();
    const character = text[cursor];
    if (character === '"') return string();
    if (character === '{') {
      cursor++;
      space();
      const object: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
      const keys = new Set<string>();
      if (text[cursor] === '}') {
        cursor++;
        return object;
      }
      while (true) {
        space();
        const key = string();
        if (keys.has(key)) invalidJSON();
        keys.add(key);
        space();
        if (text[cursor++] !== ':') invalidJSON();
        object[key] = value(depth + 1);
        space();
        const separator = text[cursor++];
        if (separator === '}') return object;
        if (separator !== ',') invalidJSON();
      }
    }
    if (character === '[') {
      cursor++;
      space();
      const array: unknown[] = [];
      if (text[cursor] === ']') {
        cursor++;
        return array;
      }
      while (true) {
        array.push(value(depth + 1));
        space();
        const separator = text[cursor++];
        if (separator === ']') return array;
        if (separator !== ',') invalidJSON();
      }
    }
    const literal = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(
      text.slice(cursor),
    );
    if (!literal) invalidJSON();
    cursor += literal[0].length;
    const parsed: unknown = JSON.parse(literal[0]);
    if (typeof parsed === 'number' && !Number.isFinite(parsed)) invalidJSON();
    return parsed;
  };
  const parsed = value(0);
  space();
  if (cursor !== text.length) invalidJSON();
  return parsed;
}

export async function parseJSONBody(
  request: Request,
  limit = BODY_LIMIT,
): Promise<Record<string, unknown>> {
  const contentType = request.headers.get('Content-Type') ?? '';
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?\s*$/i.test(contentType)) {
    throw new ApiError(415, 'UNSUPPORTED_MEDIA_TYPE', '仅接受 application/json');
  }
  const statedLength = request.headers.get('Content-Length');
  if (statedLength && (!/^\d+$/.test(statedLength) || Number(statedLength) > limit)) {
    throw new ApiError(413, 'BODY_TOO_LARGE', '请求体过大');
  }
  if (!request.body) invalidJSON();
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      length += chunk.value.byteLength;
      if (length > limit) {
        await reader.cancel();
        throw new ApiError(413, 'BODY_TOO_LARGE', '请求体过大');
      }
      chunks.push(chunk.value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    invalidJSON();
  }
  const body = parseJSONStrict(text);
  if (body === null || Array.isArray(body) || typeof body !== 'object') invalidJSON();
  return body as Record<string, unknown>;
}

export function validateDomain(value: unknown): string {
  if (
    typeof value !== 'string' ||
    value.length > 253 ||
    !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(
      value,
    )
  ) {
    throw new ApiError(400, 'INVALID_DOMAIN', '域名必须是已登记的小写 hostname');
  }
  return value;
}

export function validateSlug(value: unknown): string {
  if (!isNewSlug(value)) {
    throw new ApiError(
      400,
      'INVALID_SLUG',
      '短码须为 1–64 个英文字母、数字、下划线或连字符，且不能是保留路径',
    );
  }
  return value;
}

export function validateUrl(value: unknown): string {
  if (
    typeof value !== 'string' ||
    !value ||
    !/^https?:\/\//i.test(value) ||
    /[\u0000-\u0020\u007f\\]/.test(value) ||
    /%(?![A-Fa-f0-9]{2})/.test(value) ||
    /[\ud800-\udfff]/u.test(value)
  ) {
    throw new ApiError(400, 'INVALID_URL', '请输入完整且有效的 HTTP 或 HTTPS 链接');
  }
  if (encoder.encode(value).byteLength > URL_LIMIT)
    throw new ApiError(413, 'URL_TOO_LONG', '链接超过 8 KiB');
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new ApiError(400, 'INVALID_URL', '链接格式无效');
  }
  const authority = /^https?:\/\/([^/?#]+)/i.exec(value);
  if (
    !authority ||
    authority[1].includes('@') ||
    !parsed.hostname ||
    parsed.username ||
    parsed.password ||
    !['https:', 'http:'].includes(parsed.protocol)
  ) {
    throw new ApiError(400, 'INVALID_URL', '链接不能包含用户名或密码');
  }
  return value;
}

function randomSlug(): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';
  return Array.from(crypto.getRandomValues(new Uint8Array(10)), (byte) => alphabet[byte & 63]).join(
    '',
  );
}

export async function settingNumber(
  env: Env,
  key: string,
  fallback: number,
  minimum = 1,
  maximum = 1000,
): Promise<number> {
  const row = await env.DB.prepare('SELECT value FROM settings WHERE key = ?')
    .bind(key)
    .first<{ value: string }>();
  const value = Number(row?.value);
  return Number.isInteger(value) && value >= minimum && value <= maximum ? value : fallback;
}

async function rateLimit(env: Env, key: string, limit: number, now: number): Promise<void> {
  const window = Math.floor(now / 60_000);
  const results = await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO rate_windows(key, window, count) VALUES (?, ?, 1)
      ON CONFLICT(key, window) DO UPDATE SET count = count + 1 RETURNING count`,
    ).bind(key, window),
    env.DB.prepare('DELETE FROM rate_windows WHERE window < ?').bind(window - 60),
  ]);
  const count = (results[0].results[0] as { count: number } | undefined)?.count;
  if (count === undefined) throw new ApiError(503, 'TEMPORARILY_UNAVAILABLE', '限流服务暂时不可用');
  if (count > limit)
    throw new ApiError(429, 'RATE_LIMITED', '创建过于频繁，请稍后再试', {
      'Retry-After': String(60 - (Math.floor(now / 1000) % 60)),
    });
}

async function authenticateToken(request: Request, env: Env, now: number): Promise<TokenRow> {
  const header = request.headers.get('Authorization');
  if (!header) throw new ApiError(401, 'TOKEN_REQUIRED', '需要 Bearer 业务 Token');
  const match = /^Bearer ([A-Za-z0-9_-]{32,128})$/i.exec(header);
  if (!match) throw new ApiError(401, 'TOKEN_INVALID', '业务 Token 无效');
  const token = await env.DB.prepare('SELECT * FROM tokens WHERE digest = ?')
    .bind(await hash(match[1]))
    .first<TokenRow>();
  if (
    !token ||
    token.revoked_at !== null ||
    (token.expires_at !== null && token.expires_at <= now)
  ) {
    throw new ApiError(401, 'TOKEN_INVALID', '业务 Token 无效');
  }
  return token;
}

async function verifyTurnstile(
  request: Request,
  env: Env,
  body: Record<string, unknown>,
): Promise<void> {
  const origin = request.headers.get('Origin');
  if (origin !== new URL(request.url).origin)
    throw new ApiError(403, 'ORIGIN_FORBIDDEN', '请求来源无效');
  const token = body.turnstile_token;
  if (typeof token !== 'string' || token.length < 1 || token.length > 2048)
    throw new ApiError(403, 'TURNSTILE_FAILED', '请完成验证码');
  if (!env.TURNSTILE_SECRET_KEY)
    throw new ApiError(503, 'TEMPORARILY_UNAVAILABLE', '验证码服务尚未配置');
  const payload = new URLSearchParams({ secret: env.TURNSTILE_SECRET_KEY, response: token });
  const remoteIP = request.headers.get('CF-Connecting-IP');
  if (remoteIP) payload.set('remoteip', remoteIP);
  let response: Response;
  try {
    response = await edgeFetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: payload,
      signal: AbortSignal.timeout(8000),
    });
  } catch {
    throw new ApiError(503, 'TEMPORARILY_UNAVAILABLE', '验证码服务暂时不可用');
  }
  if (
    !response.ok ||
    !response.headers.get('Content-Type')?.toLowerCase().includes('application/json')
  ) {
    throw new ApiError(503, 'TEMPORARILY_UNAVAILABLE', '验证码服务暂时不可用');
  }
  let result: { success?: boolean; hostname?: string; action?: string };
  try {
    result = await response.json();
  } catch {
    throw new ApiError(503, 'TEMPORARILY_UNAVAILABLE', '验证码服务暂时不可用');
  }
  if (result === null || typeof result !== 'object' || Array.isArray(result)) {
    throw new ApiError(503, 'TEMPORARILY_UNAVAILABLE', '验证码服务暂时不可用');
  }
  if (
    result.success !== true ||
    result.hostname !== new URL(request.url).hostname ||
    result.action !== 'create'
  ) {
    throw new ApiError(403, 'TURNSTILE_FAILED', '验证码无效或已过期，请重新验证');
  }
}

function createResponse(
  link: Pick<LinkRow, 'slug' | 'domain'>,
  requestId: string,
  replayed = false,
): Response {
  return json(
    {
      ok: true,
      data: {
        slug: link.slug,
        domain: link.domain,
        short_url: `https://${link.domain}/${encodeLegacySlug(link.slug)}`,
      },
      request_id: requestId,
    },
    replayed ? 200 : 201,
    replayed ? { 'Idempotency-Replayed': 'true' } : undefined,
  );
}

export async function handleCreate(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  mode: 'machine' | 'anonymous',
): Promise<Response> {
  const requestId = crypto.randomUUID();
  try {
    const host = new URL(request.url).hostname;
    if (
      (mode === 'machine' && host !== env.ADMIN_HOSTNAME) ||
      (mode === 'anonymous' && host !== env.PUBLIC_HOSTNAME && host !== env.WORKERS_DEV_HOSTNAME)
    ) {
      throw new ApiError(403, 'HOST_FORBIDDEN', '该主机不提供此接口');
    }
    if (request.method !== 'POST')
      throw new ApiError(405, 'METHOD_NOT_ALLOWED', '仅接受 POST', { Allow: 'POST' });
    const now = Date.now();
    const token = mode === 'machine' ? await authenticateToken(request, env, now) : null;
    const body = await parseJSONBody(request);
    const accepted = new Set(
      mode === 'machine' ? ['url', 'domain', 'slug'] : ['url', 'slug', 'turnstile_token'],
    );
    if (Object.keys(body).some((field) => !accepted.has(field)))
      throw new ApiError(400, 'UNKNOWN_FIELD', '请求包含不允许的字段');
    const target = validateUrl(body.url);
    const domain = validateDomain(mode === 'machine' ? body.domain : env.PUBLIC_HOSTNAME);
    const customSlug = Object.hasOwn(body, 'slug') ? validateSlug(body.slug) : null;
    if (domain !== env.PUBLIC_HOSTNAME) throw new ApiError(403, 'DOMAIN_FORBIDDEN', '该域名未授权');
    const registered = await env.DB.prepare(
      'SELECT hostname FROM domains WHERE hostname = ? AND enabled = 1 AND bound = 1',
    )
      .bind(domain)
      .first();
    if (!registered) throw new ApiError(403, 'DOMAIN_FORBIDDEN', '该域名未授权');
    if (token) {
      const permission = await env.DB.prepare(
        'SELECT token_id FROM token_domains WHERE token_id = ? AND domain = ?',
      )
        .bind(token.id, domain)
        .first();
      if (!permission) throw new ApiError(403, 'DOMAIN_FORBIDDEN', '该域名未授权');
    }
    const idempotencyKey = request.headers.get('Idempotency-Key');
    if (
      idempotencyKey !== null &&
      (mode !== 'machine' || !/^[A-Za-z0-9._:-]{1,128}$/.test(idempotencyKey))
    ) {
      throw new ApiError(
        400,
        'INVALID_FIELD',
        '幂等键仅供机器接口使用，须为 1–128 个安全 ASCII 字符',
      );
    }
    const requestHash =
      idempotencyKey === null ? null : await hash(JSON.stringify([domain, target, customSlug]));
    if (token && idempotencyKey !== null) {
      const previous = await env.DB.prepare(
        'SELECT * FROM links WHERE token_id = ? AND domain = ? AND idempotency_key = ?',
      )
        .bind(token.id, domain, idempotencyKey)
        .first<LinkRow>();
      if (previous) {
        if (previous.request_hash !== requestHash)
          throw new ApiError(409, 'IDEMPOTENCY_CONFLICT', '该幂等键已用于不同请求');
        return createResponse(previous, requestId, true);
      }
    }
    if (token) {
      await rateLimit(env, `token:${token.id}`, token.rate_per_minute, now);
    } else {
      // CF-Connecting-IP is platform supplied, used only as a one-window hash, never an allowlist.
      const connection = request.headers.get('CF-Connecting-IP') ?? 'unknown';
      await rateLimit(
        env,
        `anonymous:${await hash(`${Math.floor(now / 60_000)}:${connection}`)}`,
        await settingNumber(env, 'anonymous_rate_per_minute', 10),
        now,
      );
      await verifyTurnstile(request, env, body);
    }
    await rateLimit(
      env,
      `domain:${domain}`,
      await settingNumber(env, 'domain_rate_per_minute', 120),
      now,
    );
    for (let attempt = 0; attempt < (customSlug === null ? 8 : 1); attempt++) {
      const slug = customSlug ?? randomSlug();
      if (!isNewSlug(slug)) continue;
      const id = crypto.randomUUID();
      // Permission and token status are checked again inside the insert, after asynchronous validation.
      const permissions = token
        ? `AND EXISTS (SELECT 1 FROM tokens t JOIN token_domains td ON td.token_id = t.id
        WHERE t.id = ? AND td.domain = ? AND t.revoked_at IS NULL AND (t.expires_at IS NULL OR t.expires_at > ?))`
        : '';
      const values: (string | number | null)[] = [
        id,
        domain,
        slug,
        target,
        now,
        mode,
        token?.id ?? 'anonymous',
        token?.id ?? null,
        idempotencyKey,
        requestHash,
        domain,
      ];
      if (token) values.push(token.id, domain, Date.now());
      const results = await env.DB.batch([
        env.DB.prepare(
          `INSERT INTO links
        (id, domain, slug, url, created_at, source, creator, token_id, idempotency_key, request_hash)
        SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        WHERE EXISTS (SELECT 1 FROM domains WHERE hostname = ? AND enabled = 1 AND bound = 1) ${permissions}
        ON CONFLICT DO NOTHING RETURNING id`,
        ).bind(...values),
        env.DB.prepare(
          `INSERT INTO audit(id, actor, action, entity_id, created_at)
          SELECT ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM links WHERE id = ?)`,
        ).bind(crypto.randomUUID(), token?.id ?? 'anonymous', 'link.create', id, now, id),
      ]);
      if (results[0].results.length) {
        return createResponse({ domain, slug }, requestId);
      }
      if (token && idempotencyKey !== null) {
        const previous = await env.DB.prepare(
          'SELECT * FROM links WHERE token_id = ? AND domain = ? AND idempotency_key = ?',
        )
          .bind(token.id, domain, idempotencyKey)
          .first<LinkRow>();
        if (previous) {
          if (previous.request_hash !== requestHash)
            throw new ApiError(409, 'IDEMPOTENCY_CONFLICT', '该幂等键已用于不同请求');
          return createResponse(previous, requestId, true);
        }
      }
      const occupied = await env.DB.prepare('SELECT id FROM links WHERE domain = ? AND slug = ?')
        .bind(domain, slug)
        .first();
      if (occupied && customSlug !== null) throw new ApiError(409, 'SLUG_CONFLICT', '短码已被占用');
      if (!occupied) throw new ApiError(403, 'DOMAIN_FORBIDDEN', '创建权限已失效');
    }
    throw new ApiError(503, 'SLUG_GENERATION_EXHAUSTED', '无法分配短码，请稍后重试');
  } catch (error) {
    return errorResponse(error, requestId);
  }
}

/** Preserve original target query bytes; inspect decoded names exactly once. */
export function mergeQuery(
  target: string,
  incoming: string,
  policy: 'merge' | 'preserve' = 'merge',
): string {
  if (policy === 'preserve' || !incoming || incoming === '?') return target;
  if (encoder.encode(incoming).byteLength > URL_LIMIT || /%(?![A-Fa-f0-9]{2})/.test(incoming)) {
    throw new ApiError(400, 'INVALID_QUERY', '附加参数过长或编码无效');
  }
  const fragmentIndex = target.indexOf('#');
  const fragment = fragmentIndex < 0 ? '' : target.slice(fragmentIndex);
  const beforeFragment = fragmentIndex < 0 ? target : target.slice(0, fragmentIndex);
  const questionIndex = beforeFragment.indexOf('?');
  const originalQuery = questionIndex < 0 ? '' : beforeFragment.slice(questionIndex + 1);
  const names = new Set(Array.from(new URLSearchParams(originalQuery).keys()));
  const additions = incoming
    .replace(/^\?/, '')
    .split('&')
    .filter((part) => {
      if (!part) return false;
      const name = new URLSearchParams(part).keys().next().value as string | undefined;
      return name !== undefined && !names.has(name);
    });
  if (additions.length === 0) return target;
  if (Array.from(names).some((name) => SIGNATURE_NAMES.has(name.toLowerCase()))) {
    throw new ApiError(400, 'SIGNED_QUERY_REJECTED', '此链接使用签名，不能添加新参数');
  }
  return `${beforeFragment}${questionIndex < 0 ? '?' : originalQuery === '' || beforeFragment.endsWith('&') ? '' : '&'}${additions.join('&')}${fragment}`;
}

function escapeHtml(value: string): string {
  return value.replace(
    /[&<>"']/g,
    (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]!,
  );
}

function htmlPage(title: string, message: string, status: number, link?: string): Response {
  return new Response(
    `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title><link rel="stylesheet" href="/status.css"><main><h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p>${link ? `<a class="button" href="${escapeHtml(link)}" rel="noreferrer noopener">继续访问</a>` : '<a href="/">返回首页</a>'}</main></html>`,
    {
      status,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        'Content-Security-Policy':
          "default-src 'none'; style-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        'Referrer-Policy': 'no-referrer',
      },
    },
  );
}

export async function applicationError(
  env: Env,
  status: number,
  key?: string,
  fallback?: string,
): Promise<Response> {
  const title =
    status === 403
      ? '无法访问'
      : status === 404
        ? '链接不存在'
        : status === 410
          ? '链接已停用'
          : '暂时无法访问';
  let message = fallback ?? title;
  try {
    const setting = await env.DB.prepare('SELECT value FROM settings WHERE key = ?')
      .bind(key ?? `error_${status}`)
      .first<{ value: string }>();
    if (setting?.value) message = setting.value.slice(0, 500);
  } catch {
    /* The fallback works when D1 is unavailable. */
  }
  return htmlPage(title, message, status);
}

async function recordClick(request: Request, env: Env, link: LinkRow): Promise<void> {
  const day = new Date().toISOString().slice(0, 10);
  const cf = request.cf as { country?: string } | undefined;
  const country = cf?.country && /^[A-Z]{2}$/.test(cf.country) ? cf.country : 'XX';
  const agent = request.headers.get('User-Agent') ?? '';
  const device = /bot|crawler|spider|preview/i.test(agent)
    ? 'bot'
    : /tablet|ipad/i.test(agent)
      ? 'tablet'
      : /mobile|android|iphone/i.test(agent)
        ? 'mobile'
        : 'desktop';
  let referrer = 'direct';
  try {
    const parsed = new URL(request.headers.get('Referer') ?? '');
    if (
      ['http:', 'https:'].includes(parsed.protocol) &&
      parsed.hostname.length <= 253 &&
      !/^\[|^\d+(?:\.\d+){3}$/.test(parsed.hostname)
    )
      referrer = parsed.hostname;
  } catch {
    /* Direct, IP literal, or invalid referrer. */
  }
  // Bound hostile Referer cardinality to 100 named hosts per domain/day. Overflow is grouped.
  await env.DB.prepare(
    `INSERT INTO daily_stats(day, domain, slug, country, device, referrer, count)
    SELECT ?, ?, ?, ?, ?, CASE
      WHEN ? = 'direct' OR EXISTS (SELECT 1 FROM daily_stats WHERE day = ? AND domain = ? AND referrer = ?)
        OR (SELECT COUNT(DISTINCT referrer) FROM daily_stats WHERE day = ? AND domain = ? AND referrer NOT IN ('direct', 'other')) < 100
      THEN ? ELSE 'other' END, 1
    ON CONFLICT(day, domain, slug, country, device, referrer) DO UPDATE SET count = count + 1`,
  )
    .bind(
      day,
      link.domain,
      link.slug,
      country,
      device,
      referrer,
      day,
      link.domain,
      referrer,
      day,
      link.domain,
      referrer,
    )
    .run();
}

// HTTP header transport requires ASCII. Existing percent escapes/query order remain unchanged.
export function locationHeader(target: string): string {
  const authority = /^(https?:\/\/)([^/?#]+)/i.exec(target);
  if (!authority) throw new ApiError(400, 'INVALID_URL', '链接格式无效');
  const parsed = new URL(target);
  const originalPort = /:(\d+)$/.exec(authority[2]);
  const host = `${parsed.hostname}${originalPort ? `:${originalPort[1]}` : ''}`;
  const withHost = /[^\x00-\x7f]/.test(authority[2])
    ? authority[1] + host + target.slice(authority[0].length)
    : target;
  return withHost.replace(/[^\x00-\x7f]/gu, (character) => encodeURIComponent(character));
}

export async function handleRedirect(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  domain: string,
  slug: string,
  requiresMigration = false,
): Promise<Response> {
  try {
    if (!isNewSlug(slug) && !isSafeLegacySlug(slug)) return applicationError(env, 404);
    const migrationOnly = requiresMigration || !isNewSlug(slug);
    if (migrationOnly && !isSafeLegacySlug(slug)) return applicationError(env, 404);
    const registered = await env.DB.prepare(
      'SELECT hostname FROM domains WHERE hostname = ? AND enabled = 1 AND bound = 1',
    )
      .bind(domain)
      .first();
    if (!registered || domain !== env.PUBLIC_HOSTNAME) return applicationError(env, 404);
    const link = await env.DB.prepare(
      "SELECT * FROM links WHERE domain = ? AND slug = ? AND (? = 0 OR source = 'migration')",
    )
      .bind(domain, slug, migrationOnly ? 1 : 0)
      .first<LinkRow>();
    if (!link) return applicationError(env, 404);
    if (!link.enabled || (link.expires_at !== null && link.expires_at <= Date.now()))
      return applicationError(env, 410, 'error_disabled');
    const target = mergeQuery(link.url, new URL(request.url).search, link.query_mode);
    if (request.method === 'GET')
      ctx.waitUntil(recordClick(request, env, link).catch(() => undefined));
    if (link.confirm_enabled)
      return htmlPage('即将前往其他网站', link.confirm_text || '请确认后继续访问。', 200, target);
    return new Response(null, {
      status: 302,
      headers: {
        Location: locationHeader(target),
        'Cache-Control': 'no-store',
        'Referrer-Policy': 'no-referrer',
        'X-Content-Type-Options': 'nosniff',
      },
    });
  } catch (error) {
    if (error instanceof ApiError)
      return applicationError(
        env,
        error.code === 'INVALID_SLUG' ? 404 : error.status,
        undefined,
        error.message,
      );
    return applicationError(env, 500);
  }
}
