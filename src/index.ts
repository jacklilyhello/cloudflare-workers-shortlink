import type { Env } from './types';
import {
  ApiError,
  applicationError,
  errorResponse,
  handleCreate,
  handleRedirect,
  json,
} from './core';
import { AdminError, authorizeAdmin } from './auth';
import { handleAdmin } from './admin';
import { maintenance } from './maintenance';
import { decodeLegacyPath } from './legacy-slug.mjs';

const PUBLIC = 'test.gfw.mom',
  ADMIN = 'link-admin.lily.lat';
const CSP =
  "default-src 'none'; script-src 'self' https://challenges.cloudflare.com; style-src 'self'; img-src 'self' data:; connect-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'";
function secured(response: Response, isAdmin: boolean): Response {
  const headers = new Headers(response.headers);
  headers.set('Content-Security-Policy', CSP);
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('Referrer-Policy', 'no-referrer');
  headers.set('X-Frame-Options', 'DENY');
  headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  headers.set('Strict-Transport-Security', 'max-age=31536000');
  if (isAdmin) headers.set('Cache-Control', 'no-store');
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}
async function asset(request: Request, env: Env, index = false): Promise<Response> {
  if (!env.ASSETS) throw new ApiError(503, 'TEMPORARILY_UNAVAILABLE', '页面尚未构建');
  const url = new URL(request.url);
  if (index) url.pathname = '/index.html';
  const response = await env.ASSETS.fetch(new Request(url, request));
  const headers = new Headers(response.headers);
  if (index) headers.set('Cache-Control', 'no-store');
  return new Response(response.body, { status: response.status, headers });
}
export async function route(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(request.url),
    host = url.hostname,
    path = url.pathname;
  if (
    env.PUBLIC_HOSTNAME !== PUBLIC ||
    env.ADMIN_HOSTNAME !== ADMIN ||
    !['test', 'production'].includes(env.APP_ENV)
  )
    throw new ApiError(503, 'CONFIGURATION_INVALID', '环境配置未通过保护校验');
  if (url.protocol !== 'https:') throw new ApiError(403, 'HTTPS_REQUIRED', '需要 HTTPS');
  const adminHost = host === ADMIN;
  const workersDev =
    !!env.WORKERS_DEV_HOSTNAME &&
    /^shortlink-new\.[a-z0-9-]+\.workers\.dev$/.test(env.WORKERS_DEV_HOSTNAME) &&
    host === env.WORKERS_DEV_HOSTNAME;
  if (!adminHost && host !== PUBLIC && !workersDev)
    throw new ApiError(403, 'HOST_FORBIDDEN', '未授权的主机');
  if (path === '/api/shorten') {
    if (!adminHost) throw new ApiError(403, 'HOST_FORBIDDEN', '该主机不提供机器接口');
    return handleCreate(request, env, ctx, 'machine');
  }
  if (adminHost) {
    // Every path except the exact machine endpoint needs a verified Access JWT,
    // even if an upstream Access path match is unexpectedly broad.
    const identity = await authorizeAdmin(request, env);
    if (path.startsWith('/api/admin/')) return handleAdmin(request, env, ctx, identity);
    if (request.method !== 'GET' && request.method !== 'HEAD')
      throw new ApiError(405, 'METHOD_NOT_ALLOWED', '方法不支持', { Allow: 'GET, HEAD' });
    if (path === '/')
      return new Response(null, {
        status: 302,
        headers: { Location: '/admin', 'Cache-Control': 'no-store' },
      });
    if (path === '/admin' || path === '/admin/') return asset(request, env, true);
    if (/^\/assets\/[A-Za-z0-9_.-]+$/.test(path) || path === '/status.css')
      return asset(request, env);
    throw new ApiError(404, 'NOT_FOUND', '路径不存在');
  }
  if (path.startsWith('/api/admin') || path === '/admin' || path.startsWith('/admin/'))
    throw new ApiError(403, 'HOST_FORBIDDEN', '该主机不提供管理入口');
  if (path === '/api/public/config') {
    if (request.method !== 'GET')
      throw new ApiError(405, 'METHOD_NOT_ALLOWED', '仅接受 GET', { Allow: 'GET' });
    return json({
      ok: true,
      data: { site_key: env.TURNSTILE_SITE_KEY, domain: PUBLIC },
      request_id: crypto.randomUUID(),
    });
  }
  if (path === '/api/public/shorten') return handleCreate(request, env, ctx, 'anonymous');
  if (path === '/api' || path.startsWith('/api/'))
    throw new ApiError(404, 'NOT_FOUND', '路径不存在');
  if (request.method !== 'GET' && request.method !== 'HEAD')
    throw new ApiError(405, 'METHOD_NOT_ALLOWED', '仅接受 GET 或 HEAD', { Allow: 'GET, HEAD' });
  if (path === '/') return asset(request, env, true);
  if (/^\/assets\/[A-Za-z0-9_.-]+$/.test(path) || path === '/status.css')
    return asset(request, env);
  if (path === '/robots.txt')
    return new Response('User-agent: *\nDisallow: /api/\n', {
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    });
  const legacyPath = decodeLegacyPath(path);
  if (legacyPath)
    return handleRedirect(request, env, ctx, PUBLIC, legacyPath.slug, legacyPath.requiresMigration);
  return applicationError(env, 404);
}
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    let response: Response;
    try {
      response = await route(request, env, ctx);
    } catch (error) {
      const safe =
        error instanceof AdminError
          ? new ApiError(error.status, error.code, '管理员身份验证未通过')
          : error;
      if (new URL(request.url).pathname.startsWith('/api')) response = errorResponse(safe);
      else
        response = await applicationError(env, safe instanceof ApiError ? safe.status : 500).catch(
          () => new Response('Service unavailable', { status: 503 }),
        );
    }
    if (request.method === 'HEAD')
      response = new Response(null, { status: response.status, headers: response.headers });
    return secured(response, new URL(request.url).hostname === ADMIN);
  },
  async scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    if (env.PUBLIC_HOSTNAME !== PUBLIC || env.ADMIN_HOSTNAME !== ADMIN) return;
    ctx.waitUntil(maintenance(env));
  },
} satisfies ExportedHandler<Env>;
