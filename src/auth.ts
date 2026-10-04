import { createRemoteJWKSet, customFetch, jwtVerify, type JWTVerifyGetKey } from 'jose';
import type { Env } from './types';

export const ADMIN_EMAILS = ['lilyyaloveyou@gmail.com', 'admin@888888.mom'];
const TEAM = 'lilyya.cloudflareaccess.com';
let remoteKeys: JWTVerifyGetKey | undefined;

export class AdminError extends Error {
  constructor(
    public code: string,
    public status = 403,
  ) {
    super(code);
  }
}
export async function csrfToken(assertion: string): Promise<string> {
  const bytes = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(`shortlink-csrf-v1:${assertion}`),
  );
  return Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, '0')).join('');
}
export function checkAdminConfiguration(env: Env): void {
  const configured = env.ADMIN_EMAILS.split(',').sort();
  if (
    env.ADMIN_HOSTNAME !== 'link-admin.lily.lat' ||
    env.CF_ACCESS_TEAM_DOMAIN !== TEAM ||
    configured.join(',') !== [...ADMIN_EMAILS].sort().join(',') ||
    !env.CF_ACCESS_AUD ||
    !/^[a-f0-9]{64}$/i.test(env.CF_ACCESS_AUD)
  )
    throw new AdminError('ADMIN_NOT_CONFIGURED', 503);
}
// Tests pass an in-memory public JWKS resolver to this function. Routing never accepts
// a resolver, a development auth switch, an email header, or an application token.
export async function authorizeAdmin(request: Request, env: Env, testKeys?: JWTVerifyGetKey) {
  checkAdminConfiguration(env);
  if (new URL(request.url).hostname !== env.ADMIN_HOSTNAME) throw new AdminError('HOST_FORBIDDEN');
  const assertion = request.headers.get('Cf-Access-Jwt-Assertion');
  if (!assertion || assertion.length > 8192) throw new AdminError('ADMIN_REQUIRED', 401);
  if (!remoteKeys && !testKeys)
    remoteKeys = createRemoteJWKSet(new URL(`https://${TEAM}/cdn-cgi/access/certs`), {
      timeoutDuration: 5000,
      cooldownDuration: 30000,
      cacheMaxAge: 3600000,
      [customFetch]: (input, init) => fetch(input, { ...init, redirect: 'error' }),
    });
  try {
    const { payload } = await jwtVerify(assertion, testKeys || remoteKeys!, {
      algorithms: ['RS256'],
      issuer: `https://${TEAM}`,
      audience: env.CF_ACCESS_AUD,
      requiredClaims: ['iss', 'aud', 'exp', 'iat', 'sub', 'email'],
      maxTokenAge: '24h',
      clockTolerance: 5,
    });
    if (
      typeof payload.email !== 'string' ||
      !ADMIN_EMAILS.includes(payload.email) ||
      payload.type !== 'app'
    )
      throw new AdminError('ADMIN_FORBIDDEN');
    const csrf = await csrfToken(assertion);
    if (!['GET', 'HEAD'].includes(request.method)) {
      if (
        request.headers.get('Origin') !== `https://${env.ADMIN_HOSTNAME}` ||
        request.headers.get('Sec-Fetch-Site') === 'cross-site' ||
        request.headers.get('X-CSRF-Token') !== csrf
      )
        throw new AdminError('CSRF_REJECTED');
    }
    return { email: payload.email, csrf };
  } catch (error) {
    if (error instanceof AdminError) throw error;
    throw new AdminError('ADMIN_INVALID', 401);
  }
}
