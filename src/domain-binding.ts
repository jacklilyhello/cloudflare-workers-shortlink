import type { Env, DomainRow } from './types';
import { ApiError, isPublicHostname, validateDomain } from './core';
import { edgeFetch } from './edge-fetch';

const ACCOUNT = '9431815bdb8beb2272f6668e06b7d3be';
const WORKER = 'shortlink-new';

async function readJSON(url: string, headers?: HeadersInit): Promise<any> {
  let response: Response;
  try {
    response = await edgeFetch(url, {
      method: 'GET',
      headers,
      redirect: 'error',
      signal: AbortSignal.timeout(8000),
    });
  } catch {
    throw new ApiError(503, 'BINDING_NETWORK_FAILED', '绑定核验网络读取失败，请稍后刷新');
  }
  if (!response.ok)
    throw new ApiError(
      503,
      response.status === 401 || response.status === 403
        ? 'BINDING_READ_PERMISSION'
        : 'BINDING_READ_FAILED',
      '绑定核验读取失败；不能据此判断域名不存在',
    );
  if (!response.headers.get('Content-Type')?.toLowerCase().includes('application/json'))
    throw new ApiError(503, 'BINDING_READ_FAILED', '绑定核验未取得有效 JSON 响应');
  const reader = response.body?.getReader();
  if (!reader) throw new ApiError(503, 'BINDING_READ_FAILED', '绑定核验响应为空');
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      length += part.value.byteLength;
      if (length > 2 * 1024 * 1024) {
        await reader.cancel();
        throw new ApiError(503, 'BINDING_READ_FAILED', '绑定核验响应超限');
      }
      chunks.push(part.value);
    }
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(503, 'BINDING_NETWORK_FAILED', '绑定核验网络读取中断');
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const part of chunks) {
    bytes.set(part, offset);
    offset += part.length;
  }
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
  } catch {
    throw new ApiError(503, 'BINDING_READ_FAILED', '绑定核验响应无法解析');
  }
}

/** Only official GETs with an independently qualified read credential; never creates CF resources. */
export async function verifyDomainBinding(
  env: Env,
  hostname: string,
): Promise<{
  binding_state: DomainRow['binding_state'];
  bound: boolean;
  binding_error: string | null;
}> {
  validateDomain(hostname);
  if (!isPublicHostname(hostname, env))
    throw new ApiError(400, 'INVALID_DOMAIN', '此主机不能作为公共短链入口');
  if (
    !env.DOMAIN_BINDING_READ_TOKEN ||
    env.CLOUDFLARE_ACCOUNT_ID !== ACCOUNT ||
    env.WORKER_NAME !== WORKER ||
    !env.RESOURCE_OWNER_ID ||
    !env.D1_DATABASE_ID
  )
    throw new ApiError(503, 'BINDING_READ_NOT_CONFIGURED', '独立的域名绑定只读凭据尚未配置');
  const ownership = await env.DB.prepare(
    'SELECT owner_id,account_id,worker FROM delivery_ownership WHERE singleton=1',
  ).first<{ owner_id: string; account_id: string; worker: string }>();
  if (
    ownership?.owner_id !== env.RESOURCE_OWNER_ID ||
    ownership.account_id !== ACCOUNT ||
    ownership.worker !== WORKER
  )
    throw new ApiError(503, 'BINDING_OWNERSHIP_FAILED', '新系统资源归属核验失败');
  const prefix = `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT}`;
  const headers = { Authorization: `Bearer ${env.DOMAIN_BINDING_READ_TOKEN}` };
  const custom = await readJSON(
    `${prefix}/workers/domains?hostname=${encodeURIComponent(hostname)}`,
    headers,
  );
  if (custom?.success !== true || !Array.isArray(custom.result))
    throw new ApiError(503, 'BINDING_READ_FAILED', 'CF Custom Domain 读取失败');
  if (custom.result_info?.total_pages > 1)
    throw new ApiError(503, 'BINDING_READ_FAILED', '绑定核验结果未完整读取');
  const exact = custom.result.filter((row: any) => row?.hostname === hostname);
  if (!exact.length) return { binding_state: 'unbound', bound: false, binding_error: null };
  if (
    exact.length !== 1 ||
    exact[0].service !== WORKER ||
    exact[0].environment !== 'production' ||
    typeof exact[0].zone_id !== 'string' ||
    typeof exact[0].id !== 'string'
  )
    throw new ApiError(409, 'BINDING_WRONG_WORKER', '该域名没有绑定到本项目正确的 Worker');
  if (exact[0].enabled === false || typeof exact[0].cert_id !== 'string' || !exact[0].cert_id)
    return { binding_state: 'pending', bound: false, binding_error: 'BINDING_SERVICE_PENDING' };
  const worker = await readJSON(`${prefix}/workers/scripts/${WORKER}/settings`, headers);
  const bindings = worker?.result?.bindings;
  if (worker?.success !== true || !Array.isArray(bindings))
    throw new ApiError(503, 'BINDING_READ_FAILED', 'Worker 归属读取失败');
  if (
    ['RESOURCE_OWNER_ID', 'DB', 'BACKUPS'].some(
      (name) => bindings.filter((b: any) => b.name === name).length !== 1,
    )
  )
    throw new ApiError(503, 'BINDING_OWNERSHIP_FAILED', 'CF Worker 归属字段不唯一');
  const owner = bindings.find((b: any) => b.name === 'RESOURCE_OWNER_ID');
  const db = bindings.find((b: any) => b.name === 'DB');
  const backup = bindings.find((b: any) => b.name === 'BACKUPS');
  if (
    owner?.type !== 'plain_text' ||
    owner.text !== env.RESOURCE_OWNER_ID ||
    db?.type !== 'd1' ||
    db.id !== env.D1_DATABASE_ID ||
    (db.database_id !== undefined && db.database_id !== env.D1_DATABASE_ID) ||
    backup?.type !== 'r2_bucket' ||
    backup.bucket_name !== 'shortlink-new-backups'
  )
    throw new ApiError(503, 'BINDING_OWNERSHIP_FAILED', 'CF Worker 资源归属不匹配');
  const nonce = crypto.randomUUID();
  try {
    const proof = await readJSON(
      `https://${hostname}/.well-known/shortlink-binding?nonce=${nonce}`,
    );
    if (
      proof?.worker !== WORKER ||
      proof.owner_id !== env.RESOURCE_OWNER_ID ||
      proof.hostname !== hostname ||
      proof.nonce !== nonce
    )
      throw new ApiError(503, 'BINDING_SERVICE_PENDING', 'CF 绑定已登记，但 HTTPS 服务尚未就绪');
  } catch {
    return { binding_state: 'pending', bound: false, binding_error: 'BINDING_SERVICE_PENDING' };
  }
  return { binding_state: 'verified', bound: true, binding_error: null };
}
