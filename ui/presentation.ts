import { basicAuditIdentity, type AuditActorIdentity } from '../src/audit-identity';

export const TIME_ZONE = 'Asia/Singapore';
export const TIME_ZONE_LABEL = 'Asia/Singapore（UTC+8）';

export function auditActor(
  identity: AuditActorIdentity | undefined,
  raw: unknown,
): { title: string; details: string[] } {
  // An already-open page can see an older API response after a release rollback.
  identity ??= basicAuditIdentity(raw);
  switch (identity.type) {
    case 'admin':
      return { title: `管理员：${identity.name}`, details: [] };
    case 'business_token':
      return {
        title: `业务 Token：${identity.name || '名称未记录'}`,
        details: [
          `创建管理员：${identity.created_by || '未记录'}`,
          `Token ID：${identity.token_id}`,
        ],
      };
    case 'anonymous':
      return { title: '匿名访客（公共网页）', details: [] };
    case 'system':
      return { title: `系统：${identity.name}`, details: [String(raw)] };
    default:
      return { title: '身份未识别', details: [`原始标识：${raw || '未记录'}`] };
  }
}

export function formatTime(value: unknown): string {
  if (value === null || value === undefined || value === '') return '—';
  const date = new Date(typeof value === 'number' ? value : String(value));
  if (Number.isNaN(date.getTime())) return '—';
  return new Intl.DateTimeFormat('zh-CN', {
    timeZone: TIME_ZONE,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(date);
}

export function datetimeValue(value: number | null): string {
  return value === null ? '' : new Date(value + 8 * 3600000).toISOString().slice(0, 19);
}

export function expiration(value: string): number | null {
  if (!value) return null;
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?$/.test(value)) throw new Error('到期时间无效');
  const time = new Date(`${value}+08:00`).getTime();
  if (!Number.isFinite(time)) throw new Error('到期时间无效');
  return time;
}

export type PublicUrl = { domain: string; short_url: string };
export type CreationResult = PublicUrl & { slug: string; public_urls?: PublicUrl[] };

// Only display addresses supplied by the API. No domain prefixes are synthesized here.
export function publicUrls(result: CreationResult): PublicUrl[] {
  const values = Array.isArray(result.public_urls) ? result.public_urls : [result];
  const seen = new Set<string>();
  return values.filter((value) => {
    try {
      const url = new URL(value.short_url);
      if (
        url.protocol !== 'https:' ||
        url.hostname !== value.domain ||
        url.port ||
        url.username ||
        url.password ||
        url.search ||
        url.hash ||
        seen.has(value.short_url)
      )
        return false;
      seen.add(value.short_url);
      return true;
    } catch {
      return false;
    }
  });
}
