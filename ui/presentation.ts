export const TIME_ZONE = 'Asia/Singapore';
export const TIME_ZONE_LABEL = 'Asia/Singapore（UTC+8）';

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
