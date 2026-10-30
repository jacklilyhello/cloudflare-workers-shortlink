export type RankValue = { name: string; count: number };
export type DailyValue = { date: string; visits: number };
export type RankingKind = 'countries' | 'devices' | 'referrers' | 'browsers';

export function countryFlag(code: string): string {
  if (!/^[A-Z]{2}$/.test(code) || ['XX', 'T1', 'A1', 'A2'].includes(code)) return '🌐';
  return String.fromCodePoint(...Array.from(code, (letter) => 127397 + letter.charCodeAt(0)));
}

export function trendEntries(
  daily: DailyValue[],
  days: number,
  timezone: string,
  now = Date.now(),
): DailyValue[] {
  const values = new Map(daily.map((entry) => [entry.date, entry.visits]));
  const offset = timezone === 'Asia/Singapore' ? 8 * 3600000 : 0;
  const today = new Date(now + offset).toISOString().slice(0, 10);
  const end = new Date(`${today}T00:00:00Z`).getTime();
  return Array.from({ length: days }, (_, index) => {
    const date = new Date(end - (days - index - 1) * 86400000).toISOString().slice(0, 10);
    return { date, visits: values.get(date) || 0 };
  });
}

export function rankingLabel(
  kind: RankingKind,
  value: string,
  countries: Map<string, string>,
): string {
  if (kind === 'countries')
    return countries.get(value) || (value === 'XX' ? '未知地区' : value || '未知地区');
  const labels: Record<string, string> =
    kind === 'devices'
      ? {
          desktop: '电脑',
          mobile: '手机',
          tablet: '平板',
          bot: '机器人',
          other: '其他',
          unknown: '未知设备',
        }
      : kind === 'browsers'
        ? {
            chrome: 'Chrome',
            chrome_mobile: 'Chrome Mobile',
            safari: 'Safari',
            safari_mobile: 'Safari Mobile',
            firefox: 'Firefox',
            firefox_mobile: 'Firefox Mobile',
            edge: 'Microsoft Edge',
            opera: 'Opera',
            samsung: 'Samsung Internet',
            wechat: '微信内置浏览器',
            bot: '机器人 / 无头浏览器',
            other: '其他浏览器',
            unknown: '未知 / 历史未记录',
          }
        : { direct: '直接访问 / 未提供来源', other: '其他来源' };
  return labels[value] || value || '未知';
}
