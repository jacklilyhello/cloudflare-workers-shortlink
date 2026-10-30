/** Coarse, bounded UA classification. Raw user agents are never persisted. */
export function classifyBrowser(value: string): string {
  const agent = value.slice(0, 2048);
  if (!agent.trim()) return 'unknown';
  if (/bot|crawler|spider|preview|headless/i.test(agent)) return 'bot';
  if (/MicroMessenger\//i.test(agent)) return 'wechat';
  if (/Edg(?:e|A|iOS)?\//i.test(agent)) return 'edge';
  if (/OPR\/|Opera\//i.test(agent)) return 'opera';
  if (/SamsungBrowser\//i.test(agent)) return 'samsung';
  if (/Firefox\/|FxiOS\//i.test(agent))
    return /Mobile|Android|FxiOS/i.test(agent) ? 'firefox_mobile' : 'firefox';
  if (/Chrome\/|CriOS\//i.test(agent))
    return /Mobile|Android|CriOS/i.test(agent) ? 'chrome_mobile' : 'chrome';
  if (/Version\/[\d.]+.*Safari\//i.test(agent))
    return /Mobile|iPhone|iPad/i.test(agent) ? 'safari_mobile' : 'safari';
  return 'other';
}

export function browserRankings(
  tracked: { name: string; count: number }[],
  visits: number,
): { name: string; count: number }[] {
  const counts = new Map(tracked.map((entry) => [entry.name, entry.count]));
  const unclassified = Math.max(0, visits - tracked.reduce((sum, entry) => sum + entry.count, 0));
  if (unclassified) counts.set('unknown', (counts.get('unknown') || 0) + unclassified);
  return Array.from(counts, ([name, count]) => ({ name, count })).sort(
    (a, b) => b.count - a.count || a.name.localeCompare(b.name),
  );
}
