import './analytics.css';
import type { MapCountry } from './world-map';
import {
  countryFlag,
  rankingLabel,
  trendEntries,
  type DailyValue,
  type RankValue,
  type RankingKind,
} from './analytics-data';

export type AnalyticsStats = {
  daily: DailyValue[];
  daily_timezone?: string;
  countries: RankValue[];
  devices: RankValue[];
  referrers: RankValue[];
  browsers?: RankValue[];
};
type OpenDetail = (title: string, description: string, content: HTMLElement) => void;

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className = '',
  text = '',
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  node.className = className;
  node.textContent = text;
  return node;
}
function svgNode<K extends keyof SVGElementTagNameMap>(
  tag: K,
  attrs: Record<string, string> = {},
): SVGElementTagNameMap[K] {
  const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
  return node;
}
function heading(title: string, description: string): HTMLElement {
  const row = el('div', 'chart-heading');
  row.append(el('h2', '', title), el('span', 'hint', description));
  return row;
}

export function worldMap(values: RankValue[], countries: MapCountry[]): HTMLElement {
  const panel = el('div', 'panel map-panel analytics-map');
  panel.append(heading('世界访问分布', '近似访问事件 · 国家 / 地区'));
  const frame = el('div', 'map-frame');
  const svg = svgNode('svg', {
    viewBox: '0 0 900 425',
    class: 'world-map',
    role: 'group',
    'aria-label': '真实访问国家与地区分布；有访问的区域按数量着色',
  });
  const counts = new Map(values.map((entry) => [entry.name.toUpperCase(), entry.count]));
  const actualMaximum = Math.max(0, ...values.map((entry) => entry.count));
  const maximum = Math.max(1, actualMaximum);
  const total = values.reduce((sum, entry) => sum + entry.count, 0);
  const tip = el('p', 'chart-tooltip', '悬停或使用 Tab 聚焦地区，沿国界高亮并查看访问次数。');
  tip.setAttribute('role', 'status');
  const mapped = new Set<string>();
  for (const country of countries) {
    const count = counts.get(country.code) || 0;
    mapped.add(country.code);
    const shape = country.path
      ? svgNode('path', { d: country.path, 'fill-rule': 'evenodd' })
      : svgNode('circle', {
          cx: String(country.point![0]),
          cy: String(country.point![1]),
          r: '2.2',
        });
    shape.classList.add('map-country');
    const label = `${countryFlag(country.code)} ${country.name}（${country.code}）：${count.toLocaleString('zh-CN')} 次${total ? ` · ${((count / total) * 100).toFixed(1)}%` : ''}`;
    shape.setAttribute('aria-label', label);
    const title = svgNode('title');
    title.textContent = label;
    shape.append(title);
    if (count > 0) {
      shape.classList.add('has-visits');
      shape.style.setProperty(
        '--intensity',
        String(0.25 + (0.75 * Math.log1p(count)) / Math.log1p(maximum)),
      );
      shape.setAttribute('tabindex', '0');
      const show = () => {
        shape.classList.add('is-active');
        tip.textContent = label;
      };
      const hide = () => {
        if (document.activeElement !== shape) shape.classList.remove('is-active');
      };
      shape.addEventListener('pointerenter', show);
      shape.addEventListener('pointerleave', hide);
      shape.addEventListener('focus', show);
      shape.addEventListener('blur', () => shape.classList.remove('is-active'));
    }
    svg.append(shape);
  }
  frame.append(svg);
  const legend = el('div', 'map-legend');
  const none = el('span', 'legend-label');
  none.append(el('i', 'legend-none'), '无记录');
  legend.append(
    none,
    el('span', '', '较少'),
    el('span', 'legend-scale'),
    el('span', '', `${actualMaximum.toLocaleString('zh-CN')} 次`),
  );
  panel.append(frame, legend, tip);
  if (!total) panel.append(el('p', 'notice', '这个区间暂无真实访问数据，地图不会显示访问热点。'));
  const unknown = values
    .filter((entry) => !mapped.has(entry.name.toUpperCase()))
    .reduce((sum, entry) => sum + entry.count, 0);
  if (unknown)
    panel.append(
      el(
        'p',
        'notice',
        `未知或地图未覆盖地区：${unknown.toLocaleString('zh-CN')} 次。这些访问仍计入总数和排行。`,
      ),
    );
  const credit = el('p', 'map-credit hint');
  const source = el('a', '', '地理数据：Natural Earth · Public Domain');
  source.href = 'https://www.naturalearthdata.com/about/terms-of-use/';
  source.target = '_blank';
  source.rel = 'noreferrer noopener';
  credit.append(source);
  panel.append(credit);
  return panel;
}

export function trendChart(daily: DailyValue[], days: number, timezone: string): HTMLElement {
  const panel = el('div', 'panel trend analytics-trend');
  panel.append(heading('访问趋势', `最近 ${days} 天 · 按日聚合（${timezone}）`));
  const entries = trendEntries(daily, days, timezone);
  const total = entries.reduce((sum, entry) => sum + entry.visits, 0);
  const summary = el('div', 'trend-summary');
  const legend = el('span', 'trend-series', '近似访问事件');
  summary.append(
    legend,
    el('strong', '', total.toLocaleString('zh-CN')),
    el('span', 'hint', '区间总计'),
  );
  panel.append(summary);
  if (!total) {
    panel.append(
      el('p', 'empty', '这个区间暂无访问记录。真实访问后，趋势会在异步聚合完成后显示。'),
    );
    return panel;
  }
  const maximum = Math.max(1, ...entries.map((entry) => entry.visits));
  const magnitude = 10 ** Math.floor(Math.log10(maximum));
  const ceiling = Math.ceil(maximum / magnitude) * magnitude;
  const frame = el('div', 'analytics-trend-frame');
  const svg = svgNode('svg', {
    viewBox: '0 0 900 258',
    class: 'trend-svg',
    role: 'group',
    tabindex: '0',
    'aria-label': '每日近似访问事件趋势。左右方向键查看日期，Home 和 End 跳到首尾。',
  });
  const left = 58,
    right = 882,
    top = 14,
    bottom = 213;
  for (let index = 0; index <= 4; index++) {
    const y = bottom - (index / 4) * (bottom - top);
    svg.append(
      svgNode('line', {
        x1: String(left),
        x2: String(right),
        y1: String(y),
        y2: String(y),
        class: 'chart-gridline',
      }),
    );
    const label = svgNode('text', {
      x: String(left - 12),
      y: String(y + 4),
      'text-anchor': 'end',
      class: 'chart-axis',
    });
    label.textContent = ((ceiling * index) / 4).toLocaleString('zh-CN', {
      maximumFractionDigits: 1,
    });
    svg.append(label);
  }
  const points = entries.map((entry, index) => ({
    ...entry,
    x:
      entries.length === 1
        ? (left + right) / 2
        : left + (index / (entries.length - 1)) * (right - left),
    y: bottom - (entry.visits / ceiling) * (bottom - top),
  }));
  const line = points
    .map((point, index) => `${index ? 'L' : 'M'}${point.x.toFixed(2)},${point.y.toFixed(2)}`)
    .join('');
  svg.append(svgNode('path', { d: line, class: 'trend-line' }));
  for (const [index, point] of points.entries()) {
    if (index === 0 || index === points.length - 1 || index % Math.ceil(points.length / 6) === 0) {
      const label = svgNode('text', {
        x: String(point.x),
        y: '243',
        'text-anchor': 'middle',
        class: 'chart-axis',
      });
      label.textContent = point.date.slice(5);
      svg.append(label);
    }
  }
  const crosshair = svgNode('line', {
    y1: String(top),
    y2: String(bottom),
    class: 'trend-crosshair',
    visibility: 'hidden',
    'aria-hidden': 'true',
  });
  const dot = svgNode('circle', {
    r: '4',
    class: 'trend-active-dot',
    visibility: 'hidden',
    'aria-hidden': 'true',
  });
  svg.append(crosshair, dot);
  const tip = el('div', 'trend-hover-card');
  tip.hidden = true;
  const date = el('strong'),
    count = el('span');
  tip.append(date, count);
  const status = el(
    'p',
    'chart-tooltip',
    '移动鼠标查看每日次数；键盘聚焦图表后可用左右方向键浏览。',
  );
  status.setAttribute('role', 'status');
  let active = points.length - 1;
  const show = (index: number) => {
    active = Math.min(points.length - 1, Math.max(0, index));
    const point = points[active];
    crosshair.setAttribute('x1', String(point.x));
    crosshair.setAttribute('x2', String(point.x));
    crosshair.setAttribute('visibility', 'visible');
    dot.setAttribute('cx', String(point.x));
    dot.setAttribute('cy', String(point.y));
    dot.setAttribute('visibility', 'visible');
    date.textContent = `${point.date}（${timezone}）`;
    count.textContent = `近似访问事件 ${point.visits.toLocaleString('zh-CN')}`;
    status.textContent = `${point.date}（${timezone}） · ${point.visits.toLocaleString('zh-CN')} 次近似访问`;
    tip.style.left = `${Math.max(2, Math.min(70, (point.x / 900) * 100))}%`;
    tip.hidden = false;
  };
  const hide = () => {
    tip.hidden = true;
    crosshair.setAttribute('visibility', 'hidden');
    dot.setAttribute('visibility', 'hidden');
  };
  svg.addEventListener('pointermove', (event) => {
    const point = svg.createSVGPoint();
    point.x = event.clientX;
    point.y = event.clientY;
    const matrix = svg.getScreenCTM();
    if (!matrix) return;
    const x = point.matrixTransform(matrix.inverse()).x;
    show(Math.round(((x - left) / (right - left)) * (points.length - 1)));
  });
  svg.addEventListener('pointerleave', () => {
    if (document.activeElement !== svg) hide();
  });
  svg.addEventListener('focus', () => show(active));
  svg.addEventListener('blur', hide);
  svg.addEventListener('keydown', (event) => {
    if (['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) {
      event.preventDefault();
      show(
        event.key === 'Home'
          ? 0
          : event.key === 'End'
            ? points.length - 1
            : active + (event.key === 'ArrowLeft' ? -1 : 1),
      );
    } else if (event.key === 'Escape') hide();
  });
  frame.append(svg, tip);
  panel.append(frame, status);
  return panel;
}

function rankingRows(
  kind: RankingKind,
  values: RankValue[],
  countries: Map<string, string>,
  limit?: number,
): HTMLElement {
  const list = el('ol', 'analytics-ranking');
  const total = values.reduce((sum, entry) => sum + entry.count, 0);
  for (const [index, entry] of values.slice(0, limit ?? values.length).entries()) {
    const row = el('li', 'rank-row');
    const label = rankingLabel(kind, entry.name, countries);
    const percentage = total ? (entry.count / total) * 100 : 0;
    const header = el('div', 'rank-label');
    const name = el('span', 'rank-name');
    name.append(el('span', 'rank-index', String(index + 1).padStart(2, '0')));
    if (kind === 'countries') {
      const flag = el('span', 'rank-flag', countryFlag(entry.name));
      flag.setAttribute('aria-hidden', 'true');
      name.append(flag);
    }
    name.append(label);
    header.append(
      name,
      el(
        'span',
        'rank-count',
        `${entry.count.toLocaleString('zh-CN')} · ${percentage.toFixed(1)}%`,
      ),
    );
    const track = el('div', 'rank-track'),
      fill = el('div', 'rank-fill');
    fill.style.width = `${percentage}%`;
    track.append(fill);
    row.append(header, track);
    list.append(row);
  }
  if (!values.length) list.append(el('li', 'empty', '这个区间暂无数据。'));
  return list;
}

export function rankings(
  stats: AnalyticsStats,
  countries: MapCountry[],
  openDetail: OpenDetail,
): HTMLElement {
  const grid = el('div', 'chart-grid analytics-rankings');
  const names = new Map(countries.map((country) => [country.code, country.name]));
  for (const [kind, title] of [
    ['countries', '地区排行'],
    ['devices', '设备排行'],
    ['referrers', '来源排行'],
    ['browsers', '浏览器排行'],
  ] as [RankingKind, string][]) {
    const values = stats[kind] || [];
    const panel = el('div', 'panel analytics-rank-card');
    const row = heading(title, '');
    const detail = el('button', 'button quiet small rank-expand', '展开 ↗');
    detail.type = 'button';
    detail.setAttribute('aria-label', `展开${title}，查看全部 ${values.length} 项`);
    detail.addEventListener('click', () => {
      const body = el('div', 'ranking-detail-body');
      const search = el('input', 'ranking-search');
      search.type = 'search';
      search.placeholder = '搜索排行项目';
      search.setAttribute('aria-label', `搜索${title}`);
      const full = el('div', 'ranking-detail-list');
      full.append(rankingRows(kind, values, names));
      search.addEventListener('input', () => {
        const query = search.value.trim().toLocaleLowerCase();
        const matches = (entry: RankValue) =>
          `${entry.name} ${rankingLabel(kind, entry.name, names)}`
            .toLocaleLowerCase()
            .includes(query);
        // Percentages remain relative to the full ranking, including while searching.
        const complete = rankingRows(kind, values, names);
        Array.from(complete.children).forEach((child, index) => {
          if (values[index] && !matches(values[index])) child.remove();
        });
        if (!complete.children.length && values.length)
          complete.append(el('li', 'empty', '没有匹配的项目。'));
        full.replaceChildren(complete);
      });
      body.append(search, full);
      openDetail(
        title,
        `全部 ${values.length} 项 · 最近区间 ${values.reduce((sum, entry) => sum + entry.count, 0).toLocaleString('zh-CN')} 次近似访问事件。占比按完整排行计算。`,
        body,
      );
    });
    row.lastElementChild?.remove();
    row.append(detail);
    panel.append(row, rankingRows(kind, values, names, 5));
    if (kind === 'browsers')
      panel.append(el('p', 'hint', '由 UA 近似识别；历史未保留的 UA 计入未知。'));
    grid.append(panel);
  }
  return grid;
}
