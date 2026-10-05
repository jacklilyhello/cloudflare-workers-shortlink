import './styles.css';
import { encodeLegacySlug } from '../src/legacy-slug.mjs';
import {
  formatTime,
  datetimeValue,
  expiration,
  publicUrls,
  TIME_ZONE_LABEL,
  type CreationResult,
} from './presentation';
import type { MapCountry } from './world-map';
let worldCountries: MapCountry[] = [];

type Item = Record<string, unknown>;
type PageResult<T> = { items: T[]; next_cursor?: string | null };
type Domain = {
  id: string;
  hostname: string;
  bound: boolean;
  enabled: boolean;
  binding_state?: 'unbound' | 'pending' | 'verified' | 'failed';
  last_verified_at?: number | null;
  last_checked_at?: number | null;
  binding_error?: string | null;
};
type Schedule = {
  enabled: boolean | number | string;
  interval_hours: number;
  retention_days?: number;
  last_success_at: number | null;
  next_due_at: number | null;
  state: string;
  last_error_code?: string | null;
  retry_count?: number;
};
type Link = {
  id: string;
  slug: string;
  domain: string;
  url: string;
  enabled: boolean;
  expires_at: number | null;
  confirmation_enabled: boolean;
  confirmation_text: string;
  query_policy: string;
  created_at: number | null;
  visits?: number;
};
type BusinessToken = {
  id: string;
  name: string;
  prefix: string;
  domains: string[];
  created_at: number;
  expires_at: number | null;
  revoked_at: number | null;
  rate_per_minute?: number;
};
type Stats = {
  timezone?: string;
  daily_timezone?: string;
  daily: { date: string; visits: number }[];
  countries: { name: string; count: number }[];
  devices: { name: string; count: number }[];
  referrers: { name: string; count: number }[];
  totals: { links: number; visits: number; active_links: number };
};
type MigrationRun = {
  id: string;
  state: string;
  processed: number;
  imported: number;
  unchanged: number;
  skipped: number;
  conflicts: number;
  unknown: number;
  digest: string;
  updated_at: number;
  started_at?: number | null;
  completed_at?: number | null;
  last_error_code?: string | null;
  attempts?: number;
  retry_at?: number | null;
};
type Turnstile = {
  render: (container: HTMLElement, options: Item) => string;
  reset: (id: string) => void;
};
declare global {
  interface Window {
    turnstile?: Turnstile;
    shortlinkTurnstileReady?: () => void;
  }
}

const app = document.querySelector<HTMLDivElement>('#app')!;
let csrf = '';
let theme: 'auto' | 'light' | 'dark' = 'auto';
let renderVersion = 0;
let activeTab = 'links';
let domains: Domain[] = [];
let controlId = 0;

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className = '',
  text = '',
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text) node.textContent = text;
  return node;
}
function append<T extends HTMLElement>(parent: T, ...children: (Node | string | undefined)[]): T {
  for (const child of children) if (child !== undefined) parent.append(child);
  return parent;
}
function button(label: string, callback: () => void, className = ''): HTMLButtonElement {
  const node = el('button', `button ${className}`, label);
  node.type = 'button';
  node.addEventListener('click', callback);
  return node;
}
function field(
  label: string,
  type = 'text',
  value = '',
  hint = '',
): { node: HTMLLabelElement; input: HTMLInputElement } {
  const node = el('label', 'field');
  const input = el('input');
  input.type = type;
  input.value = value;
  if (type === 'datetime-local') input.step = '1';
  input.setAttribute('aria-label', label);
  append(node, el('span', '', label), input);
  if (hint) {
    const description = el('span', 'hint', hint);
    description.id = `hint-${++controlId}`;
    input.setAttribute('aria-describedby', description.id);
    node.append(description);
  }
  return { node, input };
}
function textField(
  label: string,
  value = '',
  hint = '',
): { node: HTMLLabelElement; input: HTMLTextAreaElement } {
  const node = el('label', 'field');
  const input = el('textarea');
  input.value = value;
  input.maxLength = 2000;
  input.setAttribute('aria-label', label);
  append(node, el('span', '', label), input);
  if (hint) {
    const description = el('span', 'hint', hint);
    description.id = `hint-${++controlId}`;
    input.setAttribute('aria-describedby', description.id);
    node.append(description);
  }
  return { node, input };
}
function selectField(
  label: string,
  choices: [string, string][],
  value = '',
): { node: HTMLLabelElement; input: HTMLSelectElement } {
  const node = el('label', 'field');
  const input = select(choices, value);
  input.setAttribute('aria-label', label);
  append(node, el('span', '', label), input);
  return { node, input };
}
function select(choices: [string, string][], value = ''): HTMLSelectElement {
  const node = el('select');
  for (const [key, label] of choices) {
    const option = el('option', '', label);
    option.value = key;
    node.append(option);
  }
  if (value) node.value = value;
  return node;
}
function check(label: string, value = false): { node: HTMLLabelElement; input: HTMLInputElement } {
  const input = el('input');
  input.type = 'checkbox';
  input.checked = value;
  const node = append(el('label', 'check-field'), input, el('span', '', label));
  return { node, input };
}
function notice(parent: HTMLElement, message: string, error = false): HTMLElement {
  const node = el('p', `notice${error ? ' error' : ''}`, message);
  node.setAttribute('role', error ? 'alert' : 'status');
  parent.append(node);
  return node;
}
function showStatus(node: HTMLElement, message: string, error = false) {
  node.textContent = message;
  node.className = `notice${error ? ' error' : ''}`;
  node.hidden = false;
  node.setAttribute('role', error ? 'alert' : 'status');
}
function formatExpiry(value: number | null): string {
  return value === null ? '永久' : formatTime(value);
}
function safeAnchor(label: string, href: string, className = ''): HTMLAnchorElement {
  const a = el('a', className, label);
  try {
    const url = new URL(href);
    if (url.protocol === 'https:' || url.protocol === 'http:') {
      a.href = url.href;
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
    }
  } catch {
    /* An invalid API value stays inert. */
  }
  return a;
}
function shortUrl(link: Pick<Link, 'domain' | 'slug'>): string {
  return `https://${link.domain}/${encodeLegacySlug(link.slug)}`;
}

class ApiError extends Error {
  constructor(
    message: string,
    readonly code = '',
    readonly requestId = '',
  ) {
    super(message);
  }
}
const errorMessages: Record<string, string> = {
  SLUG_CONFLICT: '这个短码已被占用，请换一个。',
  INVALID_URL: '请输入完整的 http:// 或 https:// 链接。',
  INVALID_SLUG: '短码只接受字母、数字、下划线和连字符，最长 64 个字符。',
  RATE_LIMITED: '操作过于频繁，请稍后再试。',
  TURNSTILE_FAILED: '验证码未通过，请重新验证。',
  TURNSTILE_REQUIRED: '请先完成验证码。',
  DOMAIN_FORBIDDEN: '这个域名尚未绑定、已停用或不在授权范围内。',
  UNAUTHORIZED: '管理员会话已失效，请刷新页面重新登录。',
  ACCESS_DENIED: '当前登录身份没有管理员权限。',
  CSRF_INVALID: '页面会话已过期，请刷新页面后再操作。',
  INVALID_CSRF: '页面会话已过期，请刷新页面后再操作。',
  TEMPORARILY_UNAVAILABLE: '服务暂时不可用，请稍后再试。',
  ADMIN_REQUIRED: '需要管理员登录。请刷新页面，通过 Cloudflare Access 重新登录。',
  ADMIN_INVALID: '管理员会话已失效，请刷新页面重新登录。',
  ADMIN_FORBIDDEN: '当前邮箱不在管理员允许列表中，请使用获准邮箱重新登录。',
  ADMIN_NOT_CONFIGURED: '后台身份配置尚未完成，请先核对手动 Actions 的 Access 接入结果。',
  CSRF_REJECTED: '页面会话已过期或请求来源无效。请刷新页面重新登录，再核对相关列表后操作。',
  DOMAIN_NOT_BOUND: '此域名尚未完成绑定。请在 Cloudflare Worker 面板手动绑定，再刷新绑定状态。',
  DOMAIN_VERIFICATION_FAILED: '绑定核验失败，请查看域名状态。读取失败不会被当作绑定完成。',
  IDEMPOTENCY_DELETED: '此短码已彻底删除，不能通过重放恢复。',
};
async function api<T>(path: string, method = 'GET', body?: unknown): Promise<T> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 20000);
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET' && path.startsWith('/api/admin/')) headers['X-CSRF-Token'] = csrf;
  try {
    const response = await fetch(path, {
      method,
      body: body === undefined ? undefined : JSON.stringify(body),
      headers,
      credentials: 'same-origin',
      redirect: 'error',
      signal: controller.signal,
    });
    if (!response.headers.get('Content-Type')?.includes('application/json'))
      throw new ApiError(
        '服务返回了登录页或安全验证页面，请刷新页面完成登录后再操作。',
        'NON_JSON_RESPONSE',
      );
    const envelope = (await response.json()) as {
      ok: boolean;
      data: T;
      error?: { code: string; message: string };
      request_id?: string;
    };
    if (!response.ok || !envelope.ok) {
      const code = envelope.error?.code || 'REQUEST_FAILED';
      const retry = response.headers.get('Retry-After');
      throw new ApiError(
        `${errorMessages[code] || envelope.error?.message || '操作未成功。'}${retry ? ` 请至少等待 ${retry} 秒。` : ''}`,
        code,
        envelope.request_id,
      );
    }
    return envelope.data;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(
      method === 'GET'
        ? '无法连接服务。请检查网络；如果登录已过期，请刷新页面重新登录。'
        : path === '/api/public/shorten'
          ? '未收到服务确认，短链接可能已创建。输入已保留；再次生成可能产生另一条短链接，请避免连续重复提交。'
          : '未收到服务确认，操作可能已经完成。请先刷新相关列表核实，避免重复提交。',
      'NETWORK_UNCERTAIN',
    );
  } finally {
    window.clearTimeout(timeout);
  }
}
function errorText(error: unknown): string {
  return error instanceof ApiError
    ? `${error.message}${error.requestId ? `（请求编号 ${error.requestId}）` : ''}`
    : error instanceof Error
      ? error.message
      : '操作未成功，请稍后再试。';
}
async function copy(value: string, trigger: HTMLButtonElement) {
  try {
    await navigator.clipboard.writeText(value);
    const original = trigger.textContent;
    trigger.textContent = '已复制';
    window.setTimeout(() => {
      trigger.textContent = original;
    }, 1800);
  } catch {
    const parent = trigger.closest('dialog') || trigger.parentElement!;
    notice(parent as HTMLElement, '浏览器未允许复制，请选择链接或文本手动复制。', true);
  }
}
function themeButton(): HTMLButtonElement {
  const labels = { auto: '外观 · 自动', light: '外观 · 浅色', dark: '外观 · 深色' };
  const node = button(
    labels[theme],
    () => {
      theme = theme === 'auto' ? 'light' : theme === 'light' ? 'dark' : 'auto';
      if (theme === 'auto') delete document.documentElement.dataset.theme;
      else document.documentElement.dataset.theme = theme;
      node.textContent = labels[theme];
    },
    'quiet theme-button',
  );
  return node;
}
function brand(admin = false): HTMLElement {
  const node = el('a', 'brand');
  node.href = admin ? '/admin' : '/';
  append(
    node,
    el('span', 'brand-mark', '↗'),
    el('span', '', 'Shortlink'),
    el('span', 'wordmark-sub', admin ? 'CONSOLE' : '简单连接'),
  );
  return node;
}
function pageHeading(title: string, description: string, action?: HTMLElement): HTMLElement {
  const heading = el('div', 'section-heading');
  append(heading, append(el('div'), el('h1', '', title), el('p', '', description)), action);
  return heading;
}
function modal(
  title: string,
  description = '',
): { dialog: HTMLDialogElement; body: HTMLElement; status: HTMLElement; close: () => void } {
  const dialog = el('dialog');
  dialog.setAttribute('aria-label', title);
  const close = () => {
    dialog.close();
    dialog.remove();
  };
  append(dialog, button('关闭', close, 'quiet small dialog-close'), el('h2', '', title));
  if (description) dialog.append(el('p', 'intro', description));
  const body = el('div');
  const status = el('p');
  status.hidden = true;
  append(dialog, body, status);
  dialog.addEventListener('cancel', () => dialog.remove());
  document.body.append(dialog);
  dialog.showModal();
  return { dialog, body, status, close };
}
function confirmAction(
  title: string,
  description: string,
  label: string,
  action: () => Promise<void>,
) {
  const m = modal(title, description);
  const submit = button(
    label,
    () => {
      submit.disabled = true;
      action()
        .then(m.close)
        .catch((error) => {
          showStatus(m.status, errorText(error), true);
          submit.disabled = false;
        });
    },
    'primary',
  );
  const cancel = button('取消', m.close);
  m.body.append(append(el('div', 'form-actions'), cancel, submit));
  cancel.focus();
}

async function publicPage() {
  document.title = 'Shortlink · 简单连接';
  const page = el('div', 'page');
  const header = append(el('header', 'topbar'), brand(), themeButton());
  const main = el('main', 'public-main');
  main.id = 'main';
  append(
    main,
    el('p', 'eyebrow', 'A shorter way to connect'),
    el('h1', '', '长链接，轻一点。'),
    el('p', 'intro', '粘贴链接，生成短链。一次生成，多域名通用，让分享更简单。'),
  );
  const form = el('form', 'creation-card glass');
  form.autocomplete = 'off';
  const url = field('长链接', 'url');
  url.input.required = true;
  url.input.placeholder = 'https://example.com/your-long-link';
  url.input.maxLength = 8192;
  url.input.autocapitalize = 'off';
  url.input.spellcheck = false;
  const slugLabel = el('label', 'field');
  append(slugLabel, append(el('span'), '自定义短码', el('span', 'optional', '可选')));
  const slug = el('input');
  slug.type = 'text';
  slug.maxLength = 64;
  slug.pattern = '[A-Za-z0-9_\\-]+';
  slug.placeholder = '自动生成';
  slug.autocapitalize = 'off';
  slug.spellcheck = false;
  slug.setAttribute('aria-label', '自定义短码');
  append(
    slugLabel,
    slug,
    el('span', 'hint', '留空自动生成。字母、数字、下划线或连字符，区分大小写。'),
  );
  const captcha = el('div', 'captcha', '正在连接安全验证…');
  const status = el('p');
  status.hidden = true;
  const submit = el('button', 'button primary create-button', '生成短链接  ↗');
  submit.type = 'submit';
  submit.disabled = true;
  const result = el('section', 'result');
  result.hidden = true;
  result.setAttribute('aria-label', '生成结果');
  result.setAttribute('aria-live', 'polite');
  append(form, url.node, slugLabel, captcha, status, submit, result);
  main.append(form);
  main.append(
    append(
      el('footer', 'public-footer'),
      el('p', '', '无需登录。结果仅在当前页面展示，请及时复制保存。'),
      append(
        el('p', 'new-domain'),
        '当前域名无法访问时，可在这里',
        safeAnchor('获取新域名 ↗', 'https://sink.lily.lat/link-fb'),
        '。',
      ),
    ),
  );
  append(page, header, main);
  app.replaceChildren(page);
  let challengeToken = '';
  let widget = '';
  try {
    const config = await api<{ site_key: string; domain: string }>('/api/public/config');
    if (!config.site_key) throw new Error('安全验证尚未配置，请稍后再试。');
    const renderChallenge = () => {
      if (!window.turnstile) return;
      captcha.replaceChildren();
      widget = window.turnstile.render(captcha, {
        sitekey: config.site_key,
        theme: 'auto',
        action: 'create',
        size: window.innerWidth < 380 ? 'compact' : 'normal',
        callback: (token: string) => {
          challengeToken = token;
          submit.disabled = false;
        },
        'expired-callback': () => {
          challengeToken = '';
          submit.disabled = true;
        },
        'error-callback': () => {
          challengeToken = '';
          submit.disabled = true;
          showStatus(status, '安全验证暂时不可用，请检查网络后刷新页面。', true);
        },
      });
    };
    window.shortlinkTurnstileReady = renderChallenge;
    if (window.turnstile) renderChallenge();
    else {
      const script = el('script');
      script.src =
        'https://challenges.cloudflare.com/turnstile/v0/api.js?onload=shortlinkTurnstileReady&render=explicit';
      script.async = true;
      script.onerror = () => showStatus(status, '安全验证无法载入，请检查网络后刷新页面。', true);
      document.head.append(script);
    }
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (!challengeToken || submit.disabled) return;
      submit.disabled = true;
      submit.textContent = '正在生成…';
      status.hidden = true;
      result.hidden = true;
      try {
        const data = await api<CreationResult>('/api/public/shorten', 'POST', {
          url: url.input.value,
          ...(slug.value ? { slug: slug.value } : {}),
          turnstile_token: challengeToken,
        });
        const addresses = publicUrls(data);
        if (!addresses.length) throw new Error('短链已创建，但服务没有返回可用地址，请稍后核对。');
        result.replaceChildren(el('p', 'result-label', '短链接已生成'));
        result.append(el('p', 'hint result-hint', '同一个短码，下列可用域名前缀都通向同一目标。'));
        const copyButtons: HTMLButtonElement[] = [];
        for (const address of addresses) {
          const copyButton = button(
            '复制',
            () => {
              void copy(address.short_url, copyButton);
            },
            'small',
          );
          copyButton.setAttribute('aria-label', `复制 ${address.domain} 短链接`);
          copyButtons.push(copyButton);
          result.append(
            append(
              el('div', 'result-line'),
              safeAnchor(address.short_url, address.short_url),
              copyButton,
            ),
          );
        }
        result.hidden = false;
        copyButtons[0].focus();
      } catch (error) {
        showStatus(status, errorText(error), true);
      } finally {
        challengeToken = '';
        if (window.turnstile && widget) window.turnstile.reset(widget);
        submit.textContent = '生成短链接  ↗';
        submit.disabled = true;
      }
    });
  } catch (error) {
    captcha.textContent = '安全验证未就绪';
    showStatus(status, errorText(error), true);
  }
}

const tabs: [string, string, string][] = [
  ['links', '链接管理', '↗'],
  ['stats', '访问统计', '▥'],
  ['domains', '域名配置', '◎'],
  ['tokens', '业务 Token', '⌘'],
  ['backups', '自动备份', '▣'],
  ['audit', '审计日志', '≡'],
  ['migrations', '迁移记录', '⇄'],
  ['settings', '系统设置', '⚙'],
];
let content: HTMLElement;
async function adminPage() {
  document.title = '管理控制台 · Shortlink';
  const page = el('div', 'page');
  const account = el('span', 'account', '正在验证管理员身份…');
  append(
    page,
    append(
      el('header', 'topbar admin-topbar'),
      brand(true),
      append(el('div', 'top-actions'), account, themeButton()),
    ),
  );
  const layout = el('div', 'admin-layout');
  const nav = el('nav', 'sidebar glass');
  nav.setAttribute('aria-label', '管理导航');
  content = el('main', 'content');
  content.id = 'main';
  const navButtons = new Map<string, HTMLButtonElement>();
  for (const [id, label, symbol] of tabs) {
    const node = button(
      '',
      () => {
        activeTab = id;
        history.replaceState(null, '', `/admin#${id}`);
        for (const [key, btn] of navButtons) {
          if (key === id) btn.setAttribute('aria-current', 'page');
          else btn.removeAttribute('aria-current');
        }
        void renderTab();
      },
      'nav-button',
    );
    node.disabled = true;
    append(node, el('span', 'nav-symbol', symbol), el('span', '', label));
    nav.append(node);
    navButtons.set(id, node);
  }
  nav.append(
    el(
      'p',
      'sidebar-note',
      '一个短码对应一条映射，所有有效公共前缀共用。停用、到期与彻底删除都不会释放短码。',
    ),
  );
  append(layout, nav, content);
  page.append(layout);
  app.replaceChildren(page);
  try {
    const session = await api<{ email: string; csrf: string }>('/api/admin/session');
    csrf = session.csrf;
    account.textContent = session.email;
    account.title = session.email;
    const hash = location.hash.slice(1);
    activeTab = tabs.some(([id]) => id === hash) ? hash : 'links';
    navButtons.get(activeTab)?.setAttribute('aria-current', 'page');
    domains = (await api<PageResult<Domain>>('/api/admin/domains')).items;
    for (const node of navButtons.values()) node.disabled = false;
    await renderTab();
  } catch (error) {
    content.replaceChildren(pageHeading('无法打开管理控制台', '后台由 Cloudflare Access 保护。'));
    notice(content, errorText(error), true);
    content.append(button('重新载入', () => location.reload(), 'primary'));
  }
}
async function renderTab() {
  const version = ++renderVersion;
  const id = activeTab;
  content.replaceChildren(el('p', 'notice', '正在载入…'));
  try {
    const node =
      id === 'links'
        ? await linksPage()
        : id === 'stats'
          ? await statsPage()
          : id === 'domains'
            ? await domainsPage()
            : id === 'tokens'
              ? await tokensPage()
              : id === 'backups'
                ? await backupsPage()
                : id === 'settings'
                  ? await settingsPage()
                  : await recordsPage(id);
    if (version === renderVersion) content.replaceChildren(node);
  } catch (error) {
    if (version === renderVersion) {
      content.replaceChildren(
        pageHeading(tabs.find(([key]) => key === id)?.[1] || '管理控制台', '数据未能载入。'),
      );
      notice(content, errorText(error), true);
      content.append(
        button('重新载入', () => {
          void renderTab();
        }),
      );
    }
  }
}
function table(headers: string[]): { wrapper: HTMLDivElement; body: HTMLTableSectionElement } {
  const wrapper = el('div', 'table-scroll');
  const node = el('table');
  const head = el('thead');
  const row = el('tr');
  for (const label of headers) row.append(el('th', '', label));
  head.append(row);
  const body = el('tbody');
  append(node, head, body);
  wrapper.append(node);
  return { wrapper, body };
}
function td(text: unknown, className = ''): HTMLTableCellElement {
  return el('td', className, String(text ?? '—'));
}
function statusBadge(enabled: boolean, on = '启用', off = '停用'): HTMLElement {
  return el('span', `badge${enabled ? '' : ' off'}`, enabled ? on : off);
}

async function linksPage(): Promise<HTMLElement> {
  const root = el('section');
  root.append(
    pageHeading(
      '链接管理',
      '统一管理所有短链接，包括匿名、机器调用和迁移创建的链接。',
      button('新建链接 +', () => editLink()),
    ),
  );
  const panel = el('div', 'panel');
  const toolbar = el('form', 'toolbar');
  const q = el('input');
  q.type = 'search';
  q.placeholder = '搜索短码或目标链接';
  q.setAttribute('aria-label', '搜索短码或目标链接');
  const domain = select([
    ['', '所有域名'],
    ...domains.map((d) => [d.hostname, d.hostname] as [string, string]),
  ]);
  domain.setAttribute('aria-label', '按域名筛选');
  const statusFilter = select([
    ['', '所有状态'],
    ['active', '有效'],
    ['disabled', '已停用'],
    ['expired', '已过期'],
  ]);
  statusFilter.setAttribute('aria-label', '按状态筛选');
  const search = el('button', 'button small', '筛选');
  search.type = 'submit';
  append(toolbar, q, domain, statusFilter, search);
  panel.append(toolbar);
  const listStatus = el('p');
  listStatus.hidden = true;
  const bulk = el('div', 'bulk-bar');
  bulk.hidden = true;
  const selected = new Set<string>();
  const count = el('span');
  const bulkAction = (action: string) =>
    confirmAction(
      action === 'disable' ? '批量停用链接' : '批量启用链接',
      `将更新 ${selected.size} 条已选择链接。链接映射与短码会继续保留。`,
      '确认更新',
      async () => {
        await api('/api/admin/links/bulk', 'POST', { ids: [...selected], action });
        await load();
      },
    );
  append(
    bulk,
    count,
    button('停用', () => bulkAction('disable'), 'small danger'),
    button('启用', () => bulkAction('enable'), 'small'),
    button(
      '设置到期',
      () => {
        const m = modal('批量设置到期时间', `修改 ${selected.size} 条链接。留空表示永久有效。`);
        const expiry = field('到期时间（Asia/Singapore · UTC+8）', 'datetime-local');
        m.body.append(expiry.node);
        const save = button(
          '保存',
          () => {
            save.disabled = true;
            api('/api/admin/links/bulk', 'POST', {
              ids: [...selected],
              action: 'expiry',
              expires_at: expiration(expiry.input.value),
            })
              .then(async () => {
                m.close();
                await load();
              })
              .catch((error) => {
                showStatus(m.status, errorText(error), true);
                save.disabled = false;
              });
          },
          'primary',
        );
        m.body.append(append(el('div', 'form-actions'), save));
      },
      'small',
    ),
  );
  const { wrapper, body } = table([
    '选择',
    '短链接 / 目标',
    '状态',
    '到期时间（UTC+8）',
    '创建时间（UTC+8）',
    '操作',
  ]);
  let cursor = '';
  const cursorStack: string[] = [];
  let nextCursor = '';
  const pagination = el('div', 'pagination');
  const previous = button(
    '上一页',
    () => {
      cursor = cursorStack.pop() || '';
      void load();
    },
    'small',
  );
  const next = button(
    '下一页',
    () => {
      cursorStack.push(cursor);
      cursor = nextCursor;
      void load();
    },
    'small',
  );
  append(pagination, previous, next);
  append(panel, listStatus, bulk, wrapper, pagination);
  root.append(panel);
  const refreshBulk = () => {
    bulk.hidden = selected.size === 0;
    count.textContent = `已选择 ${selected.size} 条`;
  };
  async function load(): Promise<string | null> {
    search.disabled = true;
    previous.disabled = true;
    next.disabled = true;
    listStatus.hidden = true;
    try {
      const params = new URLSearchParams();
      if (q.value) params.set('q', q.value);
      if (domain.value) params.set('domain', domain.value);
      if (statusFilter.value) params.set('status', statusFilter.value);
      if (cursor) params.set('cursor', cursor);
      const result = await api<PageResult<Link>>(`/api/admin/links?${params}`);
      body.replaceChildren();
      selected.clear();
      refreshBulk();
      if (!result.items.length) {
        const row = el('tr');
        const cell = td('没有符合条件的链接。', 'empty');
        cell.colSpan = 6;
        row.append(cell);
        body.append(row);
      }
      for (const item of result.items) {
        const row = el('tr');
        const checkbox = el('input');
        checkbox.type = 'checkbox';
        checkbox.setAttribute('aria-label', `选择 ${item.slug}`);
        checkbox.addEventListener('change', () => {
          if (checkbox.checked) selected.add(item.id);
          else selected.delete(item.id);
          refreshBulk();
        });
        const target = append(
          el('td', 'link-cell'),
          safeAnchor(`${item.domain}/${item.slug}`, shortUrl(item)),
          el('span', 'url-text', item.url),
        );
        target.title = item.url;
        const stateCell = el('td');
        const refreshState = () => {
          const state = !item.enabled
            ? '停用'
            : item.expires_at !== null && item.expires_at <= Date.now()
              ? '过期'
              : '有效';
          stateCell.replaceChildren(statusBadge(state === '有效', state, state));
          if (item.confirmation_enabled) stateCell.append(el('span', 'secondary', '确认页已开启'));
        };
        refreshState();
        const copyButton = button(
          '复制',
          () => {
            void copy(shortUrl(item), copyButton);
          },
          'small',
        );
        const toggle = button(
          item.enabled ? '停用' : '启用',
          () => {
            toggle.disabled = true;
            api(`/api/admin/links/${encodeURIComponent(item.id)}`, 'PATCH', {
              enabled: !item.enabled,
            })
              .then(async () => {
                item.enabled = !item.enabled;
                toggle.textContent = item.enabled ? '停用' : '启用';
                refreshState();
                const refreshError = await load();
                showStatus(
                  listStatus,
                  `短码 ${item.slug} 已${item.enabled ? '启用' : '停用'}，所有公共前缀同步生效。到期时间未改变。${refreshError ? `列表刷新失败：${refreshError} 请重新筛选核对。` : ''}`,
                  !!refreshError,
                );
              })
              .catch((error) => showStatus(listStatus, errorText(error), true))
              .finally(() => {
                toggle.disabled = false;
              });
          },
          'small',
        );
        const remove = button(
          '彻底删除',
          () =>
            confirmAction(
              '彻底删除短链接',
              `短码：${item.slug}\n目标：${item.url}\n同一短码在所有公共前缀下都会失效，在线映射将被删除，原短码不再复用。旧 KV 不会改动，历史备份按原保留策略处理，不会立即抹除。`,
              '确认彻底删除',
              async () => {
                await api(`/api/admin/links/${encodeURIComponent(item.id)}`, 'DELETE', {});
                row.remove();
                selected.delete(item.id);
                refreshBulk();
                const refreshError = await load();
                showStatus(
                  listStatus,
                  `短码 ${item.slug} 已彻底删除，所有公共前缀均失效。${refreshError ? `列表刷新失败：${refreshError} 请重新筛选核对。` : ''}`,
                  !!refreshError,
                );
              },
            ),
          'small danger',
        );
        append(
          row,
          append(el('td'), checkbox),
          target,
          stateCell,
          td(formatExpiry(item.expires_at)),
          td(formatTime(item.created_at)),
          append(
            el('td'),
            append(
              el('div', 'row-actions'),
              button('编辑', () => editLink(item, load), 'small'),
              copyButton,
              toggle,
              remove,
            ),
          ),
        );
        body.append(row);
      }
      nextCursor = result.next_cursor || '';
      previous.disabled = cursorStack.length === 0;
      next.disabled = !nextCursor;
      return null;
    } catch (error) {
      const message = errorText(error);
      showStatus(listStatus, message, true);
      return message;
    } finally {
      search.disabled = false;
    }
  }
  toolbar.addEventListener('submit', (event) => {
    event.preventDefault();
    cursor = '';
    cursorStack.length = 0;
    void load();
  });
  await load();
  return root;
}

function editLink(item?: Link, afterSave?: () => Promise<unknown>) {
  const m = modal(
    item ? '编辑链接' : '新建链接',
    item
      ? '修改对同一短码的所有公共前缀生效。高级设置仅管理员可修改。'
      : '每次创建独立短码，所有有效公共前缀共用同一映射。',
  );
  const form = el('form');
  const url = field('目标链接', 'url', item?.url || '');
  url.input.required = true;
  url.input.maxLength = 8192;
  const domain = selectField(
    '返回地址的域名前缀',
    domains.filter((d) => d.enabled && d.bound).map((d) => [d.hostname, d.hostname]),
    item?.domain,
  );
  const slug = field('自定义短码（可选）', 'text', item?.slug || '');
  slug.input.maxLength = 64;
  slug.input.pattern = '[A-Za-z0-9_\\-]+';
  if (item) {
    url.input.readOnly = true;
    slug.input.readOnly = true;
    domain.input.disabled = true;
  }
  append(form, url.node, domain.node, slug.node);
  const enabled = check('启用此链接', item?.enabled ?? true);
  const expiry = field(
    '到期时间（Asia/Singapore · UTC+8）',
    'datetime-local',
    datetimeValue(item?.expires_at ?? null),
    '留空表示永久有效。过期不会释放短码。',
  );
  const confirmation = check('跳转前展示确认页', item?.confirmation_enabled ?? false);
  const text = textField(
    '确认页文字',
    item?.confirmation_text || '',
    '仅显示纯文本；不会执行 HTML。',
  );
  const policy = selectField(
    '附加查询参数',
    [
      ['merge', '合并新参数（目标同名参数优先）'],
      ['preserve', '保持原目标地址，不附加参数'],
    ],
    item?.query_policy || 'merge',
  );
  if (item) append(form, enabled.node, expiry.node, confirmation.node, text.node, policy.node);
  const save = el('button', 'button primary', '保存');
  save.type = 'submit';
  append(form, append(el('div', 'form-actions'), button('取消', m.close), save));
  m.body.append(form);
  if (!item && !domain.input.options.length) {
    showStatus(m.status, '没有已核验绑定并启用的域名。请在 Worker 面板手动绑定后刷新核验。', true);
    save.disabled = true;
  }
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (save.disabled) return;
    save.disabled = true;
    try {
      await api(
        item ? `/api/admin/links/${encodeURIComponent(item.id)}` : '/api/admin/links',
        item ? 'PATCH' : 'POST',
        item
          ? {
              enabled: enabled.input.checked,
              expires_at: expiration(expiry.input.value),
              confirmation_enabled: confirmation.input.checked,
              confirmation_text: text.input.value,
              query_policy: policy.input.value,
            }
          : {
              url: url.input.value,
              domain: domain.input.value,
              ...(slug.input.value ? { slug: slug.input.value } : {}),
            },
      );
      m.close();
      if (afterSave) await afterSave();
      else await renderTab();
    } catch (error) {
      showStatus(m.status, errorText(error), true);
      save.disabled = false;
    }
  });
}

async function domainsPage(): Promise<HTMLElement> {
  const root = el('section');
  domains = (await api<PageResult<Domain>>('/api/admin/domains')).items;
  root.append(
    pageHeading(
      '域名配置',
      '登记 → 在 Cloudflare Worker 面板手动绑定 shortlink-new → 刷新绑定状态 → 业务启用。',
      button('登记域名 +', () => {
        const m = modal(
          '登记公共短链域名',
          '登记只保存项目业务记录。请随后在 Cloudflare Worker 面板手动绑定到 shortlink-new，再返回这里核验；本页面不会创建或修改 DNS。',
        );
        const hostname = field('域名', 'text', '', '只填写小写主机名，不含 https:// 或路径。');
        hostname.input.required = true;
        hostname.input.autocapitalize = 'off';
        hostname.input.spellcheck = false;
        const form = el('form');
        const save = el('button', 'button primary', '登记');
        save.type = 'submit';
        append(
          form,
          hostname.node,
          append(el('div', 'form-actions'), button('取消', m.close), save),
        );
        m.body.append(form);
        form.addEventListener('submit', async (event) => {
          event.preventDefault();
          save.disabled = true;
          try {
            await api('/api/admin/domains', 'POST', { hostname: hostname.input.value });
            m.close();
            await renderTab();
          } catch (error) {
            showStatus(m.status, errorText(error), true);
            save.disabled = false;
          }
        });
      }),
    ),
  );
  const panel = el('div', 'panel');
  const status = el('p');
  status.hidden = true;
  const { wrapper, body } = table([
    '公共域名',
    '实际绑定',
    '核验时间（UTC+8）',
    '业务状态',
    '操作',
  ]);
  const stateLabels = {
    unbound: '未绑定',
    pending: '绑定中',
    verified: '已完成 · 已核验绑定',
    failed: '核验失败',
  };
  for (const domain of domains) {
    const state = domain.binding_state || (domain.bound ? 'verified' : 'unbound');
    const binding = append(
      el('td'),
      statusBadge(state === 'verified', stateLabels[state], stateLabels[state]),
    );
    if (domain.binding_error) binding.append(el('span', 'secondary wrap', domain.binding_error));
    const verify = button(
      '刷新绑定状态',
      () => {
        verify.disabled = true;
        verify.textContent = '正在核验…';
        api<Domain>(`/api/admin/domains/${encodeURIComponent(domain.id)}/verify`, 'POST', {})
          .then(() => renderTab())
          .catch((error) => {
            showStatus(status, errorText(error), true);
            void api<PageResult<Domain>>('/api/admin/domains')
              .then((result) => {
                const updated = result.items.find((item) => item.id === domain.id);
                if (updated?.binding_state === 'failed') {
                  binding.replaceChildren(statusBadge(false, '', '核验失败'));
                  if (updated.binding_error)
                    binding.append(el('span', 'secondary wrap', updated.binding_error));
                }
              })
              .catch(() => {});
          })
          .finally(() => {
            verify.disabled = false;
            verify.textContent = '刷新绑定状态';
          });
      },
      'small',
    );
    const toggle = button(
      domain.enabled ? '停用' : '启用',
      () =>
        confirmAction(
          `${domain.enabled ? '停用' : '启用'}域名`,
          domain.enabled
            ? '此域名将显示“该短链域名已停用”，不再跳转或创建。其他启用域名继续使用同一短码。不会删除 CF 绑定、DNS 或全局映射。'
            : '启用已核验绑定的公共域名，所有已有短码均可通过它访问。',
          '确认',
          async () => {
            await api(`/api/admin/domains/${encodeURIComponent(domain.id)}`, 'PATCH', {
              enabled: !domain.enabled,
            });
            await renderTab();
          },
        ),
      'small',
    );
    toggle.disabled = !domain.enabled && state !== 'verified';
    body.append(
      append(
        el('tr'),
        td(domain.hostname, 'mono'),
        binding,
        append(
          el('td'),
          el('span', '', `最近检查：${formatTime(domain.last_checked_at)}`),
          el('span', 'secondary', `上次成功：${formatTime(domain.last_verified_at)}`),
        ),
        append(el('td'), statusBadge(domain.enabled)),
        append(el('td'), append(el('div', 'row-actions'), verify, toggle)),
      ),
    );
  }
  append(panel, status, domains.length ? wrapper : el('p', 'empty', '尚未登记公共短链域名。'));
  notice(
    panel,
    `核验读取实际账户、Worker 和绑定状态，不以 DNS 或数据库登记代替。所有时间：${TIME_ZONE_LABEL}。读取失败会明确标为核验失败。`,
  );
  root.append(panel);
  return root;
}

async function tokensPage(): Promise<HTMLElement> {
  const root = el('section');
  let cursor = '';
  const cursorStack: string[] = [];
  let nextCursor = '';
  root.append(
    pageHeading(
      '业务 Token',
      '仅用于机器 API 创建短链。Token 不具备管理权限。',
      append(
        el('div', 'row-actions'),
        button(
          '回到第一页',
          () => {
            cursor = '';
            cursorStack.length = 0;
            void load();
          },
          'quiet',
        ),
        button('创建 Token +', () => createToken()),
      ),
    ),
  );
  const panel = el('div', 'panel');
  const { wrapper, body } = table(['名称 / 标识', '授权域名', '状态', '到期时间（UTC+8）', '操作']);
  const status = el('p');
  status.hidden = true;
  const previous = button(
    '上一页',
    () => {
      cursor = cursorStack.pop() || '';
      void load();
    },
    'small',
  );
  const next = button(
    '下一页',
    () => {
      cursorStack.push(cursor);
      cursor = nextCursor;
      void load();
    },
    'small',
  );
  async function load() {
    previous.disabled = true;
    next.disabled = true;
    status.hidden = true;
    try {
      const result = await api<PageResult<BusinessToken>>(
        `/api/admin/tokens${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''}`,
      );
      body.replaceChildren();
      for (const item of result.items) {
        const name = td(item.name);
        name.append(el('span', 'secondary mono', item.prefix || item.id.slice(0, 8)));
        const active =
          item.revoked_at === null && (item.expires_at === null || item.expires_at > Date.now());
        const revoke = button(
          '撤销',
          () =>
            confirmAction(
              '撤销业务 Token',
              `撤销“${item.name}”后，持有它的服务器、脚本和机器人将无法再创建短链。已有短链不受影响。`,
              '确认撤销',
              async () => {
                await api(`/api/admin/tokens/${encodeURIComponent(item.id)}`, 'DELETE');
                await load();
              },
            ),
          'small danger',
        );
        revoke.disabled = item.revoked_at !== null;
        body.append(
          append(
            el('tr'),
            name,
            td(item.domains.join(', '), 'wrap'),
            append(
              el('td'),
              statusBadge(active, '可用', item.revoked_at !== null ? '已撤销' : '已过期'),
            ),
            td(formatExpiry(item.expires_at)),
            append(el('td'), revoke),
          ),
        );
      }
      if (!result.items.length) {
        const cell = td('本页没有业务 Token。需要调用 API 时，创建并保存首次展示的明文。', 'empty');
        cell.colSpan = 5;
        body.append(append(el('tr'), cell));
      }
      nextCursor = result.next_cursor || '';
      previous.disabled = cursorStack.length === 0;
      next.disabled = !nextCursor;
    } catch (error) {
      showStatus(status, errorText(error), true);
    }
  }
  append(panel, status, wrapper, append(el('div', 'pagination'), previous, next));
  notice(
    panel,
    '调用地址：POST https://link-admin.lily.lat/api/shorten。通过 Authorization: Bearer <业务 Token> 认证；网络放行不能替代 Token。',
  );
  root.append(panel);
  await load();
  return root;
}
function createToken() {
  const m = modal(
    '创建业务 Token',
    '明文只展示一次，关闭后无法找回。域名授权与访问速率均由管理员控制。',
  );
  const form = el('form');
  const name = field('名称');
  name.input.required = true;
  name.input.maxLength = 100;
  const expiry = field(
    '到期时间（Asia/Singapore · UTC+8）',
    'datetime-local',
    '',
    '留空表示永久，仍可随时撤销。',
  );
  const rate = field('每分钟最多创建', 'number', '60');
  rate.input.min = '1';
  rate.input.max = '1000';
  rate.input.required = true;
  const domainChoices = el('div', 'domain-options');
  const grants: { hostname: string; input: HTMLInputElement }[] = [];
  for (const domain of domains.filter((d) => d.bound && d.enabled)) {
    const input = el('input');
    input.type = 'checkbox';
    input.checked = true;
    domainChoices.append(append(el('label', 'domain-option'), input, domain.hostname));
    grants.push({ hostname: domain.hostname, input });
  }
  append(
    form,
    name.node,
    expiry.node,
    rate.node,
    el('p', 'hint', '允许使用的已绑定域名'),
    domainChoices,
  );
  const save = el('button', 'button primary', '创建并显示 Token');
  save.type = 'submit';
  form.append(append(el('div', 'form-actions'), button('取消', m.close), save));
  m.body.append(form);
  if (!grants.length) {
    showStatus(m.status, '请先绑定并启用一个短链域名。', true);
    save.disabled = true;
  }
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    save.disabled = true;
    try {
      const allowed = grants.filter((g) => g.input.checked).map((g) => g.hostname);
      if (!allowed.length) throw new Error('请至少选择一个授权域名。');
      const result = await api<{ token: string }>('/api/admin/tokens', 'POST', {
        name: name.input.value,
        domains: allowed,
        expires_at: expiration(expiry.input.value),
        rate_per_minute: Number(rate.input.value),
      });
      form.replaceChildren(
        el('p', 'notice', 'Token 已创建。请现在复制并放入服务器的安全配置中，关闭后不会再次展示。'),
      );
      const secret = el('code', 'secret-value', result.token);
      const copyBtn = button(
        '复制 Token',
        () => {
          void copy(secret.textContent || '', copyBtn);
        },
        'primary',
      );
      append(
        form,
        secret,
        append(
          el('div', 'form-actions'),
          copyBtn,
          button('已保存，关闭', () => {
            secret.textContent = '';
            m.close();
            void renderTab();
          }),
        ),
      );
      m.dialog.addEventListener(
        'close',
        () => {
          secret.textContent = '';
        },
        { once: true },
      );
    } catch (error) {
      showStatus(m.status, errorText(error), true);
      save.disabled = false;
    }
  });
}

function svgNode<K extends keyof SVGElementTagNameMap>(
  tag: K,
  attrs: Record<string, string> = {},
): SVGElementTagNameMap[K] {
  const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
  return node;
}
function worldMap(values: Stats['countries']): HTMLElement {
  const panel = el('div', 'panel map-panel');
  const heading = append(
    el('div', 'chart-heading'),
    el('h2', '', '世界访问分布'),
    el('span', 'hint', '近似访问事件 · 国家 / 地区'),
  );
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
  const tip = el('p', 'chart-tooltip', '悬停或聚焦有访问的地区，查看访问次数。');
  tip.setAttribute('role', 'status');
  const mapped = new Set<string>();
  for (const country of worldCountries) {
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
    const label = `${country.name}（${country.code}）：${count.toLocaleString('zh-CN')} 次${total ? ` · ${((count / total) * 100).toFixed(1)}%` : ''}`;
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
      shape.addEventListener('pointerenter', () => {
        tip.textContent = label;
      });
      shape.addEventListener('focus', () => {
        tip.textContent = label;
      });
    }
    svg.append(shape);
  }
  frame.append(svg);
  const unknown = values
    .filter((entry) => !mapped.has(entry.name.toUpperCase()))
    .reduce((sum, entry) => sum + entry.count, 0);
  const legend = append(
    el('div', 'map-legend'),
    append(el('span', 'legend-label'), el('i', 'legend-none'), '无记录'),
    el('span', '', '较少'),
    el('span', 'legend-scale'),
    el('span', '', `${actualMaximum.toLocaleString('zh-CN')} 次`),
  );
  append(panel, heading, frame, legend, tip);
  if (!total) notice(panel, '这个区间暂无真实访问数据，地图不会显示访问热点。');
  if (unknown)
    notice(
      panel,
      `未知或地图未覆盖地区：${unknown.toLocaleString('zh-CN')} 次。这些访问仍计入总数和排行。`,
    );
  panel.append(
    append(
      el('p', 'map-credit hint'),
      safeAnchor(
        '地理数据：Natural Earth · Public Domain',
        'https://www.naturalearthdata.com/about/terms-of-use/',
      ),
    ),
  );
  return panel;
}
function trendChart(daily: Stats['daily'], days: number, timezone: string): HTMLElement {
  const panel = el('div', 'panel trend');
  const maximum = Math.max(1, ...daily.map((entry) => entry.visits));
  append(
    panel,
    append(
      el('div', 'chart-heading'),
      el('h2', '', '访问趋势'),
      el('span', 'hint', `最近 ${days} 天 · 按日聚合（${timezone}）`),
    ),
  );
  if (!daily.some((entry) => entry.visits > 0)) {
    panel.append(
      el('p', 'empty', '这个区间暂无访问记录。真实访问后，趋势会在异步聚合完成后显示。'),
    );
    return panel;
  }
  const values = new Map(daily.map((entry) => [entry.date, entry.visits]));
  const offset = timezone === 'Asia/Singapore' ? 8 * 3600000 : 0;
  const today = new Date(Date.now() + offset).toISOString().slice(0, 10);
  const end = new Date(`${today}T00:00:00Z`).getTime();
  const entries = Array.from({ length: days }, (_, index) => {
    const date = new Date(end - (days - index - 1) * 86400000).toISOString().slice(0, 10);
    return { date, visits: values.get(date) || 0 };
  });
  const svg = svgNode('svg', {
    viewBox: '0 0 900 260',
    class: 'trend-svg',
    role: 'group',
    'aria-label': '每日近似访问事件趋势，可聚焦或悬停查看每日次数',
  });
  const left = 52,
    right = 884,
    top = 20,
    bottom = 214;
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
    label.textContent = Math.round((maximum * index) / 4).toLocaleString('zh-CN');
    svg.append(label);
  }
  const points = entries.map((entry, index) => ({
    ...entry,
    x: left + (index / Math.max(1, entries.length - 1)) * (right - left),
    y: bottom - (entry.visits / maximum) * (bottom - top),
  }));
  const line = points
    .map((point, index) => `${index ? 'L' : 'M'}${point.x.toFixed(2)},${point.y.toFixed(2)}`)
    .join('');
  svg.append(
    svgNode('path', { d: `${line}L${right},${bottom}L${left},${bottom}Z`, class: 'trend-area' }),
  );
  svg.append(svgNode('path', { d: line, class: 'trend-line' }));
  const tip = el('p', 'chart-tooltip', '悬停或聚焦趋势上的圆点，查看完整日期与次数。');
  tip.setAttribute('role', 'status');
  for (const [index, point] of points.entries()) {
    const text = `${point.date} · ${point.visits.toLocaleString('zh-CN')} 次近似访问`;
    const hit = svgNode('circle', {
      cx: String(point.x),
      cy: String(point.y),
      r: '6',
      class: 'trend-point',
      tabindex: '0',
      'aria-label': text,
    });
    const title = svgNode('title');
    title.textContent = text;
    hit.append(title);
    hit.addEventListener('pointerenter', () => {
      tip.textContent = text;
    });
    hit.addEventListener('focus', () => {
      tip.textContent = text;
    });
    svg.append(hit);
    if (index === 0 || index === points.length - 1 || index % Math.ceil(points.length / 6) === 0) {
      const label = svgNode('text', {
        x: String(point.x),
        y: '244',
        'text-anchor': 'middle',
        class: 'chart-axis',
      });
      label.textContent = point.date.slice(5);
      svg.append(label);
    }
  }
  append(panel, svg, tip);
  return panel;
}
async function statsPage(days = 30): Promise<HTMLElement> {
  const [stats, geography] = await Promise.all([
    api<Stats>(`/api/admin/stats?days=${days}`),
    import('./world-map'),
  ]);
  worldCountries = geography.worldCountries;
  const root = el('section');
  const range = select(
    [
      ['7', '最近 7 天'],
      ['30', '最近 30 天'],
      ['90', '最近 90 天'],
    ],
    String(days),
  );
  range.setAttribute('aria-label', '统计时间范围');
  range.addEventListener('change', () => {
    const version = ++renderVersion;
    content.replaceChildren(el('p', 'notice', '正在载入真实访问统计…'));
    statsPage(Number(range.value))
      .then((node) => {
        if (version === renderVersion) content.replaceChildren(node);
      })
      .catch((error) => {
        if (version === renderVersion) {
          content.replaceChildren();
          notice(content, errorText(error), true);
        }
      });
  });
  root.append(
    pageHeading(
      '访问统计',
      '一个短码计为一条逻辑映射。地区由 Cloudflare 提供，设备与来源为近似分类。',
      range,
    ),
  );
  const cards = el('div', 'cards');
  for (const [label, value] of [
    ['链接总数', stats.totals.links],
    ['有效链接', stats.totals.active_links],
    ['区间访问事件', stats.totals.visits],
  ])
    cards.append(
      append(
        el('div', 'panel metric'),
        el('p', '', String(label)),
        el('strong', '', Number(value || 0).toLocaleString('zh-CN')),
      ),
    );
  append(
    root,
    cards,
    worldMap(stats.countries),
    trendChart(stats.daily, days, stats.daily_timezone || 'UTC'),
  );
  const grid = el('div', 'chart-grid');
  for (const [title, values] of [
    ['地区排行', stats.countries],
    ['设备排行', stats.devices],
    ['来源排行', stats.referrers],
  ] as [string, { name: string; count: number }[]][]) {
    const panel = el('div', 'panel');
    panel.append(el('h2', '', title));
    const total = values.reduce((sum, entry) => sum + entry.count, 0);
    for (const [index, entry] of values.slice(0, 12).entries()) {
      const name =
        title === '地区排行'
          ? worldCountries.find((country) => country.code === entry.name)?.name ||
            (entry.name === 'XX' ? '未知地区' : entry.name || '未知地区')
          : title === '设备排行'
            ? {
                desktop: '电脑',
                mobile: '手机',
                tablet: '平板',
                bot: '机器人',
                other: '其他',
                unknown: '未知设备',
              }[entry.name] ||
              entry.name ||
              '未知设备'
            : { direct: '直接访问 / 未提供来源', other: '其他来源' }[entry.name] ||
              entry.name ||
              '未知来源';
      const percentage = total ? (entry.count / total) * 100 : 0;
      const fill = el('div', 'rank-fill');
      fill.style.width = `${percentage}%`;
      const row = append(
        el('div', 'rank-row'),
        append(
          el('div', 'rank-label'),
          append(el('span'), el('span', 'rank-index', String(index + 1).padStart(2, '0')), name),
          el(
            'span',
            'rank-count',
            `${entry.count.toLocaleString('zh-CN')} · ${percentage.toFixed(1)}%`,
          ),
        ),
        append(el('div', 'rank-track'), fill),
      );
      row.title = `${name}：${entry.count.toLocaleString('zh-CN')} 次，占此排行 ${percentage.toFixed(1)}%`;
      panel.append(row);
    }
    if (!values.length) panel.append(el('p', 'empty', '这个区间暂无数据。'));
    grid.append(panel);
  }
  root.append(grid);
  notice(
    root,
    `访问统计是近似事件，可能包含机器人、重复访问或异步统计丢失，不代表独立访客。日志时间使用 ${TIME_ZONE_LABEL}。趋势按 UTC 自然日聚合；历史日聚合没有事件时刻，无法准确改换日边界。`,
  );
  return root;
}

function jobState(value: unknown): string {
  const state = String(value || 'idle');
  return (
    (
      {
        complete: '已完成',
        pending: '待执行',
        uploading: '上传中',
        running: '执行中',
        retrying: '等待重试',
        idle: '等待下一次执行',
        paused: '已暂停',
        failed: '执行失败',
      } as Record<string, string>
    )[state] || state
  );
}
function schedulePanel(kind: 'backup' | 'migration', schedule: Schedule): HTMLElement {
  const backup = kind === 'backup';
  const enabled = schedule.enabled === true || schedule.enabled === 1 || schedule.enabled === '1';
  const panel = el('div', 'panel schedule-panel');
  panel.append(el('h2', '', backup ? '自动备份计划' : '自动增量迁移计划'));
  const overview = el('dl', 'schedule-overview');
  for (const [label, value] of [
    ['当前状态', jobState(schedule.state)],
    ['上次成功完成', formatTime(schedule.last_success_at)],
    [
      '下次预计执行',
      enabled
        ? schedule.next_due_at
          ? formatTime(schedule.next_due_at)
          : '暂未安排，请查看任务状态'
        : '已暂停',
    ],
    ['当前任务尝试次数', String(schedule.retry_count ?? 0)],
  ])
    overview.append(append(el('div'), el('dt', '', label), el('dd', '', value)));
  panel.append(overview);
  if (schedule.last_error_code)
    notice(
      panel,
      `最近失败原因：${schedule.last_error_code}。失败不会更新上次成功完成时间。`,
      true,
    );
  const form = el('form', 'schedule-form');
  const toggle = check(backup ? '启用自动备份' : '启用自动增量迁移', enabled);
  const interval = field(
    '执行间隔（小时）',
    'number',
    String(schedule.interval_hours),
    '1–720 小时；定时器轮询后开始，实际时间可能有延迟。',
  );
  interval.input.min = '1';
  interval.input.max = '720';
  interval.input.required = true;
  const retention = field(
    '备份文件保留天数',
    'number',
    String(schedule.retention_days ?? 30),
    '0 = 永久保留。从成功完成时间起算，清理到期的私有 R2 备份文件，不清理在线映射。',
  );
  retention.input.min = '0';
  retention.input.max = '3650';
  retention.input.required = true;
  const status = el('p');
  status.hidden = true;
  const save = el('button', 'button primary', '保存计划');
  save.type = 'submit';
  append(
    form,
    toggle.node,
    append(el('div', 'field-row'), interval.node, backup ? retention.node : undefined),
    status,
    append(el('div', 'form-actions'), save),
  );
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    save.disabled = true;
    try {
      await api('/api/admin/settings', 'PUT', {
        [backup ? 'backup_enabled' : 'migration_enabled']: Number(toggle.input.checked),
        [backup ? 'backup_interval_hours' : 'migration_interval_hours']: Number(
          interval.input.value,
        ),
        ...(backup ? { backup_retention_days: Number(retention.input.value) } : {}),
      });
      await renderTab();
    } catch (error) {
      showStatus(status, errorText(error), true);
      save.disabled = false;
    }
  });
  append(
    panel,
    form,
    el(
      'p',
      'hint',
      `时间：${TIME_ZONE_LABEL}。上次成功只表示已成功完成的任务；失败及重试另行显示。`,
    ),
  );
  return panel;
}
async function backupsPage(): Promise<HTMLElement> {
  const result = await api<PageResult<Item> & { schedule: Schedule }>('/api/admin/backups');
  const root = el('section');
  root.append(
    pageHeading(
      '自动备份',
      '一致性数据备份自动保存到本项目独立私有 R2，管理员设置计划并查看状态。',
      button(
        '刷新状态',
        () => {
          void renderTab();
        },
        'quiet',
      ),
    ),
  );
  root.append(schedulePanel('backup', result.schedule));
  const panel = el('div', 'panel');
  panel.append(el('h2', '', '备份记录'));
  const { wrapper, body } = table([
    '任务',
    '创建 / 完成时间（UTC+8）',
    '大小 / 记录数',
    '状态 / 失败原因',
    '耗时 / 重试',
  ]);
  for (const item of result.items) {
    const time = append(
      el('td'),
      el('span', '', `创建：${formatTime(item.created_at)}`),
      el('span', 'secondary', `完成：${formatTime(item.completed_at)}`),
    );
    const size = Number(item.size || 0);
    const record = append(
      el('td'),
      el(
        'span',
        '',
        size < 1048576 ? `${(size / 1024).toFixed(1)} KB` : `${(size / 1048576).toFixed(2)} MB`,
      ),
      el('span', 'secondary', `${Number(item.records || 0).toLocaleString('zh-CN')} 条记录`),
    );
    const state = append(
      el('td'),
      statusBadge(item.status === 'complete', jobState(item.status), jobState(item.status)),
    );
    if (item.last_error_code)
      state.append(el('span', 'secondary wrap', String(item.last_error_code)));
    if (item.retry_at)
      state.append(el('span', 'secondary', `预计重试：${formatTime(item.retry_at)}`));
    const duration =
      item.duration_ms === null || item.duration_ms === undefined
        ? '—'
        : `${(Number(item.duration_ms) / 1000).toFixed(1)} 秒`;
    body.append(
      append(
        el('tr'),
        td(String(item.id || ''), 'mono wrap'),
        time,
        record,
        state,
        append(
          el('td'),
          el('span', '', duration),
          el('span', 'secondary', `尝试 ${Number(item.attempts || 0)} 次`),
        ),
      ),
    );
  }
  panel.append(
    result.items.length
      ? wrapper
      : el('p', 'empty', '尚无备份记录。启用计划后，定时任务会自动创建第一份备份。'),
  );
  root.append(panel);
  notice(
    root,
    '备份对象仅保存在私有 R2。任务互斥、失败重试与保留期清理由系统执行；恢复和完整性核验使用受保护的内部工具。',
  );
  return root;
}

async function recordsPage(kind: string): Promise<HTMLElement> {
  const migrations = kind === 'migrations';
  const root = el('section');
  root.append(
    pageHeading(
      migrations ? '迁移记录' : '审计日志',
      migrations
        ? '定时只读扫描旧 KV，向本项目新 D1 增量补齐。保留管理员编辑、停用与删除决定。'
        : '记录管理员及系统的关键操作，便于核对变更。日志不会展示业务 Token 明文。',
    ),
  );
  const panel = el('div', 'panel');
  const status = el('p');
  status.hidden = true;
  const runSummary = el('div');
  const { wrapper, body } = table(
    migrations ? ['结果', '记录数', '说明'] : ['发生时间（UTC+8）', '操作者', '操作', '对象'],
  );
  let nextCursor = '';
  const next = button(
    '加载更多',
    () => {
      void load(nextCursor);
    },
    'small',
  );
  next.hidden = true;
  async function load(cursor = '') {
    next.disabled = true;
    try {
      const result = await api<
        PageResult<Item> & { run?: MigrationRun | null; schedule?: Schedule }
      >(
        `/api/admin/${migrations ? 'migrations' : 'audit'}${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''}`,
      );
      if (migrations) {
        runSummary.replaceChildren();
        if (result.schedule) runSummary.append(schedulePanel('migration', result.schedule));
        const run = result.run;
        if (!run) notice(runSummary, '暂无执行记录。启用自动迁移后，下一次调度会开始只读扫描。');
        else {
          const state =
            run.state === 'complete'
              ? '本轮扫描已结束'
              : run.state === 'running'
                ? '本轮尚未完成'
                : '本轮执行失败';
          notice(
            runSummary,
            `${state} · 已观察 ${run.processed.toLocaleString('zh-CN')} 条 · 导入 ${run.imported} · 已有一致映射 ${run.unchanged} · 跳过 ${run.skipped} · 冲突 ${run.conflicts} · 未知 ${run.unknown}`,
            run.state !== 'complete' || run.conflicts > 0 || run.unknown > 0,
          );
          runSummary.append(append(el('p', 'hint wrap'), '运行标识：', el('code', 'mono', run.id)));
          runSummary.append(
            el(
              'p',
              'hint',
              `进度更新时间：${formatTime(run.updated_at)} · 成功完成时间：${formatTime(run.completed_at)} · ${TIME_ZONE_LABEL}`,
            ),
          );
          if (run.last_error_code)
            notice(
              runSummary,
              `失败原因：${run.last_error_code} · 已尝试 ${run.attempts || 0} 次 · 预计重试：${formatTime(run.retry_at)}`,
              true,
            );
          if (run.state !== 'complete')
            notice(
              runSummary,
              '自动计划支持断点恢复。达到重试上限后需先排查失败原因；暂停只停止后续调度，不撤销已迁移数据。',
            );
          if (run.conflicts || run.unknown)
            runSummary.append(
              el(
                'p',
                'notice error',
                '冲突或未知记录仍需单独核对，本轮迁移尚未全部验证通过。原有映射不会被覆盖。',
              ),
            );
          if (run.digest)
            runSummary.append(
              append(el('p', 'hint wrap'), '核验摘要：', el('code', 'mono', run.digest)),
            );
        }
      }
      for (const item of result.items) {
        const row = migrations
          ? append(
              el('tr'),
              td(item.status),
              td(Number(item.count || 0).toLocaleString('zh-CN')),
              td(item.reason || '—', 'wrap'),
            )
          : append(
              el('tr'),
              td(formatTime(item.created_at)),
              td(item.actor || item.actor_email),
              td(item.action),
              td(item.entity_id || '—', 'wrap'),
            );
        body.append(row);
      }
      if (!body.children.length) {
        const row = el('tr');
        const cell = td(migrations ? '暂无本轮观察记录。' : '暂无审计记录。', 'empty');
        cell.colSpan = migrations ? 3 : 4;
        row.append(cell);
        body.append(row);
      }
      nextCursor = result.next_cursor || '';
      next.hidden = !nextCursor;
    } catch (error) {
      showStatus(status, errorText(error), true);
    } finally {
      next.disabled = false;
    }
  }
  append(panel, status, runSummary, wrapper, append(el('div', 'pagination'), next));
  root.append(panel);
  await load();
  if (migrations)
    notice(
      root,
      '最近一轮扫描按结果与原因汇总，包含冲突与未知记录。KV 游标扫描不是原子快照，旧系统新增会由后续增量扫描发现。管理员彻底删除的短码保留占用标记，不会重新导入。迁移不会修改旧 KV 或切换生产流量。',
    );
  return root;
}

async function settingsPage(): Promise<HTMLElement> {
  const settings = await api<Item>('/api/admin/settings');
  const root = el('section');
  root.append(
    pageHeading(
      '系统设置',
      '管理限流、自动任务、数据保留与应用错误页文字。时间统一展示为 Asia/Singapore（UTC+8）。',
    ),
  );
  const form = el('form');
  const grid = el('div', 'settings-grid');
  const policies = el('div', 'panel');
  policies.append(el('h2', '', '限流、数据保留与自动任务'));
  const controls = new Map<string, HTMLInputElement | HTMLTextAreaElement>();
  for (const [key, label, fallback, min, max, hint] of [
    [
      'anonymous_rate_per_minute',
      '匿名创建每分钟上限',
      10,
      1,
      1000,
      '服务端按匿名来源施加限流；不保存匿名创建历史。',
    ],
    [
      'domain_rate_per_minute',
      '每域名每分钟创建上限',
      120,
      1,
      1000,
      '匿名与机器创建共同受域名限流约束。',
    ],
    [
      'analytics_retention_days',
      '访问聚合保留天数',
      90,
      0,
      3650,
      '单位：天。按 UTC 统计日计算，仅清理访问聚合。0 = 永久保留，不按时间清理。',
    ],
    [
      'audit_retention_days',
      '审计记录保留天数',
      365,
      0,
      3650,
      '单位：天。从记录发生时间起算，仅清理审计记录。0 = 永久保留。',
    ],
    [
      'backup_retention_days',
      '备份文件保留天数',
      30,
      0,
      3650,
      '单位：天。从成功完成时间起算，仅清理到期的 R2 备份文件。0 = 永久保留。',
    ],
    [
      'backup_interval_hours',
      '自动备份间隔（小时）',
      24,
      1,
      720,
      '1–720 小时。由 Worker 定时任务自动执行，计划与状态见自动备份页。',
    ],
    [
      'migration_interval_hours',
      '自动迁移间隔（小时）',
      24,
      1,
      720,
      '1–720 小时。仅同步固定旧 KV 到新 D1，不触发部署。',
    ],
  ] as [string, string, number, number, number, string][]) {
    const control = field(label, 'number', String(settings[key] ?? fallback), hint);
    control.input.required = true;
    control.input.min = String(min);
    control.input.max = String(max);
    controls.set(key, control.input);
    policies.append(control.node);
  }
  for (const [key, label] of [
    ['backup_enabled', '启用自动 R2 备份'],
    ['migration_enabled', '启用旧 KV 自动增量迁移'],
  ]) {
    const control = check(label, String(settings[key] ?? '1') === '1');
    controls.set(key, control.input);
    policies.append(control.node);
  }
  const errors = el('div', 'panel');
  errors.append(el('h2', '', '应用错误页文字'));
  for (const [key, label, fallback] of [
    ['error_403', '403 无权限', '你没有权限访问此链接。'],
    ['error_404', '404 未找到', '这个短链接不存在。'],
    ['error_disabled', '停用或过期', '这个链接已停用或到期。'],
    ['error_500', '其他应用错误', '服务暂时不可用，请稍后再试。'],
  ]) {
    const control = textField(
      label,
      String(settings[key] ?? fallback),
      '纯文本，最多 500 字符。边缘 WAF 或 Access 拦截页面由 Cloudflare 独立管理。',
    );
    control.input.maxLength = 500;
    controls.set(key, control.input);
    errors.append(control.node);
  }
  append(grid, policies, errors);
  const status = el('p');
  status.hidden = true;
  const save = el('button', 'button primary', '保存设置');
  save.type = 'submit';
  append(form, grid, status, append(el('div', 'form-actions'), save));
  root.append(form);
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    save.disabled = true;
    try {
      const payload: Item = {};
      for (const [key, control] of controls)
        payload[key] =
          control instanceof HTMLInputElement
            ? control.type === 'checkbox'
              ? Number(control.checked)
              : Number(control.value)
            : control.value;
      await api('/api/admin/settings', 'PUT', payload);
      showStatus(status, '设置已保存。');
    } catch (error) {
      showStatus(status, errorText(error), true);
    } finally {
      save.disabled = false;
    }
  });
  return root;
}

if (location.pathname === '/admin' || location.pathname.startsWith('/admin/')) void adminPage();
else void publicPage();
