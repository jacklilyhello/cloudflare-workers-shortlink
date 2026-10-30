import './styles.css';
import './public/creation.css';
import {
  formatTime,
  datetimeValue,
  expiration,
  publicUrls,
  auditActor,
  TIME_ZONE_LABEL,
  type CreationResult,
} from './presentation';
import type { AuditActorIdentity, AuditFilterOptions } from '../src/audit-identity';
import { auditActionLabel, auditFilterParams } from './audit-filters';
import { pageContentEditor } from './interstitial-editor';
import { worldMap, trendChart, rankings, type AnalyticsStats } from './analytics';
import {
  ERROR_PAGE_HTML_MAX_BYTES,
  type ErrorPage,
  type ErrorPageKey,
} from '../src/error-page-config';
import statusStyles from './public/status.css?raw';

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
  public_service_allowed?: boolean;
  interstitial_enabled: boolean;
  interstitial_delay: number;
  interstitial_html: string;
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
  source_domain: string;
  current_domain: string | null;
  short_url: string | null;
  url: string;
  enabled: boolean;
  expires_at: number | null;
  confirmation_enabled: boolean;
  confirmation_text: string;
  confirmation_mode: 'text' | 'html';
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
  rate_per_minute: number;
};
type Stats = AnalyticsStats & {
  timezone?: string;
  totals: { links: number; visits: number; active_links: number };
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
function shortUrl(link: Pick<Link, 'current_domain' | 'short_url'>): string | null {
  if (!link.current_domain || !link.short_url) return null;
  return (
    publicUrls({ domain: link.current_domain, short_url: link.short_url, slug: '' })[0]
      ?.short_url ?? null
  );
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
  INVALID_SLUG: '短码只接受字母、数字、下划线和连字符，最长 64 个字符，且不能使用系统保留路径。',
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
  const page = el('div', 'page public-page');
  const header = append(el('header', 'topbar'), brand(), themeButton());
  const main = el('main', 'public-main');
  main.id = 'main';
  append(
    main,
    append(
      el('div', 'public-heading'),
      el('p', 'eyebrow', 'A shorter way to connect'),
      el('h1', '', '长链接，轻一点。'),
      el('p', 'intro', '一次生成，多域名通用。让每一次分享，都简单一点。'),
    ),
  );
  const form = el('form', 'creation-card glass');
  form.autocomplete = 'off';
  const url = field('长链接', 'url');
  url.input.required = true;
  url.input.placeholder = 'https://example.com/your-long-link';
  url.input.maxLength = 8192;
  url.input.autocapitalize = 'off';
  url.input.spellcheck = false;
  const slugLabel = el('label', 'field slug-field');
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
    el('span', 'hint', '留空自动生成 · 支持字母、数字、下划线或连字符，区分大小写。'),
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
  append(
    form,
    url.node,
    slugLabel,
    append(el('div', 'creation-actions'), captcha, submit),
    status,
    result,
  );
  main.append(form);
  main.append(
    append(
      el('footer', 'public-footer'),
      el('p', '', '无需登录。结果仅在当前页面展示，请及时复制保存。'),
      append(
        el('p', 'new-domain'),
        '域名无法访问？',
        safeAnchor('获取新域名 ↗', 'https://sink.lily.lat/link-fb'),
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
        result.replaceChildren(
          append(
            el('div', 'result-heading'),
            el('p', 'result-label', '✓ 短链接已生成'),
            el('p', 'hint result-hint', '以下域名通向同一目标，任选一个分享。'),
          ),
        );
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
        copyButtons[0].focus({ preventScroll: true });
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
  ['error-pages', '应用错误页', '▤'],
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
                : id === 'error-pages'
                  ? await errorPagesPage()
                  : id === 'settings'
                    ? await settingsPage()
                    : await auditPage();
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

function auditActorCell(item: Item): HTMLTableCellElement {
  const actor = auditActor(item.actor_identity as AuditActorIdentity | undefined, item.actor);
  const cell = td(actor.title, 'wrap');
  for (const detail of actor.details) cell.append(el('span', 'secondary wrap', detail));
  return cell;
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
  const toolbar = el('form', 'toolbar link-filters');
  const q = el('input');
  q.type = 'search';
  q.placeholder = '搜索短码或目标链接';
  q.setAttribute('aria-label', '搜索短码或目标链接');
  const domain = select([
    ['', '所有来源域名'],
    ...domains.map((d) => [d.hostname, d.hostname] as [string, string]),
  ]);
  domain.setAttribute('aria-label', '按创建或迁移时的来源域名筛选');
  const statusFilter = select([
    ['', '所有状态'],
    ['active', '有效'],
    ['disabled', '已停用'],
    ['expired', '已过期'],
  ]);
  statusFilter.setAttribute('aria-label', '按状态筛选');
  const confirmationFilter = select([
    ['', '所有确认页设置'],
    ['enabled', '已开启确认页覆盖'],
  ]);
  confirmationFilter.setAttribute('aria-label', '按链接确认页覆盖状态筛选');
  const search = el('button', 'button small', '筛选');
  search.type = 'submit';
  append(toolbar, q, domain, statusFilter, confirmationFilter, search);
  panel.append(toolbar);
  const listStatus = el('p');
  listStatus.hidden = true;
  const bulk = el('div', 'bulk-bar');
  bulk.hidden = true;
  const selected = new Set<string>();
  const count = el('span');
  const bulkAction = (action: string) => {
    const ids = [...selected];
    confirmAction(
      action === 'disable' ? '批量停用链接' : '批量启用链接',
      `将更新 ${ids.length} 条已选择链接。链接映射与短码会继续保留。`,
      '确认更新',
      async () => {
        await api('/api/admin/links/bulk', 'POST', { ids, action });
        await load();
      },
    );
  };
  const bulkConfirmation = () => {
    const ids = [...selected];
    const choose = modal(
      '批量设置确认页',
      `已选择本页 ${ids.length} 条链接。已开启的链接确认页优先于访问域名的中间页。`,
    );
    const edit = (action: 'enable' | 'disable' | 'edit') => {
      choose.close();
      if (action !== 'edit') {
        confirmAction(
          action === 'enable' ? '批量开启确认页' : '批量关闭确认页',
          action === 'enable'
            ? `将为 ${ids.length} 条链接开启确认页覆盖，保留各自已有内容；未设置内容时显示默认确认说明。`
            : `将关闭 ${ids.length} 条链接的确认页覆盖，保留内容。访问时使用对应域名的中间页设置。`,
          action === 'enable' ? '确认开启' : '确认关闭',
          async () => {
            await api('/api/admin/links/bulk', 'POST', {
              ids,
              action: 'confirmation',
              confirmation_enabled: action === 'enable',
            });
            await load();
          },
        );
        return;
      }
      const m = modal(
        '批量编辑确认页内容',
        `统一替换 ${ids.length} 条链接的确认页内容和格式。各链接原有的确认页开启状态保持不变。`,
      );
      m.dialog.classList.add('page-editor-dialog');
      const editor = pageContentEditor({});
      const form = el('form');
      const save = el('button', 'button primary', '保存内容');
      save.type = 'submit';
      append(form, editor.node, append(el('div', 'form-actions'), button('取消', m.close), save));
      m.body.append(form);
      form.addEventListener('submit', async (event) => {
        event.preventDefault();
        save.disabled = true;
        try {
          const content = editor.value();
          await api('/api/admin/links/bulk', 'POST', {
            ids,
            action: 'confirmation',
            confirmation_mode: content.mode,
            confirmation_text: content.content,
          });
          m.close();
          await load();
        } catch (error) {
          showStatus(m.status, errorText(error), true);
          save.disabled = false;
        }
      });
    };
    choose.body.append(
      append(
        el('div', 'confirmation-actions'),
        button('开启确认页', () => edit('enable')),
        button('关闭确认页', () => edit('disable')),
        button('编辑确认页内容', () => edit('edit'), 'primary'),
      ),
    );
  };
  append(
    bulk,
    count,
    button('停用', () => bulkAction('disable'), 'small danger'),
    button('启用', () => bulkAction('enable'), 'small'),
    button('确认页', bulkConfirmation, 'small'),
    button(
      '设置到期',
      () => {
        const ids = [...selected];
        const m = modal('批量设置到期时间', `修改 ${ids.length} 条链接。留空表示永久有效。`);
        const expiry = field('到期时间（Asia/Singapore · UTC+8）', 'datetime-local');
        m.body.append(expiry.node);
        const save = button(
          '保存',
          async () => {
            save.disabled = true;
            try {
              await api('/api/admin/links/bulk', 'POST', {
                ids,
                action: 'expiry',
                expires_at: expiration(expiry.input.value),
              });
              m.close();
              await load();
            } catch (error) {
              showStatus(m.status, errorText(error), true);
              save.disabled = false;
            }
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
  const selectPage = check('全选本页');
  selectPage.node.className = 'page-select';
  const selectCell = wrapper.querySelector('thead th')!;
  selectCell.replaceChildren(selectPage.node);
  const pageChecks = new Map<string, HTMLInputElement>();
  selectPage.input.addEventListener('change', () => {
    for (const [id, checkbox] of pageChecks) {
      checkbox.checked = selectPage.input.checked;
      if (checkbox.checked) selected.add(id);
      else selected.delete(id);
    }
    refreshBulk();
  });
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
    selectPage.input.checked = pageChecks.size > 0 && selected.size === pageChecks.size;
    selectPage.input.indeterminate = selected.size > 0 && selected.size < pageChecks.size;
    selectPage.input.disabled = pageChecks.size === 0;
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
      if (confirmationFilter.value) params.set('confirmation', confirmationFilter.value);
      if (cursor) params.set('cursor', cursor);
      const result = await api<PageResult<Link>>(`/api/admin/links?${params}`);
      body.replaceChildren();
      selected.clear();
      pageChecks.clear();
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
        pageChecks.set(item.id, checkbox);
        checkbox.setAttribute('aria-label', `选择 ${item.slug}`);
        checkbox.addEventListener('change', () => {
          if (checkbox.checked) selected.add(item.id);
          else selected.delete(item.id);
          refreshBulk();
        });
        const address = shortUrl(item);
        const target = append(
          el('td', 'link-cell'),
          address
            ? safeAnchor(`${item.current_domain}/${item.slug}`, address)
            : el('span', '', `${item.slug}（暂无可用公共域名）`),
          el('span', 'secondary', `来源域名：${item.source_domain}`),
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
          if (item.confirmation_enabled)
            stateCell.append(el('span', 'secondary', '确认页覆盖已开启'));
        };
        refreshState();
        const copyButton = button(
          '复制',
          () => {
            if (address) void copy(address, copyButton);
          },
          'small',
        );
        copyButton.disabled = !address;
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
              `短码：${item.slug}\n目标：${item.url}\n同一短码在所有公共前缀下都会失效，在线映射将被删除，原短码不再复用。历史备份按原保留策略处理，不会立即抹除。`,
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
      refreshBulk();
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
  if (item) m.dialog.classList.add('page-editor-dialog');
  const form = el('form');
  const url = field('目标链接', 'url', item?.url || '');
  url.input.required = true;
  url.input.maxLength = 8192;
  const domain = selectField(
    item ? '来源域名（保留）' : '返回地址的域名前缀',
    item
      ? [[item.source_domain, item.source_domain]]
      : domains
          .filter(
            (d) =>
              d.enabled &&
              d.bound &&
              d.binding_state === 'verified' &&
              d.public_service_allowed !== false,
          )
          .map((d) => [d.hostname, d.hostname]),
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
  const confirmation = check(
    '跳转前展示确认页（优先于域名中间页）',
    item?.confirmation_enabled ?? false,
  );
  const editor = pageContentEditor({
    mode: item?.confirmation_mode ?? 'text',
    value: item?.confirmation_text || '',
  });
  const policy = selectField(
    '附加查询参数',
    [
      ['merge', '合并新参数（目标同名参数优先）'],
      ['preserve', '保持原目标地址，不附加参数'],
      ['origin', '覆盖为目标域名根目录（移除路径、参数和片段）'],
    ],
    item?.query_policy || 'merge',
  );
  const policyHint = el('span', 'hint');
  policyHint.id = `hint-${++controlId}`;
  policy.input.setAttribute('aria-describedby', policyHint.id);
  const refreshPolicyHint = () => {
    policyHint.textContent =
      policy.input.value === 'origin'
        ? '只跳到目标域名根目录，移除路径、查询参数和片段；原始目标地址仍会保留。'
        : policy.input.value === 'preserve'
          ? '忽略访问短链时 ? 后的所有参数，按保存的完整目标地址跳转。'
          : '把访问短链时 ? 后的新参数追加到目标；同名参数保留目标原值。例：目标 ?id=1，短链带 ?id=2&from=share，结果为 ?id=1&from=share。';
  };
  policy.input.addEventListener('change', refreshPolicyHint);
  refreshPolicyHint();
  policy.node.append(policyHint);
  if (item) append(form, enabled.node, expiry.node, confirmation.node, editor.node, policy.node);
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
      const content = editor.value();
      await api(
        item ? `/api/admin/links/${encodeURIComponent(item.id)}` : '/api/admin/links',
        item ? 'PATCH' : 'POST',
        item
          ? {
              enabled: enabled.input.checked,
              expires_at: expiration(expiry.input.value),
              confirmation_enabled: confirmation.input.checked,
              confirmation_text: content.content,
              confirmation_mode: content.mode,
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
    '跳转中间页',
    '操作',
  ]);
  const stateLabels = {
    unbound: '未绑定',
    pending: '绑定中',
    verified: '已完成 · 已核验绑定',
    failed: '核验失败',
  };
  for (const initialDomain of domains) {
    let domain = initialDomain;
    const hostnameCell = el('td', 'mono');
    const binding = el('td');
    const times = el('td');
    const businessState = el('td');
    const interstitialState = el('td');
    const verify = button(
      '刷新绑定状态',
      () => {
        verify.disabled = true;
        verify.textContent = '正在核验…';
        api<Domain>(`/api/admin/domains/${encodeURIComponent(domain.id)}/verify`, 'POST', {})
          .then(() => renderTab())
          .catch(async (error) => {
            const originalError = errorText(error);
            showStatus(status, originalError, true);
            try {
              const result = await api<PageResult<Domain>>('/api/admin/domains');
              const updated = result.items.find((item) => item.id === domain.id);
              if (!updated) throw new Error('服务没有返回该域名记录，请重新载入核对。');
              domains = result.items;
              domain = updated;
              renderRow();
            } catch (refreshError) {
              toggle.disabled = true;
              showStatus(
                status,
                `${originalError} 状态刷新失败：${errorText(refreshError)} 请重新载入页面核对。`,
                true,
              );
            }
          })
          .finally(() => {
            verify.disabled = domain.public_service_allowed === false;
            verify.textContent = '刷新绑定状态';
          });
      },
      'small',
    );
    const toggle = button(
      '',
      () => {
        const enabled = !domain.enabled;
        confirmAction(
          `${enabled ? '启用' : '停用'}域名`,
          enabled
            ? '启用已核验绑定的公共域名，所有已有短码均可通过它访问。'
            : '此域名将显示“该短链域名已停用”，不再跳转或创建。其他启用域名继续使用同一短码。不会删除 CF 绑定、DNS 或全局映射。',
          '确认',
          async () => {
            await api(`/api/admin/domains/${encodeURIComponent(domain.id)}`, 'PATCH', { enabled });
            await renderTab();
          },
        );
      },
      'small',
    );
    function renderRow() {
      const state = domain.binding_state || (domain.bound ? 'verified' : 'unbound');
      hostnameCell.textContent = domain.hostname;
      binding.replaceChildren(
        statusBadge(state === 'verified' && domain.bound, stateLabels[state], stateLabels[state]),
      );
      if (domain.binding_error) binding.append(el('span', 'secondary wrap', domain.binding_error));
      times.replaceChildren(
        el('span', '', `最近检查：${formatTime(domain.last_checked_at)}`),
        el('span', 'secondary', `上次成功：${formatTime(domain.last_verified_at)}`),
      );
      businessState.replaceChildren(
        domain.public_service_allowed === false
          ? statusBadge(false, '已停止服务', '已停止服务')
          : statusBadge(domain.enabled),
      );
      interstitialState.replaceChildren(
        statusBadge(!!domain.interstitial_enabled, '已开启', '未开启'),
      );
      if (domain.interstitial_enabled)
        interstitialState.append(
          el('span', 'secondary', `展示 ${domain.interstitial_delay ?? 0} 秒后继续`),
        );
      verify.disabled = domain.public_service_allowed === false;
      toggle.textContent = domain.enabled ? '停用' : '启用';
      toggle.disabled =
        !domain.enabled &&
        (domain.public_service_allowed === false || !domain.bound || state !== 'verified');
    }
    renderRow();
    body.append(
      append(
        el('tr'),
        hostnameCell,
        binding,
        times,
        businessState,
        interstitialState,
        append(
          el('td'),
          append(
            el('div', 'row-actions'),
            button('中间页配置', () => editDomainInterstitial(domain), 'small'),
            verify,
            toggle,
          ),
        ),
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

function editDomainInterstitial(domain: Domain) {
  const m = modal(
    `${domain.hostname} · 跳转中间页`,
    '仅通过此域名访问时使用本设置。单条链接已开启确认页时，优先展示链接确认页。域名或链接停用、过期时不会跳转。',
  );
  m.dialog.classList.add('page-editor-dialog');
  const form = el('form');
  const enabled = check('启用此域名的跳转中间页', !!domain.interstitial_enabled);
  const delay = field(
    '中间页展示时间（秒）',
    'number',
    String(domain.interstitial_delay ?? 0),
    '0–300 秒。倒计时结束后自动前往目标；单条链接确认页仍需访客手动确认。',
  );
  delay.input.min = '0';
  delay.input.max = '300';
  delay.input.step = '1';
  delay.input.required = true;
  const editor = pageContentEditor({ value: domain.interstitial_html || '', htmlOnly: true });
  const save = el('button', 'button primary', '保存配置');
  save.type = 'submit';
  append(
    form,
    enabled.node,
    delay.node,
    editor.node,
    append(el('div', 'form-actions'), button('取消', m.close), save),
  );
  m.body.append(form);
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    save.disabled = true;
    try {
      const seconds = Number(delay.input.value);
      if (!Number.isInteger(seconds) || seconds < 0 || seconds > 300)
        throw new Error('展示时间须为 0–300 之间的整数秒。');
      const content = editor.value();
      await api(`/api/admin/domains/${encodeURIComponent(domain.id)}`, 'PATCH', {
        interstitial_enabled: enabled.input.checked,
        interstitial_delay: seconds,
        interstitial_html: content.content,
      });
      m.close();
      await renderTab();
    } catch (error) {
      showStatus(m.status, errorText(error), true);
      save.disabled = false;
    }
  });
}

async function tokensPage(): Promise<HTMLElement> {
  const root = el('section');
  let cursor = '';
  const cursorStack: string[] = [];
  let nextCursor = '';
  let loadVersion = 0;
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
  const { wrapper, body } = table([
    '名称 / 标识',
    '授权域名',
    '每分钟最多创建',
    '状态',
    '到期时间（UTC+8）',
    '操作',
  ]);
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
    const version = ++loadVersion;
    previous.disabled = true;
    next.disabled = true;
    status.hidden = true;
    try {
      const result = await api<PageResult<BusinessToken>>(
        `/api/admin/tokens${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''}`,
      );
      if (version !== loadVersion) return;
      body.replaceChildren();
      for (const item of result.items) {
        const name = td(item.name);
        name.append(el('span', 'secondary mono', item.prefix || item.id.slice(0, 8)));
        const active =
          item.revoked_at === null && (item.expires_at === null || item.expires_at > Date.now());
        const edit = button('编辑', () => editToken(item, load), 'small');
        edit.disabled = item.revoked_at !== null;
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
        const remove = button(
          '彻底删除',
          () =>
            confirmAction(
              '彻底删除业务 Token',
              `彻底删除“${item.name}”后，该 Token 将立即失效且无法恢复，并从 Token 管理和审计操作者选项中移除。已有短链接和历史审计记录会保留。`,
              '确认彻底删除',
              async () => {
                await api(`/api/admin/tokens/${encodeURIComponent(item.id)}/delete`, 'POST', {
                  confirm: true,
                });
                cursor = '';
                cursorStack.length = 0;
                nextCursor = '';
                await load();
              },
            ),
          'small danger',
        );
        body.append(
          append(
            el('tr'),
            name,
            td(item.domains.join(', '), 'wrap'),
            td(`${item.rate_per_minute.toLocaleString()} 条`),
            append(
              el('td'),
              statusBadge(active, '可用', item.revoked_at !== null ? '已撤销' : '已过期'),
            ),
            td(formatExpiry(item.expires_at)),
            append(el('td'), append(el('div', 'row-actions'), edit, revoke, remove)),
          ),
        );
      }
      if (!result.items.length) {
        const cell = td('本页没有业务 Token。需要调用 API 时，创建并保存首次展示的明文。', 'empty');
        cell.colSpan = 6;
        body.append(append(el('tr'), cell));
      }
      nextCursor = result.next_cursor || '';
      previous.disabled = cursorStack.length === 0;
      next.disabled = !nextCursor;
    } catch (error) {
      if (version === loadVersion) showStatus(status, errorText(error), true);
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
function editToken(item: BusinessToken, afterSave: () => Promise<unknown>) {
  const m = modal(
    '编辑业务 Token',
    '修改名称、授权域名、到期时间和创建速率。保存后立即生效，继续使用原有 Token。',
  );
  const form = el('form');
  const name = field('名称', 'text', item.name);
  name.input.required = true;
  name.input.maxLength = 100;
  const expires = field(
    '到期时间（Asia/Singapore · UTC+8）',
    'datetime-local',
    datetimeValue(item.expires_at),
    '留空表示永久。已过期且未撤销的 Token 可重新设置有效期。',
  );
  const rate = field('每分钟最多创建', 'number', String(item.rate_per_minute));
  rate.input.min = '1';
  rate.input.max = '1000';
  rate.input.step = '1';
  rate.input.required = true;
  const domainChoices = el('div', 'domain-options');
  const eligible = domains
    .filter(
      (d) =>
        d.bound &&
        d.enabled &&
        d.binding_state === 'verified' &&
        d.public_service_allowed !== false,
    )
    .map((d) => d.hostname);
  const grants = [...new Set([...eligible, ...item.domains])].map((hostname) => {
    const input = el('input');
    input.type = 'checkbox';
    input.checked = item.domains.includes(hostname);
    domainChoices.append(
      append(
        el('label', 'domain-option'),
        input,
        `${hostname}${eligible.includes(hostname) ? '' : '（当前不可用）'}`,
      ),
    );
    return { hostname, input };
  });
  const save = el('button', 'button primary', '保存修改');
  save.type = 'submit';
  append(
    form,
    name.node,
    expires.node,
    rate.node,
    el('p', 'hint', '允许使用的已绑定域名；调整授权时须移除当前不可用的域名。'),
    domainChoices,
    append(el('div', 'form-actions'), button('取消', m.close), save),
  );
  m.body.append(form);
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    save.disabled = true;
    try {
      const body: Item = {};
      if (name.input.value !== item.name) body.name = name.input.value;
      if (expires.input.value !== datetimeValue(item.expires_at))
        body.expires_at = expiration(expires.input.value);
      if (Number(rate.input.value) !== item.rate_per_minute)
        body.rate_per_minute = Number(rate.input.value);
      const selected = grants.filter((g) => g.input.checked).map((g) => g.hostname);
      if (
        selected.length !== item.domains.length ||
        selected.some((d) => !item.domains.includes(d))
      ) {
        if (!selected.length) throw new Error('请至少选择一个授权域名。');
        if (selected.some((d) => !eligible.includes(d)))
          throw new Error('请移除当前不可用的域名后再保存授权。');
        body.domains = selected;
      }
      if (!Object.keys(body).length) throw new Error('没有要保存的修改。');
      await api(`/api/admin/tokens/${encodeURIComponent(item.id)}`, 'PATCH', body);
      m.close();
      await afterSave();
    } catch (error) {
      showStatus(m.status, errorText(error), true);
      save.disabled = false;
    }
  });
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
  for (const domain of domains.filter(
    (d) =>
      d.bound && d.enabled && d.binding_state === 'verified' && d.public_service_allowed !== false,
  )) {
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

async function statsPage(days = 30): Promise<HTMLElement> {
  const [stats, geography] = await Promise.all([
    api<Stats>(`/api/admin/stats?days=${days}`),
    import('./world-map'),
  ]);
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
      '一个短码计为一条逻辑映射。地区由 Cloudflare 提供，设备、浏览器与来源为近似分类。',
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
    worldMap(stats.countries, geography.worldCountries),
    trendChart(stats.daily, days, stats.daily_timezone || 'UTC'),
  );
  root.append(
    rankings(stats, geography.worldCountries, (title, description, body) => {
      const m = modal(title, description);
      m.dialog.classList.add('analytics-rank-dialog');
      m.body.append(body);
    }),
  );
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
function backupSchedulePanel(schedule: Schedule): HTMLElement {
  const enabled = schedule.enabled === true || schedule.enabled === 1 || schedule.enabled === '1';
  const panel = el('div', 'panel schedule-panel');
  panel.append(el('h2', '', '自动备份计划'));
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
    ['相关任务已记录失败次数', String(schedule.retry_count ?? 0)],
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
  const toggle = check('启用自动备份', enabled);
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
    append(el('div', 'field-row'), interval.node, retention.node),
    status,
    append(el('div', 'form-actions'), save),
  );
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    save.disabled = true;
    try {
      await api('/api/admin/settings', 'PUT', {
        backup_enabled: Number(toggle.input.checked),
        backup_interval_hours: Number(interval.input.value),
        backup_retention_days: Number(retention.input.value),
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
  root.append(backupSchedulePanel(result.schedule));
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
          el('span', 'secondary', `本任务累计失败 ${Number(item.attempts || 0)} 次`),
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

async function auditPage(): Promise<HTMLElement> {
  const root = el('section');
  root.append(
    pageHeading(
      '审计日志',
      '记录管理员、业务 Token、匿名访客及系统的关键操作。业务 Token 调用会显示名称、创建管理员与 ID；创建管理员不代表实际调用人。历史信息缺失时标注未记录。日志不会展示业务 Token 明文。',
    ),
  );
  const panel = el('div', 'panel');
  const status = el('p');
  status.hidden = true;
  const { wrapper, body } = table(['发生时间（UTC+8）', '操作者', '操作', '对象']);
  let appliedFilters = new URLSearchParams();
  let loadVersion = 0;
  const filters = el('form', 'audit-filters');
  const search = field('搜索审计记录', 'search');
  search.input.placeholder = '搜索操作者、邮箱、Token 名称、操作或对象';
  search.input.maxLength = 200;
  search.node.classList.add('audit-search');
  const actor = selectField('操作者', [
    ['', '所有操作者'],
    ['system', '系统操作（全部）'],
  ]);
  actor.node.classList.add('audit-actor-filter');
  actor.node.append(
    el('span', 'hint', 'Token 选项仅显示可用或已撤销的 Token；其他历史记录仍可通过关键词查询。'),
  );
  const from = field('开始时间（UTC+8）', 'datetime-local');
  const to = field('结束时间（UTC+8）', 'datetime-local');
  const exclusions = el('details', 'audit-exclusions');
  const exclusionSummary = el('summary', '', '排除操作类型（已选 0 / 20）');
  const exclusionChoices = el('div', 'audit-exclusion-choices');
  exclusionChoices.append(el('p', 'hint', '正在读取操作类型…'));
  const excluded = new Map<string, HTMLInputElement>();
  const optionsStatus = el('p');
  optionsStatus.hidden = true;
  const filterStatus = el('p');
  filterStatus.hidden = true;
  const selectedActions = () =>
    [...excluded].filter(([, input]) => input.checked).map(([action]) => action);
  const updateExclusions = () => {
    exclusionSummary.textContent = `排除操作类型（已选 ${selectedActions().length} / 20）`;
  };
  append(
    exclusions,
    exclusionSummary,
    el('p', 'hint', '勾选后仅隐藏匹配记录，不会删除日志；最多排除 20 种操作类型。'),
    exclusionChoices,
  );
  const apply = el('button', 'button primary small', '查询');
  apply.type = 'submit';
  const reset = button(
    '重置',
    () => {
      search.input.value = '';
      actor.input.value = '';
      from.input.value = '';
      to.input.value = '';
      for (const input of excluded.values()) input.checked = false;
      updateExclusions();
      filterStatus.hidden = true;
      appliedFilters = new URLSearchParams();
      void load();
    },
    'small',
  );
  append(
    filters,
    append(el('div', 'audit-filter-grid'), search.node, actor.node, from.node, to.node),
    append(el('div', 'audit-filter-actions'), exclusions, apply, reset),
    el(
      'p',
      'hint',
      '时间统一为 Asia/Singapore（UTC+8）。结束时间包含所选的整秒，未填写秒数时按 00 秒计算。修改条件后点击查询；加载更多沿用上次查询条件。',
    ),
    filterStatus,
    optionsStatus,
  );
  filters.addEventListener('submit', (event) => {
    event.preventDefault();
    try {
      appliedFilters = auditFilterParams({
        q: search.input.value,
        actor: actor.input.value,
        from: from.input.value,
        to: to.input.value,
        excludeActions: selectedActions(),
      });
      filterStatus.hidden = true;
      void load();
    } catch (error) {
      showStatus(filterStatus, errorText(error), true);
    }
  });
  panel.append(filters);
  const loadOptions = async () => {
    try {
      const options = await api<AuditFilterOptions>('/api/admin/audit/options');
      for (const item of options.actors.slice(0, 200)) {
        const identity = auditActor(item.actor_identity, item.actor);
        const label =
          item.actor_identity.type === 'business_token'
            ? `${identity.title} · Token ID：${item.actor}`
            : item.actor_identity.type === 'unknown'
              ? `${identity.title} · ${item.actor}`
              : identity.title;
        const choice = el('option', '', label);
        choice.value = `actor:${item.actor}`;
        actor.input.append(choice);
      }
      exclusionChoices.replaceChildren();
      for (const action of options.actions.slice(0, 100)) {
        const choice = check(auditActionLabel(action));
        choice.node.classList.add('wrap');
        choice.input.addEventListener('change', () => {
          if (selectedActions().length > 20) {
            choice.input.checked = false;
            showStatus(filterStatus, '最多排除 20 种操作类型。', true);
          } else filterStatus.hidden = true;
          updateExclusions();
        });
        excluded.set(action, choice.input);
        exclusionChoices.append(choice.node);
      }
      if (!excluded.size) exclusionChoices.append(el('p', 'hint', '暂无可排除的操作类型。'));
      const limits = [
        ...(options.actors_truncated ? ['操作者列表仅显示前 200 项，其余可用关键词搜索。'] : []),
        ...(options.actions_truncated ? ['操作类型列表仅显示前 100 项。'] : []),
      ];
      if (limits.length) showStatus(optionsStatus, limits.join(' '));
    } catch (error) {
      exclusionChoices.replaceChildren(el('p', 'hint', '操作类型暂时无法载入。'));
      showStatus(optionsStatus, `筛选选项未能载入：${errorText(error)}`, true);
    }
  };
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
    const version = ++loadVersion;
    const params = new URLSearchParams(appliedFilters);
    const filtered = params.size > 0;
    if (cursor) params.set('cursor', cursor);
    next.disabled = true;
    status.hidden = true;
    if (!cursor) {
      body.replaceChildren();
      nextCursor = '';
      next.hidden = true;
    }
    try {
      const result = await api<
        PageResult<Item> & {
          filtering_supported?: boolean;
        }
      >(`/api/admin/audit${params.size ? `?${params}` : ''}`);
      if (version !== loadVersion) return;
      if (filtered && result.filtering_supported !== true)
        throw new Error('当前服务版本尚不支持审计筛选，请更新服务后重试。');
      for (const item of result.items) {
        const row = append(
          el('tr'),
          td(formatTime(item.created_at)),
          auditActorCell(item),
          td(item.action),
          td(item.entity_id || '—', 'wrap'),
        );
        body.append(row);
      }
      if (!body.children.length) {
        const row = el('tr');
        const cell = td(filtered ? '没有符合筛选条件的审计记录。' : '暂无审计记录。', 'empty');
        cell.colSpan = 4;
        row.append(cell);
        body.append(row);
      }
      nextCursor = result.next_cursor || '';
      next.hidden = !nextCursor;
    } catch (error) {
      if (version === loadVersion) showStatus(status, errorText(error), true);
    } finally {
      if (version === loadVersion) next.disabled = false;
    }
  }
  append(panel, status, wrapper, append(el('div', 'pagination'), next));
  root.append(panel);
  await Promise.all([load(), loadOptions()]);
  return root;
}

async function settingsPage(): Promise<HTMLElement> {
  const settings = await api<Item>('/api/admin/settings');
  const root = el('section');
  root.append(
    pageHeading(
      '系统设置',
      '管理限流、自动任务与数据保留。时间统一展示为 Asia/Singapore（UTC+8）。',
    ),
  );
  const form = el('form');
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
  ] as [string, string, number, number, number, string][]) {
    const control = field(label, 'number', String(settings[key] ?? fallback), hint);
    control.input.required = true;
    control.input.min = String(min);
    control.input.max = String(max);
    controls.set(key, control.input);
    policies.append(control.node);
  }
  for (const [key, label] of [['backup_enabled', '启用自动 R2 备份']]) {
    const control = check(label, String(settings[key] ?? '1') === '1');
    controls.set(key, control.input);
    policies.append(control.node);
  }
  const status = el('p');
  status.hidden = true;
  const save = el('button', 'button primary', '保存设置');
  save.type = 'submit';
  append(form, policies, status, append(el('div', 'form-actions'), save));
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

function textErrorPreview(title: string, message: string): string {
  const doc = document.implementation.createHTMLDocument(title);
  doc.documentElement.lang = 'zh-CN';
  const charset = doc.createElement('meta');
  charset.setAttribute('charset', 'utf-8');
  const viewport = doc.createElement('meta');
  viewport.name = 'viewport';
  viewport.content = 'width=device-width,initial-scale=1';
  const style = doc.createElement('style');
  style.textContent = statusStyles;
  doc.head.append(charset, viewport, style);
  const home = el('a', '', '返回首页');
  home.href = '/';
  doc.body.append(append(el('main'), el('h1', '', title), el('p', '', message), home));
  return `<!doctype html>${doc.documentElement.outerHTML}`;
}

async function errorPagesPage(): Promise<HTMLElement> {
  const pages = await api<Record<ErrorPageKey, ErrorPage>>('/api/admin/error-pages');
  const root = el('section', 'error-pages');
  root.append(
    pageHeading('应用错误页', '分别设置错误页内容。上传或修改后，先预览，再保存生效。'),
    el('p', 'hint', '仅管理应用返回的页面；边缘 WAF 与 Access 拦截页由 Cloudflare 独立管理。'),
  );
  const categories: [ErrorPageKey, string, string][] = [
    ['error_403', '403 无权限', '无法访问'],
    ['error_404', '404 未找到', '链接不存在'],
    ['error_disabled', '停用或过期', '链接已停用'],
    ['error_500', '其他应用错误', '暂时无法访问'],
  ];
  for (const [key, label, title] of categories) {
    const current = pages[key];
    let html = current.html;
    let fileSelection = 0;
    let readingFile = false;
    let revision = 0;
    let previewedRevision = -1;
    let channel: MessageChannel | undefined;
    let timeout: ReturnType<typeof setTimeout> | undefined;
    const panel = el('section', 'panel error-page-panel');
    const badge = el('span', 'badge', current.mode === 'html' ? '已保存 HTML' : '已保存纯文字');
    panel.append(append(el('div', 'error-page-heading'), el('h2', '', label), badge));
    const layout = el('div', 'error-page-layout');
    const editor = el('div', 'error-page-editor');
    const mode = selectField(
      '页面内容',
      [
        ['text', '纯文字'],
        ['html', '自定义 HTML'],
      ],
      current.mode,
    );
    const text = textField('错误页文字', current.text, '最多 500 字符。');
    text.input.maxLength = 500;
    const upload = field(
      '上传 HTML 文件',
      'file',
      '',
      '单个 UTF-8 HTML 文件，最大 128 KiB。CSS、JS、图片与字体请内嵌；图片和字体可使用 data URL。',
    );
    upload.input.accept = '.html,.htm,text/html';
    const fileInfo = el('p', 'hint');
    const updateFileInfo = (name?: string) => {
      fileInfo.textContent = html
        ? `${name ?? '已保存的 HTML'} · ${(new TextEncoder().encode(html).byteLength / 1024).toFixed(1)} KiB`
        : '尚未上传 HTML 文件。';
    };
    updateFileInfo();
    const htmlFields = append(el('div'), upload.node, fileInfo);
    const previewArea = el('div', 'error-page-preview');
    const previewBody = el('div', 'error-page-preview-body');
    const placeholder = () =>
      previewBody.replaceChildren(el('p', 'empty', '点击“预览”查看当前内容，完成后可保存。'));
    placeholder();
    append(previewArea, el('h3', '', '页面预览'), previewBody);
    const status = el('p');
    status.hidden = true;
    const save = el('button', 'button primary', '保存此错误页');
    save.type = 'button';
    save.disabled = true;
    const closePreview = () => {
      if (timeout !== undefined) clearTimeout(timeout);
      timeout = undefined;
      channel?.port1.close();
      channel = undefined;
    };
    const invalidate = () => {
      revision++;
      previewedRevision = -1;
      save.disabled = true;
      closePreview();
      placeholder();
      status.hidden = true;
    };
    const updateMode = () => {
      text.node.hidden = mode.input.value !== 'text';
      htmlFields.hidden = mode.input.value !== 'html';
    };
    updateMode();
    mode.input.addEventListener('change', () => {
      invalidate();
      updateMode();
    });
    text.input.addEventListener('input', invalidate);
    upload.input.addEventListener('change', async () => {
      invalidate();
      html = '';
      updateFileInfo();
      const file = upload.input.files?.[0];
      const selection = ++fileSelection;
      readingFile = false;
      if (!file) return;
      readingFile = true;
      try {
        if (!/\.html?$/i.test(file.name)) throw new Error('请选择 .html 或 .htm 文件。');
        if (!file.size || file.size > ERROR_PAGE_HTML_MAX_BYTES)
          throw new Error('HTML 文件不能为空，且不能超过 128 KiB。');
        const source = new TextDecoder('utf-8', { fatal: true }).decode(await file.arrayBuffer());
        if (selection !== fileSelection) return;
        if (!source.trim() || /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(source))
          throw new Error('HTML 文件包含无效内容。');
        invalidate();
        html = source;
        updateFileInfo(file.name);
        showStatus(status, '文件已载入，尚未保存。请先预览。');
      } catch (error) {
        if (selection === fileSelection)
          showStatus(
            status,
            error instanceof TypeError ? '请上传 UTF-8 编码的 HTML 文件。' : errorText(error),
            true,
          );
      } finally {
        if (selection === fileSelection) readingFile = false;
      }
    });
    const preview = button('预览', () => {
      invalidate();
      const attempt = revision;
      if (mode.input.value === 'html' && readingFile) {
        showStatus(status, '正在读取 HTML 文件，请稍候再预览。');
        return;
      }
      if (mode.input.value === 'html' && !html.trim()) {
        showStatus(status, '请先上传 HTML 文件。', true);
        return;
      }
      const source =
        mode.input.value === 'html' ? html : textErrorPreview(title, text.input.value || title);
      const frame = el('iframe', 'error-page-frame');
      frame.title = `${label}预览`;
      frame.sandbox.add('allow-scripts');
      frame.referrerPolicy = 'no-referrer';
      frame.addEventListener(
        'load',
        () => {
          if (attempt !== revision || !root.isConnected) return;
          const pending = new MessageChannel();
          channel = pending;
          pending.port1.onmessage = (event: MessageEvent) => {
            if (event.data?.type !== 'loaded' || attempt !== revision || !root.isConnected) return;
            closePreview();
            previewedRevision = attempt;
            save.disabled = false;
            showStatus(status, '预览已载入。确认页面效果后，点击保存。');
          };
          frame.contentWindow?.postMessage({ type: 'shortlink:error-preview', html: source }, '*', [
            pending.port2,
          ]);
        },
        { once: true },
      );
      frame.src = '/api/admin/error-pages/preview';
      previewBody.replaceChildren(frame);
      showStatus(status, '正在载入预览…');
      timeout = setTimeout(() => {
        if (attempt !== revision || !root.isConnected) {
          closePreview();
          return;
        }
        closePreview();
        showStatus(status, '预览未能完成，请检查 HTML 内容或重新登录后重试。', true);
      }, 15000);
    });
    save.addEventListener('click', async () => {
      if (previewedRevision !== revision) return;
      const payload = { key, mode: mode.input.value, text: text.input.value, html };
      for (const input of [save, preview, mode.input, text.input, upload.input])
        input.disabled = true;
      try {
        await api('/api/admin/error-pages', 'PUT', payload);
        badge.textContent = payload.mode === 'html' ? '已保存 HTML' : '已保存纯文字';
        showStatus(status, '此错误页已保存。');
      } catch (error) {
        showStatus(status, errorText(error), true);
      } finally {
        for (const input of [preview, mode.input, text.input, upload.input]) input.disabled = false;
        save.disabled = previewedRevision !== revision;
      }
    });
    append(
      editor,
      mode.node,
      text.node,
      htmlFields,
      el(
        'p',
        'hint',
        '支持内嵌 CSS 和 JavaScript。页面在隔离环境运行，外部资源、接口请求、表单提交与弹窗受限。',
      ),
      append(el('div', 'form-actions'), preview, save),
      status,
    );
    append(layout, editor, previewArea);
    panel.append(layout);
    root.append(panel);
  }
  return root;
}

if (location.pathname === '/admin' || location.pathname.startsWith('/admin/')) void adminPage();
else void publicPage();
