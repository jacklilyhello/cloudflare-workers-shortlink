import './styles.css';

type Item = Record<string, unknown>;
type PageResult<T> = { items: T[]; next_cursor?: string | null };
type Domain = { id: string; hostname: string; bound: boolean; enabled: boolean };
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
function formatTime(value: unknown): string {
  if (value === null || value === undefined || value === '') return '未知';
  const date = new Date(typeof value === 'number' ? value : String(value));
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString('zh-CN', { hour12: false });
}
function datetimeValue(value: number | null): string {
  if (value === null) return '';
  const date = new Date(value);
  return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}
function formatExpiry(value: number | null): string {
  return value === null ? '永久' : formatTime(value);
}
function expiration(value: string): number | null {
  if (!value) return null;
  const time = new Date(value).getTime();
  if (!Number.isFinite(time)) throw new Error('到期时间无效');
  return time;
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
  return `https://${link.domain}/${link.slug}`;
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
  DOMAIN_NOT_BOUND: '此域名尚未完成绑定，请先通过手动 Actions 核对并绑定。',
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
  m.body.append(append(el('div', 'form-actions'), button('取消', m.close), submit));
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
    el('p', 'intro', '粘贴链接，生成短链。让分享更简单。'),
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
  const prefix = el('span', '', '短链域名/');
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
    append(el('div', 'slug-input'), prefix, slug),
    el('span', 'hint', '字母、数字、下划线或连字符，区分大小写。'),
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
  main.append(el('footer', 'public-footer', '无需登录。结果仅在当前页面展示，请及时复制保存。'));
  append(page, header, main);
  app.replaceChildren(page);
  let challengeToken = '';
  let widget = '';
  try {
    const config = await api<{ site_key: string; domain: string }>('/api/public/config');
    prefix.textContent = `${config.domain}/`;
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
        const data = await api<{ slug: string; domain: string; short_url: string }>(
          '/api/public/shorten',
          'POST',
          {
            url: url.input.value,
            ...(slug.value ? { slug: slug.value } : {}),
            turnstile_token: challengeToken,
          },
        );
        result.replaceChildren(el('p', 'result-label', '短链接已生成'));
        const copyButton = button(
          '复制',
          () => {
            void copy(data.short_url, copyButton);
          },
          'small',
        );
        result.append(
          append(el('div', 'result-line'), safeAnchor(data.short_url, data.short_url), copyButton),
        );
        result.hidden = false;
        copyButton.focus();
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
  ['backups', '备份与导出', '▣'],
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
  nav.append(el('p', 'sidebar-note', '链接映射永久保留。停用与过期不会删除映射或释放短码。'));
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
        const expiry = field('到期时间', 'datetime-local');
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
    '到期时间',
    '创建时间',
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
  async function load() {
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
        const state = !item.enabled
          ? '停用'
          : item.expires_at !== null && item.expires_at <= Date.now()
            ? '过期'
            : '有效';
        const stateCell = append(el('td'), statusBadge(state === '有效', state, state));
        if (item.confirmation_enabled) stateCell.append(el('span', 'secondary', '确认页已开启'));
        const copyButton = button(
          '复制',
          () => {
            void copy(shortUrl(item), copyButton);
          },
          'small',
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
            ),
          ),
        );
        body.append(row);
      }
      nextCursor = result.next_cursor || '';
      previous.disabled = cursorStack.length === 0;
      next.disabled = !nextCursor;
    } catch (error) {
      showStatus(listStatus, errorText(error), true);
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

function editLink(item?: Link, afterSave?: () => Promise<void>) {
  const m = modal(
    item ? '编辑链接' : '新建链接',
    item ? '短码与映射永久保留。高级设置仅管理员可修改。' : '每次创建独立短链，即使目标链接相同。',
  );
  const form = el('form');
  const url = field('目标链接', 'url', item?.url || '');
  url.input.required = true;
  url.input.maxLength = 8192;
  const domain = selectField(
    '短链域名',
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
    '到期时间',
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
    showStatus(m.status, '没有已绑定并启用的域名。请先完成手动 Actions 绑定。', true);
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
      '登记短链域名，分别控制绑定状态与业务启用状态。',
      button('登记域名 +', () => {
        const m = modal(
          '登记短链域名',
          '登记不修改 DNS 或 Worker 绑定。绑定必须经过核对目标的手动 Actions；目前部署流程只开放 test.gfw.mom。',
        );
        const hostname = field('域名', 'text', '', '只填写小写主机名，例如 test.gfw.mom。');
        hostname.input.required = true;
        const form = el('form');
        const save = el('button', 'button primary', '登记');
        save.type = 'submit';
        append(form, hostname.node, append(el('div', 'form-actions'), save));
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
  const { wrapper, body } = table(['域名', '实际绑定', '状态', '操作']);
  for (const domain of domains)
    body.append(
      append(
        el('tr'),
        td(domain.hostname, 'mono'),
        append(el('td'), statusBadge(domain.bound, '已核验绑定', '待手动绑定')),
        append(el('td'), statusBadge(domain.enabled)),
        append(
          el('td'),
          button(
            domain.enabled ? '停用' : '启用',
            () =>
              confirmAction(
                `${domain.enabled ? '停用' : '启用'}域名`,
                domain.enabled
                  ? '停用后不再允许新建该域名的短链，已有映射会继续保留。'
                  : '只有实际绑定并获得授权的域名才能用于创建。',
                '确认',
                async () => {
                  await api(`/api/admin/domains/${encodeURIComponent(domain.id)}`, 'PATCH', {
                    enabled: !domain.enabled,
                  });
                  await renderTab();
                },
              ),
            'small',
          ),
        ),
      ),
    );
  if (!domains.length) panel.append(el('p', 'empty', '尚未登记短链域名。'));
  else panel.append(wrapper);
  notice(
    panel,
    '后台登记不会创建资源或声明绑定完成。新资源只通过显式触发的 Actions 配置；不得接管其他业务域名。',
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
  const { wrapper, body } = table(['名称 / 标识', '授权域名', '状态', '到期时间', '操作']);
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
  const expiry = field('到期时间', 'datetime-local', '', '留空表示永久，仍可随时撤销。');
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

async function statsPage(days = 30): Promise<HTMLElement> {
  const stats = await api<Stats>(`/api/admin/stats?days=${days}`);
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
    content.replaceChildren(el('p', 'notice', '正在载入统计…'));
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
      '聚合跳转访问；设备来自 User-Agent 分类，地区来自 Cloudflare 提供的信息。',
      range,
    ),
  );
  const cards = el('div', 'cards');
  for (const [label, value] of [
    ['链接总数', stats.totals.links],
    ['有效链接', stats.totals.active_links],
    ['区间访问', stats.totals.visits],
  ])
    cards.append(
      append(
        el('div', 'panel metric'),
        el('p', '', String(label)),
        el('strong', '', Number(value || 0).toLocaleString('zh-CN')),
      ),
    );
  root.append(cards);
  const trend = el('div', 'panel trend');
  trend.append(el('h2', '', '访问趋势'));
  const bars = el('div', 'bars');
  bars.setAttribute('role', 'img');
  bars.setAttribute(
    'aria-label',
    stats.daily.map((d) => `${d.date}：${d.visits} 次`).join('；') || '尚无访问数据',
  );
  const maximum = Math.max(1, ...stats.daily.map((d) => d.visits));
  for (const entry of stats.daily) {
    const column = el('div', 'bar-column');
    column.title = `${entry.date} · ${entry.visits} 次`;
    const fill = el('div', 'bar-fill');
    fill.style.height = `${Math.max(1, (entry.visits / maximum) * 100)}%`;
    append(column, append(el('div', 'bar-track'), fill), el('span', '', entry.date.slice(5)));
    bars.append(column);
  }
  trend.append(stats.daily.length ? bars : el('p', 'empty', '这个区间暂无访问记录。'));
  root.append(trend);
  const grid = el('div', 'chart-grid');
  for (const [title, values] of [
    ['地区', stats.countries],
    ['设备', stats.devices],
    ['来源', stats.referrers],
  ] as [string, { name: string; count: number }[]][]) {
    const panel = el('div', 'panel');
    panel.append(el('h2', '', title));
    const max = Math.max(1, ...values.map((v) => v.count));
    for (const entry of values.slice(0, 12)) {
      const fill = el('div', 'rank-fill');
      fill.style.width = `${(entry.count / max) * 100}%`;
      panel.append(
        append(
          el('div', 'rank-row'),
          append(
            el('div', 'rank-label'),
            el('span', '', entry.name || '未知 / 直接访问'),
            el('span', '', entry.count.toLocaleString()),
          ),
          append(el('div', 'rank-track'), fill),
        ),
      );
    }
    if (!values.length) panel.append(el('p', 'empty', '暂无数据'));
    grid.append(panel);
  }
  root.append(grid);
  notice(
    root,
    '访问统计是近似聚合，可能包含机器人、重复访问或异步统计丢失；不是独立访客数。不会为了统计抓取目标链接。',
  );
  return root;
}

async function download(path: string, filename: string, status: HTMLElement) {
  try {
    const response = await fetch(path, {
      credentials: 'same-origin',
      redirect: 'error',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const result = response.headers.get('Content-Type')?.includes('application/json')
        ? ((await response.json()) as { error?: { message: string } })
        : null;
      throw new Error(result?.error?.message || '下载失败，请刷新页面核实登录状态。');
    }
    if (
      !['application/json', 'application/x-ndjson', 'application/octet-stream'].some((type) =>
        response.headers.get('Content-Type')?.includes(type),
      )
    )
      throw new Error('下载返回了安全验证页面，请刷新页面后重试。');
    const blob = await response.blob();
    const objectUrl = URL.createObjectURL(blob);
    const anchor = el('a');
    anchor.href = objectUrl;
    anchor.download = filename;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(objectUrl), 30000);
    showStatus(status, '下载已开始。导出包含完整目标链接，请妥善保存。');
  } catch (error) {
    showStatus(status, errorText(error), true);
  }
}
async function downloadExport(trigger: HTMLButtonElement, status: HTMLElement) {
  trigger.disabled = true;
  const parts: BlobPart[] = ['{"schema_version":1,"links":['];
  let count = 0;
  let cursor = '';
  const visited = new Set<string>();
  try {
    do {
      const controller = new AbortController();
      const timeout = window.setTimeout(() => controller.abort(), 20000);
      let page: { links: Link[]; next_cursor: string | null };
      try {
        const response = await fetch(
          `/api/admin/export${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''}`,
          {
            credentials: 'same-origin',
            redirect: 'error',
            signal: controller.signal,
            headers: { Accept: 'application/json' },
          },
        );
        if (!response.headers.get('Content-Type')?.includes('application/json'))
          throw new Error('导出返回了安全验证页面，请刷新页面后重试。');
        const payload = (await response.json()) as {
          links?: Link[];
          next_cursor?: string | null;
          error?: { message: string };
        };
        if (!response.ok || !Array.isArray(payload.links))
          throw new Error(payload.error?.message || '导出未成功。');
        page = { links: payload.links, next_cursor: payload.next_cursor || null };
      } finally {
        window.clearTimeout(timeout);
      }
      if (page.links.length) {
        parts.push(
          `${count ? ',' : ''}${page.links.map((link) => JSON.stringify(link)).join(',')}`,
        );
        count += page.links.length;
      }
      cursor = page.next_cursor || '';
      if (cursor && visited.has(cursor))
        throw new Error('导出游标重复，已停止下载以避免输出不完整的数据。');
      visited.add(cursor);
      showStatus(status, `正在导出，已读取 ${count.toLocaleString('zh-CN')} 条链接…`);
    } while (cursor);
    parts.push(']}');
    const objectUrl = URL.createObjectURL(new Blob(parts, { type: 'application/json' }));
    const anchor = el('a');
    anchor.href = objectUrl;
    anchor.download = 'shortlink-links.json';
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(objectUrl), 30000);
    showStatus(
      status,
      `已完整读取并开始下载 ${count.toLocaleString('zh-CN')} 条链接。导出不是数据库原子快照；需要一致性快照时请使用备份。`,
    );
  } catch (error) {
    showStatus(status, `导出未完成，不会下载不完整文件。${errorText(error)}`, true);
  } finally {
    trigger.disabled = false;
  }
}
async function backupsPage(): Promise<HTMLElement> {
  const result = await api<PageResult<Item>>('/api/admin/backups');
  const root = el('section');
  const status = el('p');
  status.hidden = true;
  const exportButton = button('导出链接', () => {
    void downloadExport(exportButton, status);
  });
  root.append(
    pageHeading(
      '备份与导出',
      '显示最近 100 份备份，文件保存在本项目 R2。链接导出不含业务 Token 明文。',
      append(
        el('div', 'row-actions'),
        button(
          '刷新',
          () => {
            void renderTab();
          },
          'quiet',
        ),
        exportButton,
        button(
          '立即备份',
          () =>
            confirmAction(
              '创建数据备份',
              '生成当前数据库的逻辑备份并保存到本项目 R2。它不会改写旧 KV 或切换生产流量。',
              '创建备份',
              async () => {
                await api('/api/admin/backups', 'POST', {});
                await renderTab();
              },
            ),
          'primary',
        ),
      ),
    ),
  );
  const panel = el('div', 'panel');
  const { wrapper, body } = table(['备份标识', '创建时间', '大小', '状态', '操作']);
  for (const item of result.items) {
    const id = String(item.id || '');
    const downloadButton = button(
      '下载',
      () => {
        void download(
          `/api/admin/backups/${encodeURIComponent(id)}/download`,
          `shortlink-backup-${id}.ndjson`,
          status,
        );
      },
      'small',
    );
    downloadButton.disabled = item.status !== 'complete';
    body.append(
      append(
        el('tr'),
        td(id, 'mono'),
        td(formatTime(item.created_at)),
        td(item.size === undefined ? '—' : `${(Number(item.size) / 1024).toFixed(1)} KB`),
        td(
          item.status === 'complete'
            ? '已完成'
            : item.status === 'pending'
              ? '待处理'
              : item.status === 'uploading'
                ? '上传中'
                : item.status,
        ),
        append(el('td'), downloadButton),
      ),
    );
  }
  panel.append(
    result.items.length ? wrapper : el('p', 'empty', '暂无备份。绑定 R2 后，可以创建第一份备份。'),
  );
  append(root, status, panel);
  notice(
    root,
    '自动备份周期和备份保留期在系统设置中调整。链接映射永久保留；备份清理只清理到期的备份文件。恢复及旧 KV 迁移只通过经核对的手动 Actions 执行。',
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
        ? '旧 KV 只读，新 D1 写入。实际迁移与增量补齐由手动 Actions 执行。'
        : '记录管理员及系统的关键操作，便于核对变更。日志不会展示业务 Token 明文。',
    ),
  );
  const panel = el('div', 'panel');
  const status = el('p');
  status.hidden = true;
  const runSummary = el('div');
  const { wrapper, body } = table(
    migrations ? ['结果', '记录数', '说明'] : ['时间', '操作者', '操作', '对象'],
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
      const result = await api<PageResult<Item> & { run?: MigrationRun | null }>(
        `/api/admin/${migrations ? 'migrations' : 'audit'}${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''}`,
      );
      if (migrations) {
        runSummary.replaceChildren();
        const run = result.run;
        if (!run)
          notice(runSummary, '尚未执行真实迁移。完成新资源绑定后，可触发旧 KV 迁移工作流。');
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
          runSummary.append(el('p', 'hint', `最近核对：${formatTime(run.updated_at)}`));
          if (run.state !== 'complete')
            runSummary.append(
              el('p', 'notice', `继续处理时，触发迁移工作流，并将 resume_run 参数设为 ${run.id}。`),
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
      '这里按最近一轮迁移的结果与原因汇总观察记录，包含未知记录。本轮扫描不是旧 KV 的一致性快照；旧系统仍可能新增，切换前需再做增量核对。迁移记录不代表生产切换完成。',
    );
  return root;
}

async function settingsPage(): Promise<HTMLElement> {
  const settings = await api<Item>('/api/admin/settings');
  const root = el('section');
  root.append(
    pageHeading('系统设置', '管理统计与备份策略、应用错误页文字。修改不会缩短链接映射的保留期。'),
  );
  const form = el('form');
  const grid = el('div', 'settings-grid');
  const policies = el('div', 'panel');
  policies.append(el('h2', '', '保留与备份策略'));
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
      1,
      3650,
      '按保留期清理访问聚合。链接映射永久保留。',
    ],
    ['audit_retention_days', '审计记录保留天数', 365, 1, 3650, '按保留期清理审计记录。'],
    [
      'backup_retention_days',
      '备份文件保留天数',
      30,
      1,
      3650,
      '到期备份可被清理，请另存需长期保留的备份。',
    ],
    [
      'backup_interval_hours',
      '自动备份间隔（小时）',
      24,
      1,
      720,
      '依靠 Worker Cron 执行。实际运行状态需在备份记录中核实。',
    ],
  ] as [string, string, number, number, number, string][]) {
    const control = field(label, 'number', String(settings[key] ?? fallback), hint);
    control.input.required = true;
    control.input.min = String(min);
    control.input.max = String(max);
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
        payload[key] = control instanceof HTMLInputElement ? Number(control.value) : control.value;
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
