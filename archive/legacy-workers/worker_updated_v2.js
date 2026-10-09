// ==================== 基础配置 ====================
// 内部配置，只保留后台密码
const INTERNAL_CONFIG = {
  admin_pass: "lilyadmin888", // ⬅️ 记得修改密码
};

// ==================== 1. 后台管理页面模板 ====================
const htmlAdmin = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>短链接管理后台</title>
    <meta name="viewport" content="width=device-width,initial-scale=1.0">
    <style>
      :root {
        --bg-color: #f3f4f6;
        --bg-gradient: radial-gradient(circle at top left, #e0f2fe 0, #f3f4f6 35%, #e5e7eb 100%);
        --card-bg: rgba(255, 255, 255, 0.82);
        --card-border: rgba(148, 163, 184, 0.45);
        --card-shadow: 0 18px 45px rgba(15, 23, 42, 0.12);
        --radius-xl: 26px;
        --radius-lg: 18px;
        --radius-md: 12px;

        --text-main: #0f172a;
        --text-sub: #6b7280;
        --text-muted: #9ca3af;

        --primary: #2563eb;
        --primary-soft: rgba(37, 99, 235, 0.12);
        --primary-border: rgba(37, 99, 235, 0.4);
        --danger: #ef4444;

        --input-bg: rgba(255, 255, 255, 0.98);
        --input-border: rgba(148, 163, 184, 0.7);
        --input-focus-ring: rgba(59, 130, 246, 0.55);
      }

      @media (prefers-color-scheme: dark) {
        :root {
          --bg-color: #020617;
          --bg-gradient: radial-gradient(circle at top left, #0f172a 0, #020617 40%, #020617 100%);
          --card-bg: rgba(15, 23, 42, 0.88);
          --card-border: rgba(51, 65, 85, 0.9);
          --card-shadow: 0 22px 60px rgba(15, 23, 42, 0.9);

          --text-main: #e5e7eb;
          --text-sub: #9ca3af;
          --text-muted: #6b7280;

          --input-bg: rgba(15, 23, 42, 0.96);
          --input-border: rgba(75, 85, 99, 0.9);
        }
      }

      * { box-sizing: border-box; }

      body {
        margin: 0;
        padding: 0;
        min-height: 100vh;
        background: var(--bg-gradient), var(--bg-color);
        font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", system-ui, sans-serif;
        color: var(--text-main);
        -webkit-font-smoothing: antialiased;
      }

      .page {
        max-width: 1100px;
        margin: 0 auto;
        padding: 26px 18px 36px;
      }

      .brand {
        display: flex;
        align-items: center;
        gap: 10px;
        padding-left: 4px;
        margin-bottom: 18px;
        user-select: none;
      }

      .brand-dot {
        width: 10px;
        height: 10px;
        border-radius: 999px;
        background: radial-gradient(circle at 30% 20%, #38bdf8 0, #2563eb 35%, #4f46e5 100%);
        box-shadow: 0 0 18px rgba(56, 189, 248, 0.8);
      }

      .brand-title {
        font-size: 13px;
        letter-spacing: 0.14em;
        text-transform: uppercase;
        color: var(--text-muted);
      }

      .card {
        background: var(--card-bg);
        border: 1px solid var(--card-border);
        border-radius: var(--radius-xl);
        box-shadow: var(--card-shadow);
        backdrop-filter: blur(20px) saturate(140%);
        -webkit-backdrop-filter: blur(20px) saturate(140%);
        padding: 26px 22px 22px;
        margin-bottom: 20px;
      }

      .card-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        margin-bottom: 12px;
      }

      h2 {
        margin: 0;
        font-size: 22px;
        letter-spacing: 0.02em;
      }

      .subtitle {
        margin: 4px 0 0;
        color: var(--text-sub);
        font-size: 13px;
      }

      .section-title {
        margin: 0 0 12px;
        font-size: 16px;
        font-weight: 600;
      }

      .badge {
        font-size: 11px;
        padding: 4px 10px;
        border-radius: 999px;
        background: var(--primary-soft);
        color: #1d4ed8;
        border: 1px solid rgba(129, 140, 248, 0.35);
        letter-spacing: 0.08em;
        text-transform: uppercase;
        white-space: nowrap;
      }

      .btn {
        padding: 10px 14px;
        border-radius: 12px;
        border: none;
        cursor: pointer;
        font-size: 14px;
        font-weight: 600;
        transition: transform 0.16s ease, box-shadow 0.18s ease, filter 0.16s ease;
      }

      .btn-primary {
        background-image: linear-gradient(90deg, #2563eb, #4f46e5);
        color: #fff;
        box-shadow: 0 12px 26px rgba(37, 99, 235, 0.35);
      }

      .btn-primary:hover { transform: translateY(-1px); filter: brightness(1.03); }
      .btn-primary:active { transform: translateY(0); box-shadow: 0 8px 18px rgba(30,64,175,0.5); }

      .btn-ghost {
        background: rgba(255,255,255,0.6);
        color: var(--text-main);
        border: 1px solid var(--card-border);
      }

      .btn-red {
        background: rgba(248, 113, 113, 0.14);
        color: var(--danger);
        border: 1px solid rgba(248, 113, 113, 0.35);
      }

      .toolbar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        flex-wrap: wrap;
        margin-top: 10px;
        padding: 12px;
        border-radius: var(--radius-lg);
        border: 1px solid rgba(148,163,184,0.22);
        background: rgba(255,255,255,0.35);
      }

      .tool-group {
        display: flex;
        align-items: center;
        gap: 10px;
        flex-wrap: wrap;
      }

      .tool-label {
        font-size: 13px;
        color: var(--text-sub);
        user-select: none;
      }

      select,
      input[type="number"] {
        padding: 9px 10px;
        border-radius: 12px;
        border: 1px solid var(--card-border);
        background: rgba(255,255,255,0.78);
        color: var(--text-main);
        outline: none;
      }

      input[type="number"] {
        width: 110px;
      }

      .pager-info {
        font-size: 13px;
        color: var(--text-sub);
        white-space: nowrap;
      }

      table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 10px;
      }

      thead th {
        text-align: left;
        padding: 12px;
        font-size: 13px;
        color: var(--text-sub);
        letter-spacing: 0.01em;
        border-bottom: 1px solid var(--card-border);
      }

      tbody td {
        padding: 14px 12px;
        border-bottom: 1px solid rgba(148,163,184,0.25);
        word-break: break-all;
      }

      .empty {
        text-align: center;
        color: var(--text-sub);
        padding: 18px 0;
      }

      @media (max-width: 720px) {
        thead { display: none; }
        tbody tr { display: block; margin-bottom: 14px; border: 1px solid var(--card-border); border-radius: 14px; background: rgba(255,255,255,0.78); }
        tbody td { display: flex; justify-content: space-between; align-items: center; gap: 10px; border-bottom: 1px solid rgba(148,163,184,0.18); }
        tbody td:last-child { border-bottom: none; }
        tbody td::before { content: attr(data-label); font-size: 12px; color: var(--text-sub); }
      }
    </style>
</head>
<body>
  <div class="page">
    <header class="brand">
      <div class="brand-dot"></div>
      <span class="brand-title">SHORT URL SERVICE</span>
    </header>

    <section class="card">
      <div class="card-header">
        <div>
          <h2>短链接管理后台</h2>
          <p class="subtitle">管理短链接：查看后缀、原始链接与创建时间（精确到秒）。删除会同时清理哈希索引（不改变原有核心逻辑）。</p>
        </div>
        <span class="badge">ADMIN PANEL</span>
      </div>

      <div style="margin-top: 16px; display: flex; gap: 10px; justify-content: flex-end;">
        <button class="btn btn-ghost" onclick="reload()">刷新数据</button>
      </div>
    </section>

    <section class="card">
      <h3 class="section-title">链接列表</h3>

      <div class="toolbar">
        <div class="tool-group">
          <span class="tool-label">排序</span>
          <select id="sortSelect" onchange="onSortChange()">
            <option value="name">按后缀（A → Z）</option>
            <option value="time">按创建时间（新 → 旧）</option>
          </select>
          <span class="pager-info" id="totalInfo"></span>
        </div>

        <div class="tool-group" style="justify-content:flex-end;">
          <button class="btn btn-ghost" onclick="prevPage()">上一页</button>
          <button class="btn btn-ghost" onclick="nextPage()">下一页</button>
          <span class="pager-info" id="pageInfo"></span>
          <input id="jumpInput" type="number" min="1" placeholder="页码" />
          <button class="btn btn-primary" onclick="jumpPage()">跳转</button>
        </div>
      </div>

      <div id="linkContent" style="margin-top: 4px;"></div>
    </section>
  </div>

  <script>
    const pass = prompt("请输入管理密码");

    // 后台入口路径是可变的（由 Worker 环境变量控制），因此 API 路径使用当前页面路径推导：
    let base = location.pathname || "";
    while (base.length > 1 && base.endsWith("/")) base = base.slice(0, -1);
    const apiBase = base + "/api";

    const state = {
      page: 1,
      size: 10,
      sort: 'name',
      total: 0,
      totalPages: 1,
      loading: false,
    };

    function escapeHtml(input) {
      const s = String(input ?? '');
      return s
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
    }

    function pad2(n) {
      return String(n).padStart(2, '0');
    }

    // 本地时间格式：YYYY-MM-DD HH:mm:ss
    // 如果 createdAt 缺失/非法，默认显示 1970（epoch=0）
    function formatTime(createdAtMs) {
      const ms = Number.isFinite(createdAtMs) ? createdAtMs : 0;
      // 兼容：未存储创建时间时统一显示 1970-01-01 00:00:00
      if (ms === 0) return '1970-01-01 00:00:00';
      const d = new Date(ms);
      return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate())
        + ' ' + pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
    }

    function setPagerInfo() {
      const pageInfo = document.getElementById('pageInfo');
      const totalInfo = document.getElementById('totalInfo');
      if (pageInfo) pageInfo.textContent = '第 ' + state.page + ' / ' + state.totalPages + ' 页';
      if (totalInfo) totalInfo.textContent = '共 ' + state.total + ' 条';
    }

    function renderEmpty(msg) {
      document.getElementById('linkContent').innerHTML = '<div class="empty">' + (msg || '暂无数据') + '</div>';
      setPagerInfo();
    }

    function renderTable(items) {
      let html = '';
      html += '<table>';
      html += '<thead><tr>'
        + '<th style="width:16%">后缀</th>'
        + '<th>原始链接</th>'
        + '<th style="width:20%">创建时间</th>'
        + '<th style="width:12%">操作</th>'
        + '</tr></thead>';
      html += '<tbody>';

      items.forEach(item => {
        const name = escapeHtml(item.name);
        const url = escapeHtml(item.value || '');
        const created = formatTime(Number(item.createdAt));

        html += '<tr>'
          + '<td data-label="后缀"><strong>/' + name + '</strong></td>'
          + '<td data-label="原始链接">'
          +   (url
                ? '<a href="' + url + '" target="_blank" rel="noopener noreferrer">' + url + '</a>'
                : '<span style="color: var(--text-muted);">（空）</span>')
          + '</td>'
          + '<td data-label="创建时间">' + escapeHtml(created) + '</td>'
          + '<td data-label="操作">'
          +   '<button class="btn btn-red" data-key="' + name + '" onclick="delLink(this.dataset.key, this)">删除</button>'
          + '</td>'
          + '</tr>';
      });

      html += '</tbody></table>';
      document.getElementById('linkContent').innerHTML = html;
      setPagerInfo();
    }

    async function loadPage(page) {
      if (state.loading) return;
      state.loading = true;

      const p = Math.max(1, Math.floor(Number(page) || 1));
      renderEmpty('加载中...');

      const sortSelect = document.getElementById('sortSelect');
      if (sortSelect && sortSelect.value !== state.sort) {
        sortSelect.value = state.sort;
      }

      try {
        const qs = new URLSearchParams({
          page: String(p),
          size: String(state.size),
          sort: state.sort,
        });

        const res = await fetch(apiBase + '/all?' + qs.toString(), {
          headers: { 'Authorization': pass },
          cache: 'no-store'
        });
        if (!res.ok) { alert('鉴权失败'); renderEmpty(); return; }

        const data = await res.json();
        state.page = Number(data.page) || p;
        state.total = Number(data.total) || 0;
        state.totalPages = Math.max(1, Number(data.totalPages) || 1);

        const items = Array.isArray(data.links) ? data.links : [];
        if (!items.length) { renderEmpty(); return; }
        renderTable(items);
      } catch (e) {
        renderEmpty('加载失败');
      } finally {
        state.loading = false;
      }
    }

    function reload() {
      loadPage(state.page);
    }

    function onSortChange() {
      const sel = document.getElementById('sortSelect');
      const v = sel ? sel.value : 'name';
      state.sort = (v === 'time') ? 'time' : 'name';
      state.page = 1;
      loadPage(1);
    }

    function prevPage() {
      if (state.page <= 1) return;
      loadPage(state.page - 1);
    }

    function nextPage() {
      if (state.page >= state.totalPages) return;
      loadPage(state.page + 1);
    }

    function jumpPage() {
      const input = document.getElementById('jumpInput');
      const v = input ? Number(input.value) : NaN;
      if (!Number.isFinite(v) || v < 1) return;
      loadPage(Math.floor(v));
    }

    async function delLink(name, btn) {
      if (!name) return;
      if (!confirm('确定删除 /' + name + ' 吗？')) return;

      if (btn) {
        btn.disabled = true;
        btn.textContent = '删除中...';
      }

      try {
        const res = await fetch(apiBase + '/delete/' + encodeURIComponent(name), {
          headers: { 'Authorization': pass },
          cache: 'no-store'
        });
        if (!res.ok) {
          alert('删除失败');
          if (btn) {
            btn.disabled = false;
            btn.textContent = '删除';
          }
          return;
        }

        // 删除后刷新当前页（每页仅 10 条，刷新很快，且能保持分页与排序正确）
        loadPage(state.page);
      } catch (e) {
        alert('请求失败，请稍后重试。');
        if (btn) {
          btn.disabled = false;
          btn.textContent = '删除';
        }
      }
    }

    // 回车直接跳转
    const jumpInput = document.getElementById('jumpInput');
    if (jumpInput) {
      jumpInput.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') jumpPage();
      });
    }

    loadPage(1);
  </script>
</body>
</html>`;

// ==================== 2. 首页模板 (生成页) ====================
const htmlIndex = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <title>短链接生成</title>
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <style>
    :root {
      --bg-color: #f3f4f6;
      --bg-gradient: radial-gradient(circle at top left, #e0f2fe 0, #f3f4f6 35%, #e5e7eb 100%);
      --card-bg: rgba(255, 255, 255, 0.82);
      --card-border: rgba(148, 163, 184, 0.45);
      --card-shadow: 0 18px 45px rgba(15, 23, 42, 0.12);
      --radius-xl: 24px;
      --radius-lg: 18px;
      --radius-md: 12px;

      --text-main: #0f172a;
      --text-sub: #6b7280;
      --text-muted: #9ca3af;

      --primary: #2563eb;
      --primary-soft: rgba(37, 99, 235, 0.12);
      --primary-border: rgba(37, 99, 235, 0.4);

      --accent: #22c55e;
      --accent-soft: rgba(34, 197, 94, 0.12);

      --input-bg: rgba(255, 255, 255, 0.98);
      --input-border: rgba(148, 163, 184, 0.7);
      --input-focus-ring: rgba(59, 130, 246, 0.55);

      --button-primary-from: #2563eb;
      --button-primary-to: #4f46e5;
      --button-primary-shadow: 0 14px 30px rgba(37, 99, 235, 0.35);

      --button-accent-from: #16a34a;
      --button-accent-to: #22c55e;
      --button-accent-shadow: 0 12px 26px rgba(34, 197, 94, 0.32);

      --result-bg: rgba(248, 250, 252, 0.92);
      --result-border: rgba(148, 163, 184, 0.4);
    }

    @media (prefers-color-scheme: dark) {
      :root {
        --bg-color: #020617;
        --bg-gradient: radial-gradient(circle at top left, #0f172a 0, #020617 40%, #020617 100%);
        --card-bg: rgba(15, 23, 42, 0.88);
        --card-border: rgba(51, 65, 85, 0.9);
        --card-shadow: 0 22px 60px rgba(15, 23, 42, 0.9);

        --text-main: #e5e7eb;
        --text-sub: #9ca3af;
        --text-muted: #6b7280;

        --input-bg: rgba(15, 23, 42, 0.96);
        --input-border: rgba(75, 85, 99, 0.9);

        --result-bg: rgba(15, 23, 42, 0.96);
        --result-border: rgba(55, 65, 81, 0.9);
      }
    }

    * { box-sizing: border-box; }

    html, body {
      margin: 0;
      padding: 0;
      height: 100%;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", system-ui, sans-serif;
      background: var(--bg-gradient), var(--bg-color);
      color: var(--text-main);
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 16px;
      -webkit-font-smoothing: antialiased;
    }

    .page {
      width: 100%;
      max-width: 520px;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 16px;
      padding-left: 4px;
      user-select: none;
    }

    .brand-dot {
      width: 9px;
      height: 9px;
      border-radius: 999px;
      background: radial-gradient(circle at 30% 20%, #38bdf8 0, #2563eb 35%, #4f46e5 100%);
      box-shadow: 0 0 18px rgba(56, 189, 248, 0.8);
    }

    .brand-title {
      font-size: 13px;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      color: var(--text-muted);
    }

    .shell {
      position: relative;
    }

    .shell::before {
      content: "";
      position: absolute;
      inset: -80px;
      background:
        radial-gradient(circle at 10% 0, rgba(59,130,246,0.16) 0, transparent 55%),
        radial-gradient(circle at 120% 120%, rgba(129,140,248,0.18) 0, transparent 55%);
      opacity: 0.9;
      pointer-events: none;
      z-index: -1;
    }

    .card {
      background: var(--card-bg);
      border-radius: var(--radius-xl);
      border: 1px solid var(--card-border);
      box-shadow: var(--card-shadow);
      padding: 26px 22px 22px;
      backdrop-filter: blur(20px) saturate(140%);
      -webkit-backdrop-filter: blur(20px) saturate(140%);
    }

    @media (min-width: 640px) {
      .card {
        padding: 30px 28px 26px;
      }
    }

    .card-header {
      margin-bottom: 18px;
    }

    .title-row {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 12px;
    }

    h1 {
      margin: 0;
      font-size: 22px;
      font-weight: 650;
      letter-spacing: 0.03em;
    }

    .badge {
      font-size: 10px;
      padding: 3px 8px;
      border-radius: 999px;
      background: var(--primary-soft);
      color: #1d4ed8;
      border: 1px solid rgba(129, 140, 248, 0.35);
      text-transform: uppercase;
      letter-spacing: 0.12em;
      white-space: nowrap;
    }

    .subtitle {
      margin: 6px 0 0;
      font-size: 13px;
      color: var(--text-sub);
    }

    .form {
      margin-top: 16px;
      display: flex;
      flex-direction: column;
      gap: 14px;
    }

    .field {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }

    label {
      font-size: 12px;
      font-weight: 500;
      color: var(--text-sub);
    }

    input[type="url"],
    input[type="text"] {
      width: 100%;
      padding: 11px 12px;
      font-size: 14px;
      border-radius: var(--radius-md);
      border: 1px solid var(--input-border);
      background: var(--input-bg);
      color: var(--text-main);
      outline: none;
      transition: border-color 0.16s ease, box-shadow 0.16s ease, background-color 0.16s ease, transform 0.06s ease;
    }

    input::placeholder {
      color: var(--text-muted);
    }

    input:focus {
      border-color: var(--primary);
      box-shadow:
        0 0 0 1px var(--primary-border),
        0 0 0 6px var(--input-focus-ring);
      transform: translateY(-0.5px);
    }

    .inline-row { display: flex; gap: 10px; flex-wrap: wrap; }
    .inline-row > .field { flex: 1; min-width: 0; }

    .captcha-wrapper {
      min-height: 58px;
      display: flex;
      align-items: center;
      justify-content: flex-start;
    }

    .captcha-tip {
      font-size: 11px;
      color: var(--text-muted);
      margin-top: 4px;
    }

    .primary-btn {
      margin-top: 6px;
      width: 100%;
      padding: 13px 14px;
      border-radius: var(--radius-lg);
      border: none;
      cursor: pointer;
      font-size: 15px;
      font-weight: 600;
      letter-spacing: 0.04em;
      text-align: center;
      color: #ffffff;
      background-image: linear-gradient(90deg, var(--button-primary-from), var(--button-primary-to));
      box-shadow: var(--button-primary-shadow);
      transform: translateY(0);
      transition:
        box-shadow 0.18s ease,
        transform 0.18s ease,
        filter 0.18s ease,
        opacity 0.18s ease;
    }

    .primary-btn:hover {
      transform: translateY(-1px);
      filter: brightness(1.04);
      box-shadow: 0 18px 38px rgba(37, 99, 235, 0.45);
    }

    .primary-btn:active {
      transform: translateY(0);
      box-shadow: 0 10px 24px rgba(30, 64, 175, 0.6);
      filter: brightness(0.97);
    }

    .primary-btn:disabled {
      cursor: default;
      opacity: 0.65;
      box-shadow: none;
      filter: grayscale(0.1);
    }

    .result {
      margin-top: 18px;
      padding: 14px 12px 12px;
      border-radius: var(--radius-lg);
      background: var(--result-bg);
      border: 1px solid var(--result-border);
      display: none;
    }

    .result-label {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.14em;
      color: var(--text-muted);
      margin-bottom: 6px;
    }

    .result-link {
      font-weight: 650;
      font-size: 14px;
      color: var(--primary);
      word-break: break-all;
      margin-bottom: 10px;
    }

    .copy-btn {
      width: 100%;
      padding: 10px 12px;
      border-radius: var(--radius-md);
      border: none;
      cursor: pointer;
      font-size: 14px;
      font-weight: 550;
      color: #ffffff;
      background-image: linear-gradient(90deg, var(--button-accent-from), var(--button-accent-to));
      box-shadow: var(--button-accent-shadow);
      transition: box-shadow 0.18s ease, transform 0.18s ease, filter 0.18s ease;
    }

    .copy-btn:hover {
      transform: translateY(-0.5px);
      filter: brightness(1.03);
      box-shadow: 0 16px 34px rgba(34, 197, 94, 0.45);
    }

    .copy-btn:active {
      transform: translateY(0);
      box-shadow: 0 10px 22px rgba(22, 163, 74, 0.65);
      filter: brightness(0.98);
    }

    .footnote {
      margin-top: 12px;
      font-size: 11px;
      color: var(--text-muted);
      text-align: center;
      user-select: none;
    }

    @media (max-width: 480px) {
      .card { border-radius: 20px; }
      h1 { font-size: 20px; }
    }
  </style>
</head>
<body>
  <div class="page">
    <header class="brand">
      <div class="brand-dot"></div>
      <span class="brand-title">SHORT URL SERVICE</span>
    </header>

    <main class="shell">
      <section class="card">
        <div class="card-header">
          <div class="title-row">
            <h1>短链接生成</h1>
            <span class="badge">LIQUID GLASS UI</span>
          </div>
          <p class="subtitle">
          无需登陆，适用于分享、重定向和日常使用。为了防止域名屏蔽
          <a href="https://sink.lily.lat/link-fb" target="_blank" rel="noopener noreferrer">点击获取新域名</a>
        </p>
        </div>

        <div class="form">
          <div class="field">
            <label for="u">长链接</label>
            <input
              type="url"
              id="u"
              placeholder="例如：https://example.com/v1/2026/long-url...."
              autocomplete="off"
            />
          </div>

          <div class="inline-row">
            <div class="field">
              <label for="k">自定义后缀（可选）</label>
              <input
                type="text"
                id="k"
                placeholder="例如：good 或者 worker-2026"
                autocomplete="off"
              />
            </div>
          </div>

          <div class="field">
            <label>验证</label>
            <div id="captcha-container" class="captcha-wrapper"></div>
            <div class="captcha-tip" id="captcha-tip">
              如已在 Worker 环境变量启用，将自动加载 Cloudflare Turnstile 验证。
            </div>
          </div>

          <button id="btn" class="primary-btn" onclick="s()">立即生成</button>
        </div>

        <div id="res" class="result">
          <div class="result-label">SHORT LINK</div>
          <div id="link" class="result-link"></div>
          <button class="copy-btn" onclick="cp(this)">点击复制</button>
        </div>
      </section>

      <footer class="footnote">
        通过 Cloudflare 驱动 · 基于 KV 持久化存储 · 后缀链接永久有效
      </footer>
    </main>
  </div>

  <script>
    let tk = "";
    let isVerified = false;

    async function init() {
      try {
        const res = await fetch('/api/get-ui-config');
        const cfg = await res.json();

        const btn = document.getElementById('btn');
        const tip = document.getElementById('captcha-tip');

        if (cfg.captchaEnabled === 'true' && cfg.siteKey) {
          btn.disabled = true;

          const script = document.createElement('script');
          script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js";
          script.async = true;
          document.head.appendChild(script);

          const div = document.createElement('div');
          div.className = "cf-turnstile";
          div.setAttribute('data-sitekey', cfg.siteKey);
          div.setAttribute('data-callback', 'onTs');
          document.getElementById('captcha-container').appendChild(div);

          if (tip) {
            tip.textContent = "请先完成人机验证，然后再生成短链接。";
          }
        } else {
          btn.disabled = false;
          if (tip) {
            tip.textContent = "当前未启用验证码，可直接生成短链接。";
          }
        }
      } catch (e) {
        const btn = document.getElementById('btn');
        if (btn) btn.disabled = false;
      }
    }

    window.onTs = function (t) {
      tk = t;
      isVerified = true;
      const btn = document.getElementById('btn');
      if (btn) btn.disabled = false;
    };

    async function s() {
      const u = document.getElementById('u').value.trim();
      const k = document.getElementById('k').value.trim();

      if (!u || !u.startsWith('http')) {
        alert('请输入以 http 或 https 开头的完整链接。');
        return;
      }

      const btn = document.getElementById('btn');
      if (btn) btn.disabled = true;

      try {
        const res = await fetch('/', {
          method: 'POST',
          body: JSON.stringify({ url: u, key: k, cf_token: tk })
        });
        const d = await res.json();

        if (d.key) {
          const full = window.location.origin + d.key;
          const linkEl = document.getElementById('link');
          const resBox = document.getElementById('res');
          if (linkEl) linkEl.textContent = full;
          if (resBox) resBox.style.display = 'block';
        } else {
          alert('错误：' + (d.error || '生成失败'));
        }
      } catch (e) {
        alert('请求失败，请稍后重试。');
      } finally {
        if (btn) btn.disabled = false;
      }
    }

    function cp(b) {
      const text = document.getElementById('link').textContent;
      if (!text) return;
      navigator.clipboard.writeText(text).then(function () {
        const old = b.innerText;
        b.innerText = '已复制';
        setTimeout(function () {
          b.innerText = old;
        }, 2000);
      });
    }

    init();
  </script>
</body>
</html>`;

// ==================== 3. 后端核心逻辑 ====================
// 说明：
// - KV 命名空间绑定为 LINKS
// - Worker 环境变量：TURNSTILE_SITE_KEY（文本）、TURNSTILE_SECRET_KEY（机密）

async function sha512(url) {
  const url_digest = await crypto.subtle.digest(
    "SHA-512",
    new TextEncoder().encode(url)
  );
  return Array.from(new Uint8Array(url_digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ==================== 3.1 管理后台列表缓存 & 创建时间辅助 ====================
// 说明：
// - 创建时间存储在短链接 key 的 KV metadata 中：{ createdAt: epochMs }
// - 历史数据可能没有 metadata，则 createdAt 视为 0（1970）
const ADMIN_LIST_CACHE_TTL_MS = 4000;
const __adminListCache = {
  at: 0,
  /** @type {null | Array<{name: string, createdAt: number}>} */
  items: null,
};

function invalidateAdminListCache() {
  __adminListCache.at = 0;
  __adminListCache.items = null;
}

function readCreatedAt(meta) {
  if (!meta || typeof meta !== "object") return 0;
  const v = meta.createdAt;
  const n = typeof v === "number" ? v : Number(v);
  return Number.isFinite(n) ? n : 0;
}

async function buildAdminIndex() {
  const out = [];
  let cursor = undefined;
  while (true) {
    const list = await LINKS.list({ cursor, limit: 1000 });
    for (const k of list.keys) {
      // 过滤：哈希索引（sha512=128位） + 旧的系统配置 key
      if (k.name.length !== 128 && !k.name.startsWith("SYS_CONFIG_")) {
        out.push({ name: k.name, createdAt: readCreatedAt(k.metadata) });
      }
    }
    if (list.list_complete || !list.cursor) break;
    cursor = list.cursor;
  }
  return out;
}

async function getAdminIndexCached() {
  const now = Date.now();
  if (__adminListCache.items && (now - __adminListCache.at) < ADMIN_LIST_CACHE_TTL_MS) {
    // 返回副本，避免排序时把缓存数组原地改掉
    return __adminListCache.items.slice();
  }
  const items = await buildAdminIndex();
  __adminListCache.items = items;
  __adminListCache.at = now;
  return items.slice();
}

async function handleRequest(request) {
  const url = new URL(request.url);
  const pathname = url.pathname;
  const path = decodeURIComponent(pathname.split("/")[1]);
  const auth = request.headers.get("Authorization");

  function normalizeAdminPath(p) {
    let v = (typeof p === "string" ? p : "").trim();
    if (!v) v = "/admin";
    if (!v.startsWith("/")) v = "/" + v;
    while (v.length > 1 && v.endsWith("/")) v = v.slice(0, -1);
    if (v === "/") v = "/admin";
    return v;
  }

  function isTruthyEnv(v) {
    if (typeof v !== "string") return false;
    const s = v.trim().toLowerCase();
    return s === "true" || s === "1" || s === "yes" || s === "y" || s === "on";
  }

  // ==================== 环境变量配置 ====================
  // 1) 后台入口路径：ADMIN_PATH（文本），例如：/a8f3k2p9
  // 2) Turnstile 开关：CAPTCHA_ENABLED（文本 true/false）
  const adminBase = normalizeAdminPath(typeof ADMIN_PATH === "string" ? ADMIN_PATH : "");
  const adminApiBase = adminBase + "/api";
  const captchaEnabled = isTruthyEnv(typeof CAPTCHA_ENABLED === "string" ? CAPTCHA_ENABLED : "") ? "true" : "false";

  const htmlHeaders = {
    "content-type": "text/html;charset=UTF-8",
    "Access-Control-Allow-Origin": "*",
    "cache-control": "no-store",
  };

  const jsonHeaders = {
    "content-type": "application/json;charset=UTF-8",
    "Access-Control-Allow-Origin": "*",
    "cache-control": "no-store",
  };

  // 后台页面（路径由环境变量控制）
  if (pathname === adminBase || pathname === adminBase + "/") {
    return new Response(htmlAdmin, { headers: htmlHeaders });
  }

  // 后台：获取短链接列表（分页 + 排序 + 显示长链接 + 创建时间）
  // GET {adminApiBase}/all?page=1&size=10&sort=name|time
  if (pathname === adminApiBase + "/all") {
    if (auth !== INTERNAL_CONFIG.admin_pass) {
      return new Response("Unauthorized", { status: 401 });
    }

    const pageRaw = Number(url.searchParams.get("page") || "1");
    const sizeRaw = Number(url.searchParams.get("size") || "10");
    const sortRaw = String(url.searchParams.get("sort") || "name").toLowerCase();

    const size = Math.min(10, Math.max(1, Math.floor(Number.isFinite(sizeRaw) ? sizeRaw : 10)));
    const sort = sortRaw === "time" ? "time" : "name";

    // 读取索引（带 createdAt），并按用户选择排序
    const index = await getAdminIndexCached();

    if (sort === "time") {
      // 新 → 旧；同时间按 name 稳定排序
      index.sort((a, b) => {
        const dt = (b.createdAt || 0) - (a.createdAt || 0);
        if (dt !== 0) return dt;
        return a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: "base" });
      });
    } else {
      // A → Z，支持数字排序（a2 < a10）
      index.sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: "base" }));
    }

    const total = index.length;
    const totalPages = Math.max(1, Math.ceil(total / size));
    const page = Math.min(totalPages, Math.max(1, Math.floor(Number.isFinite(pageRaw) ? pageRaw : 1)));

    const start = (page - 1) * size;
    const pageItems = index.slice(start, start + size);

    // 每页最多 10 条，只取这一页的长链接，避免全量 KV.get 造成缓慢
    const values = await Promise.all(pageItems.map((it) => LINKS.get(it.name)));

    const links = [];
    const missingKeys = [];
    for (let i = 0; i < pageItems.length; i++) {
      const it = pageItems[i];
      const val = values[i];
      if (typeof val === "string" && val.length) {
        links.push({ name: it.name, value: val, createdAt: it.createdAt || 0 });
      } else {
        // 极少数情况下，list 到 key 但 get 为空（例如刚被删），顺手清理
        missingKeys.push(it.name);
      }
    }

    if (missingKeys.length) {
      await Promise.all(missingKeys.map((k) => LINKS.delete(k)));
      invalidateAdminListCache();
    }

    return new Response(
      JSON.stringify({ page, size, sort, total, totalPages, links }),
      { headers: jsonHeaders }
    );
  }

  // 后台：删除指定后缀短链（包括哈希索引）
  if (pathname.startsWith(adminApiBase + "/delete/")) {
    if (auth !== INTERNAL_CONFIG.admin_pass) {
      return new Response("Unauthorized", { status: 401 });
    }

    const prefix = adminApiBase + "/delete/";
    const keyDel = decodeURIComponent(pathname.slice(prefix.length) || "");
    if (!keyDel) return new Response("Bad Request", { status: 400 });

    const longUrl = await LINKS.get(keyDel);
    if (longUrl) {
      const hash = await sha512(longUrl);
      await Promise.all([LINKS.delete(hash), LINKS.delete(keyDel)]);
    } else {
      await LINKS.delete(keyDel);
    }

    // 刷新后台列表缓存
    invalidateAdminListCache();

    return new Response("OK", { headers: { "cache-control": "no-store" } });
  }

  // 前端：获取 UI 配置（开关 + siteKey 全部来自环境变量）
  if (pathname === "/api/get-ui-config") {
    return new Response(
      JSON.stringify({
        captchaEnabled,
        siteKey: typeof TURNSTILE_SITE_KEY === "string" ? TURNSTILE_SITE_KEY : "",
      }),
      { headers: jsonHeaders }
    );
  }

  // 生成短链（全部永久）
  if (request.method === "POST") {
    const req = await request.json();

    // 启用验证码时校验 Turnstile（使用机密 TURNSTILE_SECRET_KEY）
    if (captchaEnabled === "true" && req.cf_token) {
      const secret =
        typeof TURNSTILE_SECRET_KEY === "string" ? TURNSTILE_SECRET_KEY : "";
      const f = new FormData();
      f.append("secret", secret);
      f.append("response", req.cf_token);
      try {
        const vr = await fetch(
          "https://challenges.cloudflare.com/turnstile/v0/siteverify",
          {
            method: "POST",
            body: f,
          }
        );
        const vo = await vr.json();
        // 仍旧宽松模式，不强制校验 vo.success
      } catch (e) {
        // 保证服务可用，不因验证失败直接阻断
      }
    }

    let key = req.key || Math.random().toString(36).substring(2, 8);
    if (req.key && (await LINKS.get(req.key))) {
      return new Response(JSON.stringify({ error: "后缀已占用" }), {
        status: 409,
        headers: jsonHeaders,
      });
    }

    const hash = await sha512(req.url);
    const existKey = await LINKS.get(hash);

    if (!req.key && existKey) {
      // 已为该长链接生成过短链，直接复用
      key = existKey;
    } else {
      // 全部永久：不设置 expirationTtl
      await LINKS.put(key, req.url, { metadata: { createdAt: Date.now() } });
      if (!req.key) await LINKS.put(hash, key);

      // 新增后刷新后台列表缓存
      invalidateAdminListCache();
    }

    return new Response(JSON.stringify({ key: "/" + key }), {
      headers: jsonHeaders,
    });
  }

  // 首页 or 重定向
  if (!path) return new Response(htmlIndex, { headers: htmlHeaders });

  const target = await LINKS.get(path);
  if (target) return Response.redirect(target + url.search, 302);

  return new Response("404 Not Found", { status: 404 });
}

addEventListener("fetch", (e) => e.respondWith(handleRequest(e.request)));

