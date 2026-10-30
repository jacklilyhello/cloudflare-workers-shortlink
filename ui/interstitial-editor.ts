import './interstitial-editor.css';

const HTML_MAX_BYTES = 128 * 1024;

export function pageContentEditor(options: {
  mode?: 'text' | 'html';
  value?: string;
  htmlOnly?: boolean;
}) {
  const node = document.createElement('div');
  node.className = 'custom-page-editor';
  const modeLabel = document.createElement('label');
  modeLabel.className = 'field';
  const modeTitle = document.createElement('span');
  modeTitle.textContent = '页面内容格式';
  const mode = document.createElement('select');
  mode.setAttribute('aria-label', '页面内容格式');
  for (const [value, label] of [
    ['text', '纯文本'],
    ['html', '自定义 HTML + CSS + JS'],
  ]) {
    if (options.htmlOnly && value === 'text') continue;
    const option = document.createElement('option');
    option.value = value;
    option.textContent = label;
    mode.append(option);
  }
  mode.value = options.htmlOnly ? 'html' : (options.mode ?? 'text');
  modeLabel.append(modeTitle, mode);
  const label = document.createElement('label');
  label.className = 'field';
  const title = document.createElement('span');
  const input = document.createElement('textarea');
  input.value = options.value ?? '';
  input.spellcheck = false;
  input.autocapitalize = 'off';
  input.setAttribute('aria-label', '页面内容');
  const hint = document.createElement('span');
  hint.className = 'hint';
  const refresh = () => {
    const html = mode.value === 'html';
    title.textContent = html ? '页面源码' : '确认页文字';
    input.maxLength = html ? HTML_MAX_BYTES : 2000;
    input.classList.toggle('source-editor', html);
    input.placeholder = html
      ? '<style>body { font-family: sans-serif; }</style>\n<h1>即将前往目标网站</h1>\n<script>/* 自定义页面交互 */</script>'
      : '请确认后继续访问。';
    hint.textContent = html
      ? '支持 HTML、<style> CSS 和 <script> JS，UTF-8 最多 128 KiB。自定义内容在隔离页面运行，无法访问后台；外部资源和网络请求受限。系统负责继续访问与跳转计时。'
      : '最多 2000 字符。纯文本模式不会执行 HTML 或 JavaScript。';
  };
  mode.addEventListener('change', refresh);
  refresh();
  label.append(title, input, hint);
  node.append(modeLabel, label);
  return {
    node,
    input,
    mode,
    value() {
      const html = mode.value === 'html';
      if (html && new TextEncoder().encode(input.value).byteLength > HTML_MAX_BYTES)
        throw new Error('页面源码的 UTF-8 大小不能超过 128 KiB。');
      if (!html && input.value.length > 2000) throw new Error('确认页文字不能超过 2000 字符。');
      return { mode: html ? ('html' as const) : ('text' as const), content: input.value };
    },
  };
}
