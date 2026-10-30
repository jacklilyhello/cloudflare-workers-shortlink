export const INTERSTITIAL_HTML_MAX_BYTES = 128 * 1024;
export const INTERSTITIAL_BODY_MAX_BYTES = INTERSTITIAL_HTML_MAX_BYTES * 6 + 8192;

export function validPageContent(value: unknown, mode: 'text' | 'html'): value is string {
  return (
    typeof value === 'string' &&
    !/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value) &&
    (mode === 'text'
      ? value.length <= 2000
      : new TextEncoder().encode(value).byteLength <= INTERSTITIAL_HTML_MAX_BYTES)
  );
}

function escape(value: string): string {
  return value.replace(
    /[&<>"']/g,
    (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]!,
  );
}

const responses = new WeakSet<Response>();
export function isInterstitialResponse(response: Response): boolean {
  return responses.has(response);
}

/** Only the trusted outer document controls the destination and countdown.
 * Custom scripts run in an opaque-origin frame without parent DOM access;
 * resource fetches are restricted by CSP.
 */
export function interstitialPage(
  target: string,
  content: string,
  mode: 'text' | 'html',
  delay: number | null,
): Response {
  const automatic = delay !== null;
  const seconds = automatic ? Math.max(0, Math.min(300, Math.trunc(delay))) : 0;
  const title = automatic ? '即将前往目标网站' : '即将前往其他网站';
  const childPolicy =
    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; font-src data:; connect-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'";
  const frameDocument = `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="${escape(childPolicy)}"><meta name="viewport" content="width=device-width,initial-scale=1"></head><body>${content}</body></html>`;
  const body =
    mode === 'html' && content.trim()
      ? `<iframe title="自定义页面内容" sandbox="allow-scripts" referrerpolicy="no-referrer" srcdoc="${escape(frameDocument)}"></iframe>`
      : `<main><h1>${title}</h1><p>${escape(content || '请确认后继续访问。')}</p></main>`;
  const timer = automatic
    ? `<p id="countdown" role="status">${seconds} 秒后自动继续</p><script>(()=>{const link=document.getElementById('continue');const label=document.getElementById('countdown');const end=Date.now()+${seconds}*1000;const tick=()=>{const remaining=Math.max(0,Math.ceil((end-Date.now())/1000));label.textContent=remaining+' 秒后自动继续';if(remaining===0){location.replace(link.href);return;}setTimeout(tick,200);};tick();})();</script><noscript>请点击继续访问。</noscript>`
    : '';
  const response = new Response(
    `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><style>html{color-scheme:light dark;font:16px/1.6 system-ui,sans-serif;background:#102027;color:#e6f2f4}body{margin:0;min-height:100vh;display:flex;flex-direction:column}main{box-sizing:border-box;width:min(680px,100%);margin:auto;padding:40px 24px}p{white-space:pre-wrap;overflow-wrap:anywhere}iframe{border:0;width:100%;min-height:65vh;flex:1;background:#fff}footer{text-align:center;padding:20px 24px;background:#142c34}a{display:inline-block;padding:10px 28px;border-radius:12px;background:#8cded0;color:#102027;text-decoration:none;font-weight:650}#countdown{margin:8px 0 0;font-size:14px;color:#b4c8ce}</style></head><body>${body}<footer><a id="continue" href="${escape(target)}" rel="noreferrer noopener">继续访问</a>${timer}</footer></body></html>`,
    {
      status: 200,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        // srcdoc inherits this policy. Input exists only as escaped iframe source;
        // no uploaded code is inserted in the outer document or accepted via messages.
        'Content-Security-Policy':
          "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; font-src data:; connect-src 'none'; frame-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
        'X-Frame-Options': 'DENY',
        'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
      },
    },
  );
  responses.add(response);
  return response;
}
