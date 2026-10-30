import { ERROR_PAGE_HTML_MAX_BYTES } from './error-page-config';

const ISOLATED_CSP =
  "sandbox allow-scripts; default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; font-src data:; connect-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'";

const isolatedResponses = new WeakMap<Response, 'custom' | 'preview'>();

export function isolatedErrorPageKind(response: Response): 'custom' | 'preview' | undefined {
  return isolatedResponses.get(response);
}

function isolatedHtml(html: string, status: number, kind: 'custom' | 'preview'): Response {
  const response = new Response(html, {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'Content-Security-Policy': `${ISOLATED_CSP}; frame-ancestors ${kind === 'preview' ? 'https://link-admin.lily.lat' : "'none'"}`,
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'X-Frame-Options': kind === 'preview' ? 'SAMEORIGIN' : 'DENY',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    },
  });
  isolatedResponses.set(response, kind);
  return response;
}

export function customErrorPage(html: string, status: number): Response {
  return isolatedHtml(html, status, 'custom');
}

export function errorPagePreview(): Response {
  // This fixed bootstrap is the only code that handles the transferred port.
  // Defer document.write until the message event ends so uploaded scripts cannot
  // recover the private port through window.event. Bind its method before any
  // uploaded code can replace MessagePort.prototype.postMessage.
  const html = `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>应用错误页预览</title><body><script>
  (() => {
    const receive = (event) => {
      if (event.source !== parent || event.origin !== 'https://link-admin.lily.lat') return;
      const data = event.data;
      if (!data || data.type !== 'shortlink:error-preview' || typeof data.html !== 'string' || event.ports.length !== 1) return;
      if (new TextEncoder().encode(data.html).byteLength > ${ERROR_PAGE_HTML_MAX_BYTES}) return;
      removeEventListener('message', receive);
      const port = event.ports[0];
      const complete = port.postMessage.bind(port);
      const close = port.close.bind(port);
      const source = data.html;
      setTimeout(() => {
        document.open();
        const loaded = (event) => {
          if (!event.isTrusted || document.readyState !== 'complete') return;
          removeEventListener('load', loaded);
          complete({type: 'loaded'});
          close();
        };
        addEventListener('load', loaded);
        document.write(source);
        document.close();
      }, 0);
    };
    addEventListener('message', receive);
  })();
  </script></body></html>`;
  return isolatedHtml(html, 200, 'preview');
}
