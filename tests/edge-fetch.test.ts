import { readFile } from 'node:fs/promises';
import ts from 'typescript';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { describe, expect, it } from 'vitest';

const siteverify = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
const certs = 'https://lilyya.cloudflareaccess.com/cdn-cgi/access/certs';
const fixtureSecret = 'fixture-secret';
const compiled = ts.transpileModule(
  await readFile(new URL('../src/edge-fetch.ts', import.meta.url), 'utf8'),
  { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } },
).outputText;

async function runtimeProbe(
  target: string,
  post: boolean,
  respond: (request: Request) => Promise<Response> | Response,
) {
  const calls: string[] = [];
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      modules: true,
      compatibilityDate: '2026-07-02',
      script: `${compiled}
        export default {async fetch() {
          try {
            const response = await edgeFetch(${JSON.stringify(target)}, {
              method: ${JSON.stringify(post ? 'POST' : 'GET')},
              redirect: 'follow',
              ${post ? `body: new URLSearchParams({secret: '${fixtureSecret}', response: 'fixture-response'}),` : ''}
              signal: AbortSignal.timeout(8000),
            });
            return Response.json({status: response.status, body: await response.json()});
          } catch (error) {
            return Response.json({error: error.message}, {status: 502});
          }
        }}`,
      outboundService: async (request) => {
        calls.push(request.url);
        if (request.url !== target) throw new Error('FOREIGN_FIXTURE_REQUEST');
        return respond(request as unknown as Request);
      },
    }),
  );
  try {
    const response = await mf.dispatchFetch('http://localhost/');
    return { status: response.status, data: await response.json(), calls };
  } finally {
    await mf.dispose();
  }
}

describe('redirect refusal in the actual Workers runtime', () => {
  it('sends a correctly encoded Siteverify request without unsupported redirect mode', async () => {
    const result = await runtimeProbe(siteverify, true, async (request) => {
      expect(request.method).toBe('POST');
      expect(request.headers.get('Content-Type')).toContain('application/x-www-form-urlencoded');
      const form = new URLSearchParams(await request.text());
      expect([...form.keys()].sort()).toEqual(['response', 'secret']);
      expect(form.get('secret')).toBe(fixtureSecret);
      expect(form.get('response')).toBe('fixture-response');
      return Response.json({ success: false, 'error-codes': ['invalid-input-response'] });
    });
    expect(result).toMatchObject({
      status: 200,
      data: { status: 200, body: { success: false } },
      calls: [siteverify],
    });
  });

  it('can fetch Access public keys through the same supported runtime path', async () => {
    const result = await runtimeProbe(certs, false, (request) => {
      expect(request.method).toBe('GET');
      return Response.json({ keys: [] });
    });
    expect(result).toMatchObject({ status: 200, data: { status: 200, body: { keys: [] } } });
    expect(result.calls).toEqual([certs]);
  });

  it('rejects a POST redirect without forwarding its secret to another origin', async () => {
    const result = await runtimeProbe(
      siteverify,
      true,
      () =>
        new Response('private upstream response', {
          status: 307,
          headers: { Location: 'https://foreign.example.test/collect' },
        }),
    );
    expect(result).toEqual({
      status: 502,
      data: { error: 'UPSTREAM_REDIRECT_REJECTED' },
      calls: [siteverify],
    });
    expect(JSON.stringify(result)).not.toContain(fixtureSecret);
    expect(JSON.stringify(result)).not.toContain('private upstream response');
  });

  it('rejects a redirected JWKS lookup instead of trusting the redirect target', async () => {
    const result = await runtimeProbe(
      certs,
      false,
      () =>
        new Response(null, {
          status: 302,
          headers: { Location: 'https://foreign.example.test/keys' },
        }),
    );
    expect(result).toEqual({
      status: 502,
      data: { error: 'UPSTREAM_REDIRECT_REJECTED' },
      calls: [certs],
    });
  });
});
