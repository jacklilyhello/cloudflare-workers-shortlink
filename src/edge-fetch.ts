/** Workers supports manual redirects; reject them before any second request. */
export async function edgeFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const response = await fetch(input, { ...init, redirect: 'manual' });
  if (response.status >= 300 && response.status < 400) {
    await response.body?.cancel();
    throw new Error('UPSTREAM_REDIRECT_REJECTED');
  }
  return response;
}
