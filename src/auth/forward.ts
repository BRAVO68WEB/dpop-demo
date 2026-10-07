/** Same-origin proxy. The DPoP proof's htu stays the upstream URL. */
export function forward(upstream: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers)
  headers.set('X-LR-Target', upstream)
  return fetch('/lr/forward', {
    method: init.method ?? 'GET',
    headers,
    body: init.body,
  })
}
