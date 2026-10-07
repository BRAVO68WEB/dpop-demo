export type Attempt = {
  status: number
  headers: Headers
  body: unknown
}

function errorCode(body: unknown): string | null {
  if (!body || typeof body !== 'object' || !('error' in body)) return null
  const error = (body as { error?: unknown }).error
  return typeof error === 'string' ? error : null
}

/** Token endpoint uses HTTP 400. A resource server uses HTTP 401. One retry. */
export function nonceChallenge(attempt: Attempt): string | null {
  if (attempt.status !== 400 && attempt.status !== 401) return null
  const nonce = attempt.headers.get('DPoP-Nonce')
  if (!nonce) return null
  const www = attempt.headers.get('WWW-Authenticate') ?? ''
  if (errorCode(attempt.body) === 'use_dpop_nonce' || www.toLowerCase().includes('use_dpop_nonce')) {
    return nonce
  }
  return null
}

export async function withDpopNonceRetry(send: (nonce?: string) => Promise<Attempt>): Promise<Attempt> {
  const first = await send(undefined)
  const nonce = nonceChallenge(first)
  if (!nonce) return first
  return send(nonce)
}
