import { describe, expect, it } from 'vitest'
import { withDpopNonceRetry } from './nonceRetry'

describe('withDpopNonceRetry', () => {
  it('retries once when the token endpoint asks for a nonce', async () => {
    const nonces: Array<string | undefined> = []
    const result = await withDpopNonceRetry(async (nonce) => {
      nonces.push(nonce)
      if (!nonce) {
        return {
          status: 400,
          headers: new Headers({ 'DPoP-Nonce': 'server-nonce' }),
          body: { error: 'use_dpop_nonce' },
        }
      }
      return { status: 200, headers: new Headers(), body: { access_token: 'token', token_type: 'DPoP' } }
    })
    expect(nonces).toEqual([undefined, 'server-nonce'])
    expect(result.status).toBe(200)
  })

  it('retries a resource-server challenge carried in WWW-Authenticate', async () => {
    let calls = 0
    const result = await withDpopNonceRetry(async (nonce) => {
      calls += 1
      if (!nonce) {
        return {
          status: 401,
          headers: new Headers({
            'DPoP-Nonce': 'resource-nonce',
            'WWW-Authenticate': 'DPoP error="use_dpop_nonce"',
          }),
          body: '',
        }
      }
      return { status: 200, headers: new Headers(), body: { sub: 'user' } }
    })
    expect(calls).toBe(2)
    expect(result.status).toBe(200)
  })

  it('does not retry a different token error', async () => {
    let calls = 0
    const result = await withDpopNonceRetry(async () => {
      calls += 1
      return {
        status: 400,
        headers: new Headers({ 'DPoP-Nonce': 'ignored' }),
        body: { error: 'invalid_grant' },
      }
    })
    expect(calls).toBe(1)
    expect(result.status).toBe(400)
  })
})
