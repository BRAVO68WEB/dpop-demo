import { describe, expect, it } from 'vitest'
import { base64url } from './base64url'
import { createPkce } from './pkce'

describe('PKCE', () => {
  it('creates an S256 challenge for a 43 character verifier', async () => {
    const { verifier, challenge } = await createPkce()
    expect(verifier).toMatch(/^[A-Za-z0-9_-]{43}$/)
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
    expect(challenge).toBe(base64url(new Uint8Array(digest)))
  })
})
