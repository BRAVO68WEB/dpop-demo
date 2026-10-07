import * as jose from 'jose'
import { describe, expect, it } from 'vitest'
import { accessTokenHash, createDpopProof, ecPublicJwk, generateDpopKey, proofHtu } from './dpop'

const rfcJwk = {
  kty: 'EC',
  x: 'l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs',
  y: '9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA',
  crv: 'P-256',
}

describe('DPoP proof', () => {
  it('uses the RFC 7638 thumbprint from RFC 9449', async () => {
    await expect(jose.calculateJwkThumbprint(rfcJwk)).resolves.toBe('0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I')
  })

  it('hashes the access token the way RFC 9449 does', async () => {
    const token = 'Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU'
    await expect(accessTokenHash(token)).resolves.toBe('fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo')
  })

  it('drops the query and fragment from htu', () => {
    expect(proofHtu('https://auth.example.com/token?extra=1#fragment')).toBe('https://auth.example.com/token')
  })

  it('signs a proof bound to one request and keeps the private key local', async () => {
    const key = await generateDpopKey()
    await expect(crypto.subtle.exportKey('jwk', key.privateKey)).rejects.toThrow()
    expect(key.jkt).toBe(await jose.calculateJwkThumbprint(key.publicJwk))

    const accessToken = 'access-token-value'
    const proof = await createDpopProof({
      privateKey: key.privateKey,
      publicJwk: key.publicJwk,
      htm: 'get',
      htu: 'https://api.example.com/userinfo?drop=this',
      accessToken,
      nonce: 'server-nonce',
    })

    const verified = await jose.jwtVerify(proof, key.publicKey, { typ: 'dpop+jwt' })
    expect(verified.protectedHeader.alg).toBe('ES256')
    expect(verified.protectedHeader.jwk).toEqual(key.publicJwk)
    expect(verified.protectedHeader.jwk).not.toHaveProperty('d')
    expect(verified.payload.htm).toBe('GET')
    expect(verified.payload.htu).toBe('https://api.example.com/userinfo')
    expect(verified.payload.ath).toBe(await accessTokenHash(accessToken))
    expect(verified.payload.nonce).toBe('server-nonce')
    expect(ecPublicJwk(verified.protectedHeader.jwk as jose.JWK).crv).toBe('P-256')
  })

  it('omits ath when no access token is presented', async () => {
    const key = await generateDpopKey()
    const proof = await createDpopProof({
      privateKey: key.privateKey,
      publicJwk: key.publicJwk,
      htm: 'POST',
      htu: 'https://auth.example.com/token',
    })
    expect(jose.decodeJwt(proof).ath).toBeUndefined()
  })
})
