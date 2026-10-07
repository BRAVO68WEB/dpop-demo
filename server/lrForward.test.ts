import { describe, expect, it } from 'vitest'
import { assertAllowedTarget, TargetError, upstreamHeaders } from './lrForward'

const issuer = 'https://demo.hub.loginradius.com/service/oidc/DemoApp'

describe('assertAllowedTarget', () => {
  it('allows another path on the issuer origin', () => {
    const url = assertAllowedTarget('https://demo.hub.loginradius.com/api/oidc/DemoApp/token', issuer)
    expect(url.pathname).toBe('/api/oidc/DemoApp/token')
  })

  it('rejects a different origin', () => {
    expect(() => assertAllowedTarget('https://evil.example/token', issuer)).toThrow(TargetError)
  })

  it('rejects a non-http URL', () => {
    expect(() => assertAllowedTarget('javascript:alert(1)', issuer)).toThrow(TargetError)
  })

  it('rejects an issuer that is not a URL', () => {
    expect(() => assertAllowedTarget('https://demo.hub.loginradius.com/token', 'not a url')).toThrow(
      /VITE_LR_ISSUER/,
    )
  })
})

describe('upstreamHeaders', () => {
  it('tells LoginRadius the target scheme so htu stays https', () => {
    const headers = upstreamHeaders(
      { headers: { dpop: 'proof', authorization: 'DPoP token', accept: 'application/json' } } as never,
      new URL('https://demo.hub.loginradius.com/api/oidc/DemoApp/token'),
    )
    expect(headers.get('x-forwarded-proto')).toBe('https')
    expect(headers.get('dpop')).toBe('proof')
    expect(headers.get('authorization')).toBe('DPoP token')
  })

  it('uses http when the target is http', () => {
    const headers = upstreamHeaders({ headers: {} } as never, new URL('http://127.0.0.1:3201/api/oidc/app/token'))
    expect(headers.get('x-forwarded-proto')).toBe('http')
  })
})
