import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import { SessionView, type CallState } from './SessionView'

const jwk = {
  kty: 'EC' as const,
  crv: 'P-256' as const,
  x: 'x-coordinate',
  y: 'y-coordinate',
}

const idle: CallState = { status: 'idle' }

function render(accessJkt: string | null, bearer: CallState = idle) {
  return renderToStaticMarkup(
    <SessionView
      profileTitle="Ada Lovelace"
      profileLines={[{ label: 'sub', value: 'user-1' }]}
      publicJwk={jwk}
      jkt="thumbprint-a"
      tokenType="DPoP"
      accessJkt={accessJkt}
      accessIsJwt
      accessPayload={{ cnf: { jkt: accessJkt } }}
      accessSignature="Signature verified with the app JWKS."
      rawAccessToken="header.payload.signature"
      idSignature="Signature verified with the app JWKS."
      idPayload={{ sub: 'user-1' }}
      signingLines={[{ label: 'Access token kid', value: 'kid-1 (published in the JWKS)' }]}
      refreshDetail="Refresh token is present."
      canRefresh
      refreshBusy={false}
      refreshError={null}
      dpopCall={idle}
      bearerCall={bearer}
      onSignOut={() => undefined}
      onRefresh={() => undefined}
      onDpopUserinfo={() => undefined}
      onBearerUserinfo={() => undefined}
    />,
  )
}

describe('SessionView', () => {
  it('shows a match when cnf.jkt equals the browser thumbprint', () => {
    const html = render('thumbprint-a')
    expect(html).toContain('Match. The access token is attached to this browser key.')
    expect(html).toContain('token_type is DPoP.')
    expect(html).toContain('It is not bound to the DPoP key.')
  })

  it('shows a mismatch when the token is bound to another key', () => {
    const html = render('thumbprint-b')
    expect(html).toContain('Does not match the key in this browser.')
  })

  it('treats Bearer rejection as the expected result and Bearer success as a failure', () => {
    const rejected = render('thumbprint-a', {
      status: 'done',
      result: { status: 401, wwwAuthenticate: 'DPoP error="invalid_token"', body: { error: 'invalid_token' } },
    })
    expect(rejected).toContain('Rejected (HTTP 401).')
    expect(rejected).toContain('DPoP error=&quot;invalid_token&quot;')

    const accepted = render('thumbprint-a', {
      status: 'done',
      result: { status: 200, wwwAuthenticate: null, body: { sub: 'user-1' } },
    })
    expect(accepted).toContain('Accepted (HTTP 200).')
    expect(accepted).toContain('class="banner bad"')
  })
})
