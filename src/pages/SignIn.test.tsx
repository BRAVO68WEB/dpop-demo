import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import { SignInView } from './SignIn'

describe('SignInView', () => {
  it('keeps Sign in disabled until the client is configured', () => {
    const html = renderToStaticMarkup(
      <SignInView
        issuer=""
        clientId=""
        redirectUri="http://localhost:5173/callback"
        problems={['Set VITE_LR_ISSUER.', 'Set VITE_LR_CLIENT_ID.']}
        discovery={{ status: 'skipped' }}
        busy={false}
        actionError={null}
        onSignIn={() => undefined}
        onRetryDiscovery={() => undefined}
      />,
    )
    expect(html).toContain('Set VITE_LR_ISSUER.')
    expect(html).toContain('disabled')
    expect(html).toContain('Sign in')
  })

  it('enables Sign in when discovery advertises ES256', () => {
    const html = renderToStaticMarkup(
      <SignInView
        issuer="https://demo.hub.loginradius.com/service/oidc/Demo"
        clientId="client-1"
        redirectUri="http://localhost:5173/callback"
        problems={[]}
        discovery={{
          status: 'ready',
          discovery: {
            issuer: 'https://demo.hub.loginradius.com/service/oidc/Demo',
            authorization_endpoint: 'https://demo.hub.loginradius.com/service/oidc/Demo/authorize',
            token_endpoint: 'https://demo.hub.loginradius.com/api/oidc/Demo/token',
            userinfo_endpoint: 'https://demo.hub.loginradius.com/service/oidc/Demo/userinfo',
            jwks_uri: 'https://demo.hub.loginradius.com/service/oidc/Demo/jwks',
            dpop_signing_alg_values_supported: ['ES256', 'RS256'],
          },
        }}
        busy={false}
        actionError={null}
        onSignIn={() => undefined}
        onRetryDiscovery={() => undefined}
      />,
    )
    expect(html).toContain('ES256, RS256')
    expect(html).not.toContain('disabled')
  })
})
