import { useEffect, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { appConfig } from '../config'
import { decodeJwt } from '../auth/dpop'
import { audienceIncludes, exchangeCode, issuersMatch, loadDiscovery } from '../auth/loginradius'
import { clearTransaction, loadKey, loadTransaction, saveTokens } from '../auth/storage'
import { Card, Shell } from './Shell'

export function Callback() {
  const navigate = useNavigate()
  const [params] = useSearchParams()
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const query = params.toString()
    let cancel = false
    void finish(query)
      .then(() => {
        if (!cancel) navigate('/session', { replace: true })
      })
      .catch((caught: unknown) => {
        if (!cancel) setError(caught instanceof Error ? caught.message : 'Sign-in failed.')
      })
    return () => {
      cancel = true
    }
  }, [navigate, params])

  return (
    <Shell>
      <Card title={error ? 'Sign-in stopped' : 'Signing you in'} heading="h1">
        {error ? (
          <>
            <p className="banner bad">{error}</p>
            <Link className="button secondary" to="/">
              Back to sign in
            </Link>
          </>
        ) : (
          <p>Exchanging the authorization code for a DPoP-bound token.</p>
        )}
      </Card>
    </Shell>
  )
}

async function finish(query: string): Promise<void> {
  const params = new URLSearchParams(query)
  const oauthError = params.get('error')
  if (oauthError) {
    clearTransaction()
    throw new Error(params.get('error_description') || oauthError)
  }

  const transaction = loadTransaction()
  if (!transaction) throw new Error('This sign-in attempt is missing from this tab. Start again.')

  const code = params.get('code')
  if (!code) throw new Error('The authorization response did not include a code.')
  if (params.get('state') !== transaction.state) {
    throw new Error('State did not match the sign-in request. Start again.')
  }

  const discovery = await loadDiscovery()
  const iss = params.get('iss')
  if (iss && !issuersMatch(iss, discovery.issuer)) {
    throw new Error('The authorization response issuer did not match discovery.')
  }

  const key = await loadKey()
  if (!key) throw new Error('The DPoP key is missing from this browser. Start again.')
  if (key.jkt !== transaction.jkt) {
    throw new Error('The DPoP key changed during sign-in. Start again.')
  }

  const config = appConfig()
  const tokens = await exchangeCode({
    tokenEndpoint: discovery.token_endpoint,
    clientId: config.clientId,
    redirectUri: transaction.redirectUri,
    code,
    codeVerifier: transaction.codeVerifier,
    key,
  })

  if (!tokens.id_token) throw new Error('Token response did not include an ID token.')
  const idToken = decodeJwt(tokens.id_token)
  if (!idToken) throw new Error('ID token was not a JWT.')
  if (idToken.payload.nonce !== transaction.nonce) {
    throw new Error('ID token nonce did not match the sign-in request.')
  }
  if (typeof idToken.payload.iss !== 'string' || !issuersMatch(idToken.payload.iss, discovery.issuer)) {
    throw new Error('ID token issuer did not match discovery.')
  }
  if (!audienceIncludes(idToken.payload.aud, config.clientId)) {
    throw new Error('ID token audience did not include this client.')
  }

  saveTokens(tokens)
  clearTransaction()
}
