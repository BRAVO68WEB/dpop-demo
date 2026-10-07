import { useEffect, useState } from 'react'
import { appConfig } from '../config'
import { generateDpopKey } from '../auth/dpop'
import { loadDiscovery, supportsEs256 } from '../auth/loginradius'
import { createPkce } from '../auth/pkce'
import { randomId } from '../auth/base64url'
import { loadKey, saveKey, saveTransaction } from '../auth/storage'
import type { Discovery } from '../auth/types'
import { Card, Shell } from './Shell'

type DiscoveryState =
  | { status: 'skipped' }
  | { status: 'loading' }
  | { status: 'ready'; discovery: Discovery }
  | { status: 'error'; message: string }

export function SignInView({
  issuer,
  clientId,
  redirectUri,
  problems,
  discovery,
  busy,
  actionError,
  onSignIn,
  onRetryDiscovery,
}: {
  issuer: string
  clientId: string
  redirectUri: string
  problems: string[]
  discovery: DiscoveryState
  busy: boolean
  actionError: string | null
  onSignIn: () => void
  onRetryDiscovery: () => void
}) {
  const es256 = discovery.status === 'ready' && supportsEs256(discovery.discovery)
  const ready = problems.length === 0 && es256 && !busy
  const algs =
    discovery.status === 'ready' ? (discovery.discovery.dpop_signing_alg_values_supported ?? []) : []

  return (
    <Shell>
      <Card title="Sign in" heading="h1">
        <p className="lede">
          This browser creates a signing key, then signs you in with LoginRadius using authorization
          code and PKCE. The access token comes back bound to that key.
        </p>
        <ol>
          <li>Generate a P-256 key and send its thumbprint as dpop_jkt.</li>
          <li>Sign in at LoginRadius. The code exchange includes a DPoP proof.</li>
          <li>After login, compare that thumbprint with cnf.jkt on the access token.</li>
        </ol>
      </Card>
      <Card title="This client">
        <dl>
          <div>
            <dt>Issuer</dt>
            <dd>{issuer || 'Not set'}</dd>
          </div>
          <div>
            <dt>Client id</dt>
            <dd>{clientId || 'Not set'}</dd>
          </div>
          <div>
            <dt>Redirect URI</dt>
            <dd>{redirectUri}</dd>
          </div>
          <div>
            <dt>Discovery</dt>
            <dd>
              {discovery.status === 'loading' && 'Reading discovery…'}
              {discovery.status === 'skipped' && 'Waiting for issuer and client id.'}
              {discovery.status === 'error' && discovery.message}
              {discovery.status === 'ready' && discovery.discovery.issuer}
            </dd>
          </div>
          {discovery.status === 'ready' && (
            <div>
              <dt>DPoP signing algorithms</dt>
              <dd>{algs.length ? algs.join(', ') : 'Not advertised'}</dd>
            </div>
          )}
        </dl>
        {problems.length > 0 && (
          <ul className="problems">
            {problems.map((problem) => (
              <li key={problem}>{problem}</li>
            ))}
          </ul>
        )}
        {discovery.status === 'ready' && !es256 && (
          <p className="banner bad">
            Discovery did not advertise ES256 in dpop_signing_alg_values_supported. Turn on DPoP for
            this app.
          </p>
        )}
        {actionError && <p className="banner bad">{actionError}</p>}
        <div className="button-row">
          <button type="button" disabled={!ready} onClick={onSignIn}>
            {busy ? 'Redirecting…' : 'Sign in'}
          </button>
          {(discovery.status === 'error' || (discovery.status === 'ready' && !es256)) && (
            <button type="button" className="secondary" onClick={onRetryDiscovery} disabled={busy}>
              Check discovery again
            </button>
          )}
        </div>
      </Card>
    </Shell>
  )
}

export function SignIn() {
  const config = appConfig()
  const [discovery, setDiscovery] = useState<DiscoveryState>(
    config.problems.length ? { status: 'skipped' } : { status: 'loading' },
  )
  const [busy, setBusy] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    if (config.problems.length) return
    let cancel = false
    setDiscovery({ status: 'loading' })
    loadDiscovery(attempt > 0)
      .then((next) => {
        if (!cancel) setDiscovery({ status: 'ready', discovery: next })
      })
      .catch((error: unknown) => {
        if (!cancel) {
          setDiscovery({
            status: 'error',
            message: error instanceof Error ? error.message : 'Discovery failed.',
          })
        }
      })
    return () => {
      cancel = true
    }
  }, [attempt, config.problems.length])

  async function onSignIn() {
    setBusy(true)
    setActionError(null)
    try {
      const current = discovery.status === 'ready' ? discovery.discovery : await loadDiscovery()
      let key = await loadKey()
      if (!key) {
        key = await generateDpopKey()
        await saveKey(key)
      }
      const pkce = await createPkce()
      const state = randomId(16)
      const nonce = randomId(16)
      saveTransaction({
        state,
        nonce,
        codeVerifier: pkce.verifier,
        jkt: key.jkt,
        redirectUri: config.redirectUri,
      })
      const url = new URL(current.authorization_endpoint)
      url.searchParams.set('client_id', config.clientId)
      url.searchParams.set('redirect_uri', config.redirectUri)
      url.searchParams.set('response_type', 'code')
      url.searchParams.set('scope', config.scopes)
      url.searchParams.set('state', state)
      url.searchParams.set('nonce', nonce)
      url.searchParams.set('code_challenge', pkce.challenge)
      url.searchParams.set('code_challenge_method', 'S256')
      url.searchParams.set('dpop_jkt', key.jkt)
      window.location.assign(url.toString())
    } catch (error) {
      setBusy(false)
      setActionError(error instanceof Error ? error.message : 'Sign-in failed.')
    }
  }

  return (
    <SignInView
      issuer={config.issuer}
      clientId={config.clientId}
      redirectUri={config.redirectUri}
      problems={config.problems}
      discovery={discovery}
      busy={busy}
      actionError={actionError}
      onSignIn={() => void onSignIn()}
      onRetryDiscovery={() => setAttempt((value) => value + 1)}
    />
  )
}
