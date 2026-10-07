import type { EcPublicJwk } from '../auth/dpop'
import type { EndpointResult } from '../auth/types'
import { Card, Shell } from './Shell'

export type CallState =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'done'; result: EndpointResult }
  | { status: 'error'; message: string }

export function SessionView({
  profileTitle,
  profileLines,
  publicJwk,
  jkt,
  tokenType,
  accessJkt,
  accessIsJwt,
  accessPayload,
  accessSignature,
  rawAccessToken,
  idSignature,
  idPayload,
  signingLines,
  refreshDetail,
  canRefresh,
  refreshBusy,
  refreshError,
  dpopCall,
  bearerCall,
  onSignOut,
  onRefresh,
  onDpopUserinfo,
  onBearerUserinfo,
}: {
  profileTitle: string
  profileLines: { label: string; value: string }[]
  publicJwk: EcPublicJwk
  jkt: string
  tokenType: string
  accessJkt: string | null
  accessIsJwt: boolean
  accessPayload: Record<string, unknown> | null
  accessSignature: string
  rawAccessToken: string
  idSignature: string
  idPayload: Record<string, unknown> | null
  signingLines: { label: string; value: string }[]
  refreshDetail: string
  canRefresh: boolean
  refreshBusy: boolean
  refreshError: string | null
  dpopCall: CallState
  bearerCall: CallState
  onSignOut: () => void
  onRefresh: () => void
  onDpopUserinfo: () => void
  onBearerUserinfo: () => void
}) {
  const typeOk = tokenType.toLowerCase() === 'dpop'
  const bound = accessIsJwt && accessJkt !== null
  const matches = bound && accessJkt === jkt

  return (
    <Shell
      action={
        <button type="button" className="secondary" onClick={onSignOut}>
          Sign out
        </button>
      }
    >
      <Card title={profileTitle} heading="h1">
        <p>The ID token identifies you. It is not bound to the DPoP key.</p>
        <Lines lines={profileLines} />
        <p className="muted">{idSignature}</p>
        {idPayload && (
          <details>
            <summary>ID token payload</summary>
            <pre>{JSON.stringify(idPayload, null, 2)}</pre>
          </details>
        )}
      </Card>

      <Card title="DPoP key in this browser">
        <p>The private key is non-extractable and stays in this browser.</p>
        <Lines
          lines={[
            { label: 'kty', value: publicJwk.kty },
            { label: 'crv', value: publicJwk.crv },
            { label: 'x', value: publicJwk.x },
            { label: 'y', value: publicJwk.y },
            { label: 'alg', value: 'ES256' },
            { label: 'Thumbprint (jkt)', value: jkt },
          ]}
        />
      </Card>

      <Card title="Key attached to the access token">
        <p className={typeOk ? 'banner ok' : 'banner bad'}>
          {typeOk
            ? `token_type is ${tokenType}.`
            : `token_type is ${tokenType || 'missing'}. A bound token uses DPoP.`}
        </p>
        {!accessIsJwt && (
          <p className="banner bad">This access token is not a JWT, so there is no cnf.jkt to show.</p>
        )}
        {accessIsJwt && !accessJkt && (
          <p className="banner bad">This access token has no cnf.jkt. It is not DPoP-bound.</p>
        )}
        {bound && (
          <>
            <Lines
              lines={[
                { label: 'cnf.jkt', value: accessJkt },
                { label: 'Browser jkt', value: jkt },
              ]}
            />
            <p className={matches ? 'banner ok' : 'banner bad'}>
              {matches ? 'Match. The access token is attached to this browser key.' : 'Does not match the key in this browser.'}
            </p>
          </>
        )}
        <p className="muted">{accessSignature}</p>
        {accessPayload && (
          <details>
            <summary>Access token payload</summary>
            <pre>{JSON.stringify(accessPayload, null, 2)}</pre>
          </details>
        )}
        <details>
          <summary>Raw access token</summary>
          <pre>{rawAccessToken}</pre>
        </details>
      </Card>

      <Card title="Refresh token">
        <p>{refreshDetail}</p>
        {refreshError && <p className="banner bad">{refreshError}</p>}
        <button type="button" onClick={onRefresh} disabled={!canRefresh || refreshBusy}>
          {refreshBusy ? 'Refreshing…' : 'Refresh'}
        </button>
      </Card>

      <Card title="LoginRadius signing key">
        <p>This is the key that signed the tokens. It is separate from the DPoP key.</p>
        <Lines lines={signingLines} />
      </Card>

      <Card title="Userinfo">
        <p>Userinfo is the protected resource. One call sends a fresh proof. The other sends the same token as Bearer.</p>
        <div className="actions">
          <button type="button" onClick={onDpopUserinfo} disabled={dpopCall.status === 'loading'}>
            {dpopCall.status === 'loading' ? 'Calling userinfo…' : 'Call userinfo with DPoP'}
          </button>
          <button type="button" className="secondary" onClick={onBearerUserinfo} disabled={bearerCall.status === 'loading'}>
            {bearerCall.status === 'loading' ? 'Calling userinfo…' : 'Call userinfo as Bearer'}
          </button>
        </div>
        <CallReport title="DPoP call" state={dpopCall} interpret={interpretDpop} />
        <CallReport title="Bearer call" state={bearerCall} interpret={(result) => interpretBearer(result, typeOk)} />
      </Card>

      <p className="muted">
        Tokens in this demo stay in sessionStorage so a reload can show them. Sign out deletes them and the key.
      </p>
    </Shell>
  )
}

function interpretDpop(result: EndpointResult): { tone: 'ok' | 'bad'; text: string } {
  if (result.status >= 200 && result.status < 300) {
    return { tone: 'ok', text: `Userinfo returned a profile (HTTP ${result.status}).` }
  }
  return { tone: 'bad', text: `Userinfo rejected the DPoP call (HTTP ${result.status}).` }
}

function interpretBearer(result: EndpointResult, dpopToken: boolean): { tone: 'ok' | 'bad'; text: string } {
  if (result.status === 401) {
    const why = dpopToken ? ' A DPoP-bound token was not accepted as Bearer.' : ''
    return { tone: 'ok', text: `Rejected (HTTP 401).${why}` }
  }
  if (result.status >= 200 && result.status < 300) {
    return { tone: 'bad', text: `Accepted (HTTP ${result.status}). The resource treated this DPoP-bound token as Bearer.` }
  }
  return { tone: 'bad', text: `Bearer call returned HTTP ${result.status}.` }
}

function CallReport({
  title,
  state,
  interpret,
}: {
  title: string
  state: CallState
  interpret: (result: EndpointResult) => { tone: 'ok' | 'bad'; text: string }
}) {
  return (
    <div>
      <h3>{title}</h3>
      {state.status === 'idle' && <p className="muted">Not called yet.</p>}
      {state.status === 'loading' && <p className="muted">Calling userinfo…</p>}
      {state.status === 'error' && <p className="banner bad">{state.message}</p>}
      {state.status === 'done' && (
        <>
          <p className={`banner ${interpret(state.result).tone}`}>{interpret(state.result).text}</p>
          {state.result.wwwAuthenticate && <p className="mono">{state.result.wwwAuthenticate}</p>}
          <details>
            <summary>Response body</summary>
            <pre>{JSON.stringify(state.result.body, null, 2)}</pre>
          </details>
        </>
      )}
    </div>
  )
}

function Lines({ lines }: { lines: { label: string; value: string }[] }) {
  return (
    <dl>
      {lines.map((line) => (
        <div key={line.label}>
          <dt>{line.label}</dt>
          <dd>{line.value}</dd>
        </div>
      ))}
    </dl>
  )
}

export function idClaims(payload: Record<string, unknown>): { label: string; value: string }[] {
  return ['sub', 'name', 'email', 'nonce']
    .filter((name) => typeof payload[name] === 'string' && payload[name])
    .map((name) => ({ label: name, value: String(payload[name]) }))
}

export function profileTitle(payload: Record<string, unknown>): string {
  for (const name of ['name', 'email', 'sub']) {
    if (typeof payload[name] === 'string' && payload[name]) return String(payload[name])
  }
  return 'Signed in'
}
