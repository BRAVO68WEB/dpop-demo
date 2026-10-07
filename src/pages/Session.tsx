import * as jose from 'jose'
import { useEffect, useRef, useState, type RefObject } from 'react'
import { Navigate } from 'react-router-dom'
import { appConfig } from '../config'
import { decodeJwt, readConfirmationJkt, type DpopKey } from '../auth/dpop'
import {
  callUserInfo,
  fetchJwks,
  issuersMatch,
  loadDiscovery,
  refreshTokens,
} from '../auth/loginradius'
import { clearSession, loadKey, loadTokens, saveTokens } from '../auth/storage'
import type { Discovery, EndpointResult, TokenResponse } from '../auth/types'
import { Card, Shell } from './Shell'
import { idClaims, profileTitle, SessionView, type CallState } from './SessionView'

type Ready = {
  key: DpopKey
  tokens: TokenResponse
  discovery: Discovery
  jwks: jose.JSONWebKeySet | null
  jwksError: string | null
  accessSignature: string
  idSignature: string
}

export function Session() {
  const [phase, setPhase] = useState<'loading' | 'empty' | 'error' | 'ready'>('loading')
  const [loadError, setLoadError] = useState<string | null>(null)
  const [ready, setReady] = useState<Ready | null>(null)
  const [refreshBusy, setRefreshBusy] = useState(false)
  const [refreshError, setRefreshError] = useState<string | null>(null)
  const [refreshedJkt, setRefreshedJkt] = useState<string | null>(null)
  const [dpopCall, setDpopCall] = useState<CallState>({ status: 'idle' })
  const [bearerCall, setBearerCall] = useState<CallState>({ status: 'idle' })
  const readyRef = useRef<Ready | null>(null)

  useEffect(() => {
    let cancel = false
    void (async () => {
      const tokens = loadTokens()
      const key = await loadKey()
      if (!tokens || !key) {
        if (!cancel) setPhase('empty')
        return
      }
      const discovery = await loadDiscovery()
      let jwks: jose.JSONWebKeySet | null = null
      let jwksError: string | null = null
      try {
        jwks = await fetchJwks(discovery.jwks_uri)
      } catch (error) {
        jwksError = error instanceof Error ? error.message : 'JWKS request failed.'
      }
      const accessSignature = await signatureText(tokens.access_token, jwks, discovery.issuer, {
        clockTolerance: 60,
      })
      const idSignature = tokens.id_token
        ? await signatureText(tokens.id_token, jwks, discovery.issuer, {
            audience: appConfig().clientId,
            clockTolerance: 60,
          })
        : 'Token response did not include an ID token.'
      if (cancel) return
      const next = { key, tokens, discovery, jwks, jwksError, accessSignature, idSignature }
      readyRef.current = next
      setReady(next)
      setPhase('ready')
    })().catch((error: unknown) => {
      if (!cancel) {
        setLoadError(error instanceof Error ? error.message : 'Could not open the session.')
        setPhase('error')
      }
    })
    return () => {
      cancel = true
    }
  }, [])

  if (phase === 'empty') return <Navigate to="/" replace />
  if (phase === 'loading') {
    return (
      <Shell>
        <Card title="Opening the session" heading="h1">
          <p>Loading the key and tokens stored in this browser.</p>
        </Card>
      </Shell>
    )
  }
  if (phase === 'error' || !ready) {
    return (
      <Shell>
        <Card title="Session unavailable" heading="h1">
          <p className="banner bad">{loadError ?? 'The session could not be read.'}</p>
          <button type="button" onClick={() => void signOut()}>
            Sign out
          </button>
        </Card>
      </Shell>
    )
  }

  const access = decodeJwt(ready.tokens.access_token)
  const accessJkt = access ? readConfirmationJkt(access.payload) : null
  const id = ready.tokens.id_token ? decodeJwt(ready.tokens.id_token) : null
  const idPayload = id ? (id.payload as Record<string, unknown>) : null
  const signingLines = describeSigning(access?.header.kid, id?.header.kid, ready.jwks, ready.jwksError)

  let refreshDetail =
    'LoginRadius binds the refresh token to this key for a public client. Refresh sends a new proof from the same key.'
  if (!ready.tokens.refresh_token) {
    refreshDetail = 'The token response did not include a refresh token.'
  } else if (refreshedJkt && refreshedJkt === ready.key.jkt) {
    refreshDetail = `Refresh succeeded. The new access token is still attached to ${ready.key.jkt}.`
  } else if (refreshedJkt) {
    refreshDetail = `Refresh returned cnf.jkt ${refreshedJkt}, which does not match this browser.`
  }

  return (
    <SessionView
      profileTitle={idPayload ? profileTitle(idPayload) : 'Signed in'}
      profileLines={idPayload ? idClaims(idPayload) : []}
      publicJwk={ready.key.publicJwk}
      jkt={ready.key.jkt}
      tokenType={ready.tokens.token_type}
      accessJkt={accessJkt}
      accessIsJwt={access !== null}
      accessPayload={access ? (access.payload as Record<string, unknown>) : null}
      accessSignature={ready.accessSignature}
      rawAccessToken={ready.tokens.access_token}
      idSignature={ready.idSignature}
      idPayload={idPayload}
      signingLines={signingLines}
      refreshDetail={refreshDetail}
      canRefresh={Boolean(ready.tokens.refresh_token)}
      refreshBusy={refreshBusy}
      refreshError={refreshError}
      dpopCall={dpopCall}
      bearerCall={bearerCall}
      onSignOut={() => void signOut()}
      onRefresh={() => void refresh(readyRef, setReady, setRefreshBusy, setRefreshError, setRefreshedJkt)}
      onDpopUserinfo={() => void userInfo('DPoP', readyRef, setDpopCall)}
      onBearerUserinfo={() => void userInfo('Bearer', readyRef, setBearerCall)}
    />
  )
}

async function signOut() {
  await clearSession()
  window.location.assign('/')
}

async function signatureText(
  token: string,
  jwks: jose.JSONWebKeySet | null,
  expectedIssuer: string,
  options: jose.JWTVerifyOptions,
): Promise<string> {
  if (!decodeJwt(token)) return 'This token is not a JWT, so its signature was not checked here.'
  if (!jwks) return 'Signature was not checked because the JWKS request failed.'
  try {
    const { payload } = await jose.jwtVerify(token, jose.createLocalJWKSet(jwks), options)
    if (typeof payload.iss !== 'string' || !issuersMatch(payload.iss, expectedIssuer)) {
      return 'Signature verified, but the issuer does not match discovery.'
    }
    return 'Signature verified with the app JWKS.'
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Signature check failed.'
    return `Signature check failed. ${message}`
  }
}

function describeSigning(
  accessKid: string | undefined,
  idKid: string | undefined,
  jwks: jose.JSONWebKeySet | null,
  jwksError: string | null,
): { label: string; value: string }[] {
  const known = new Set((jwks?.keys ?? []).map((key) => key.kid).filter((kid): kid is string => Boolean(kid)))
  const lines = [
    { label: 'Access token kid', value: kidLine(accessKid, known, jwks !== null) },
    { label: 'ID token kid', value: kidLine(idKid, known, jwks !== null) },
  ]
  if (jwksError) lines.push({ label: 'JWKS', value: jwksError })
  else lines.push({ label: 'JWKS kids', value: known.size ? [...known].join(', ') : 'The JWKS did not include kid values.' })
  return lines
}

function kidLine(kid: string | undefined, known: Set<string>, haveJwks: boolean): string {
  if (!kid) return 'The token header did not include kid.'
  if (!haveJwks) return kid
  return known.has(kid) ? `${kid} (published in the JWKS)` : `${kid} (not in the JWKS)`
}

async function refresh(
  readyRef: RefObject<Ready | null>,
  setReady: (ready: Ready) => void,
  setBusy: (busy: boolean) => void,
  setError: (error: string | null) => void,
  setRefreshedJkt: (jkt: string | null) => void,
) {
  const current = readyRef.current
  if (!current?.tokens.refresh_token) return
  setBusy(true)
  setError(null)
  try {
    const fresh = await refreshTokens({
      tokenEndpoint: current.discovery.token_endpoint,
      clientId: appConfig().clientId,
      refreshToken: current.tokens.refresh_token,
      key: current.key,
    })
    const tokens = { ...current.tokens, ...fresh, id_token: fresh.id_token ?? current.tokens.id_token }
    saveTokens(tokens)
    const accessSignature = await signatureText(tokens.access_token, current.jwks, current.discovery.issuer, {
      clockTolerance: 60,
    })
    const next = { ...current, tokens, accessSignature }
    readyRef.current = next
    setReady(next)
    const decoded = decodeJwt(tokens.access_token)
    setRefreshedJkt(decoded ? readConfirmationJkt(decoded.payload) : null)
  } catch (error) {
    setError(error instanceof Error ? error.message : 'Refresh failed.')
  } finally {
    setBusy(false)
  }
}

async function userInfo(
  scheme: 'DPoP' | 'Bearer',
  readyRef: RefObject<Ready | null>,
  setCall: (state: CallState) => void,
) {
  const current = readyRef.current
  if (!current) return
  setCall({ status: 'loading' })
  try {
    const result: EndpointResult = await callUserInfo({
      userinfoEndpoint: current.discovery.userinfo_endpoint,
      accessToken: current.tokens.access_token,
      scheme,
      key: current.key,
    })
    setCall({ status: 'done', result })
  } catch (error) {
    setCall({ status: 'error', message: error instanceof Error ? error.message : 'Userinfo failed.' })
  }
}
