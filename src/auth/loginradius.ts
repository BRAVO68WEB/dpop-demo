import * as jose from 'jose'
import { appConfig } from '../config'
import { createDpopProof, decodeJwt, type DpopKey } from './dpop'
import { forward } from './forward'
import { withDpopNonceRetry, type Attempt } from './nonceRetry'
import type { Discovery, EndpointResult, TokenResponse } from './types'

export type { Discovery, EndpointResult, TokenResponse }

const REQUIRED = [
  'issuer',
  'authorization_endpoint',
  'token_endpoint',
  'userinfo_endpoint',
  'jwks_uri',
] as const

let discoveryPromise: Promise<Discovery> | null = null
const exchanges = new Map<string, Promise<TokenResponse>>()

export class OAuthHttpError extends Error {
  readonly status: number
  readonly wwwAuthenticate: string | null
  readonly body: unknown

  constructor(attempt: Attempt) {
    super(describe(attempt))
    this.name = 'OAuthHttpError'
    this.status = attempt.status
    this.wwwAuthenticate = attempt.headers.get('WWW-Authenticate')
    this.body = attempt.body
  }
}

function describe(attempt: Attempt): string {
  if (attempt.body && typeof attempt.body === 'object') {
    const record = attempt.body as { error_description?: unknown; error?: unknown }
    if (typeof record.error_description === 'string') return record.error_description
    if (typeof record.error === 'string') return record.error
  }
  return `Request failed (${attempt.status}).`
}

async function readAttempt(response: Response): Promise<Attempt> {
  const text = await response.text()
  let body: unknown = text
  if (text) {
    try {
      body = JSON.parse(text) as unknown
    } catch {
      body = text
    }
  }
  return { status: response.status, headers: response.headers, body }
}

function asDiscovery(value: unknown): Discovery {
  if (!value || typeof value !== 'object') {
    throw new Error('Discovery response was not a JSON object.')
  }
  const record = value as Record<string, unknown>
  for (const field of REQUIRED) {
    if (typeof record[field] !== 'string' || !record[field]) {
      throw new Error(`Discovery did not include ${field}.`)
    }
  }
  const algs = record.dpop_signing_alg_values_supported
  return {
    issuer: record.issuer as string,
    authorization_endpoint: record.authorization_endpoint as string,
    token_endpoint: record.token_endpoint as string,
    userinfo_endpoint: record.userinfo_endpoint as string,
    jwks_uri: record.jwks_uri as string,
    dpop_signing_alg_values_supported: Array.isArray(algs)
      ? algs.filter((item): item is string => typeof item === 'string')
      : undefined,
  }
}

export function loadDiscovery(force = false): Promise<Discovery> {
  if (!discoveryPromise || force) {
    discoveryPromise = fetchDiscovery().catch((error: unknown) => {
      discoveryPromise = null
      throw error
    })
  }
  return discoveryPromise
}

async function fetchDiscovery(): Promise<Discovery> {
  const { issuer } = appConfig()
  const response = await forward(`${issuer}/.well-known/openid-configuration`, {
    headers: { accept: 'application/json' },
  })
  const attempt = await readAttempt(response)
  if (attempt.status < 200 || attempt.status >= 300) throw new OAuthHttpError(attempt)
  return asDiscovery(attempt.body)
}

function tokenResponse(attempt: Attempt): TokenResponse {
  if (attempt.status < 200 || attempt.status >= 300) throw new OAuthHttpError(attempt)
  if (!attempt.body || typeof attempt.body !== 'object') {
    throw new Error('Token response was not JSON.')
  }
  const body = attempt.body as Record<string, unknown>
  if (typeof body.access_token !== 'string' || typeof body.token_type !== 'string') {
    throw new Error('Token response did not include an access token.')
  }
  return {
    access_token: body.access_token,
    token_type: body.token_type,
    expires_in: typeof body.expires_in === 'number' ? body.expires_in : undefined,
    refresh_token: typeof body.refresh_token === 'string' ? body.refresh_token : undefined,
    id_token: typeof body.id_token === 'string' ? body.id_token : undefined,
    scope: typeof body.scope === 'string' ? body.scope : undefined,
  }
}

async function postToken(
  tokenEndpoint: string,
  form: URLSearchParams,
  key: DpopKey,
  accessToken?: string,
): Promise<TokenResponse> {
  const attempt = await withDpopNonceRetry(async (nonce) => {
    const proof = await createDpopProof({
      privateKey: key.privateKey,
      publicJwk: key.publicJwk,
      htm: 'POST',
      htu: tokenEndpoint,
      accessToken,
      nonce,
    })
    const response = await forward(tokenEndpoint, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        accept: 'application/json',
        dpop: proof,
      },
      body: form.toString(),
    })
    return readAttempt(response)
  })
  return tokenResponse(attempt)
}

export function exchangeCode(input: {
  tokenEndpoint: string
  clientId: string
  redirectUri: string
  code: string
  codeVerifier: string
  key: DpopKey
}): Promise<TokenResponse> {
  const existing = exchanges.get(input.code)
  if (existing) return existing
  const form = new URLSearchParams({
    grant_type: 'authorization_code',
    code: input.code,
    redirect_uri: input.redirectUri,
    client_id: input.clientId,
    code_verifier: input.codeVerifier,
  })
  const pending = postToken(input.tokenEndpoint, form, input.key).catch((error: unknown) => {
    exchanges.delete(input.code)
    throw error
  })
  exchanges.set(input.code, pending)
  return pending
}

export function refreshTokens(input: {
  tokenEndpoint: string
  clientId: string
  refreshToken: string
  key: DpopKey
}): Promise<TokenResponse> {
  const form = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: input.refreshToken,
    client_id: input.clientId,
  })
  return postToken(input.tokenEndpoint, form, input.key)
}

export async function fetchJwks(jwksUri: string): Promise<jose.JSONWebKeySet> {
  const response = await forward(jwksUri, { headers: { accept: 'application/json' } })
  const attempt = await readAttempt(response)
  if (attempt.status < 200 || attempt.status >= 300) throw new OAuthHttpError(attempt)
  if (!attempt.body || typeof attempt.body !== 'object' || !('keys' in attempt.body)) {
    throw new Error('JWKS response did not include keys.')
  }
  return attempt.body as jose.JSONWebKeySet
}

function presentBody(text: string): unknown {
  const trimmed = text.trim()
  if (!trimmed) return null
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      return JSON.parse(trimmed) as unknown
    } catch {
      return trimmed
    }
  }
  const decoded = decodeJwt(trimmed)
  return decoded ? { jwt: decoded.payload } : trimmed
}

export function supportsEs256(discovery: Discovery): boolean {
  return (discovery.dpop_signing_alg_values_supported ?? []).includes('ES256')
}

export async function callUserInfo(input: {
  userinfoEndpoint: string
  accessToken: string
  scheme: 'DPoP' | 'Bearer'
  key?: DpopKey
}): Promise<EndpointResult> {
  const send = async (nonce?: string): Promise<Attempt> => {
    const headers = new Headers({ accept: 'application/json' })
    if (input.scheme === 'DPoP') {
      if (!input.key) throw new Error('A DPoP userinfo call needs the browser key.')
      const proof = await createDpopProof({
        privateKey: input.key.privateKey,
        publicJwk: input.key.publicJwk,
        htm: 'GET',
        htu: input.userinfoEndpoint,
        accessToken: input.accessToken,
        nonce,
      })
      headers.set('authorization', `DPoP ${input.accessToken}`)
      headers.set('dpop', proof)
    } else {
      headers.set('authorization', `Bearer ${input.accessToken}`)
    }
    const response = await forward(input.userinfoEndpoint, { headers })
    const text = await response.text()
    return { status: response.status, headers: response.headers, body: presentBody(text) }
  }

  const attempt = input.scheme === 'DPoP' ? await withDpopNonceRetry(send) : await send()
  return {
    status: attempt.status,
    wwwAuthenticate: attempt.headers.get('WWW-Authenticate'),
    body: attempt.body,
  }
}

export function issuersMatch(left: string, right: string): boolean {
  return left.replace(/\/$/, '') === right.replace(/\/$/, '')
}

export function audienceIncludes(audience: unknown, clientId: string): boolean {
  if (typeof audience === 'string') return audience === clientId
  return Array.isArray(audience) && audience.some((item) => item === clientId)
}
