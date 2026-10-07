import * as jose from 'jose'
import { base64url, randomId } from './base64url'

export type EcPublicJwk = {
  kty: 'EC'
  crv: 'P-256'
  x: string
  y: string
}

export type DpopKey = {
  publicJwk: EcPublicJwk
  jkt: string
  privateKey: CryptoKey
  publicKey: CryptoKey
}

export function ecPublicJwk(jwk: jose.JWK): EcPublicJwk {
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) {
    throw new Error('DPoP key must be an EC P-256 public JWK.')
  }
  return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }
}

/** htu is the scheme, host, port, and path. Query and fragment are excluded. */
export function proofHtu(endpoint: string): string {
  const url = new URL(endpoint)
  return `${url.origin}${url.pathname}`
}

export async function accessTokenHash(accessToken: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(accessToken))
  return base64url(new Uint8Array(digest))
}

export async function generateDpopKey(): Promise<DpopKey> {
  const algorithm = { name: 'ECDSA', namedCurve: 'P-256' } as const
  let pair = await crypto.subtle.generateKey(algorithm, false, ['sign', 'verify'])
  let exported: jose.JWK
  try {
    exported = await crypto.subtle.exportKey('jwk', pair.publicKey)
  } catch {
    const extractable = await crypto.subtle.generateKey(algorithm, true, ['sign', 'verify'])
    const pkcs8 = await crypto.subtle.exportKey('pkcs8', extractable.privateKey)
    exported = await crypto.subtle.exportKey('jwk', extractable.publicKey)
    const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, algorithm, false, ['sign'])
    const publicKey = await crypto.subtle.importKey('jwk', exported, algorithm, true, ['verify'])
    pair = { privateKey, publicKey }
  }
  const publicJwk = ecPublicJwk(exported)
  const jkt = await jose.calculateJwkThumbprint(publicJwk)
  return { publicJwk, jkt, privateKey: pair.privateKey, publicKey: pair.publicKey }
}

export async function createDpopProof(input: {
  privateKey: CryptoKey
  publicJwk: EcPublicJwk
  htm: string
  htu: string
  accessToken?: string
  nonce?: string
  iat?: number
  jti?: string
}): Promise<string> {
  const claims: jose.JWTPayload = {
    jti: input.jti ?? randomId(16),
    htm: input.htm.toUpperCase(),
    htu: proofHtu(input.htu),
    iat: input.iat ?? Math.floor(Date.now() / 1000),
  }
  if (input.accessToken) claims.ath = await accessTokenHash(input.accessToken)
  if (input.nonce) claims.nonce = input.nonce

  return new jose.SignJWT(claims)
    .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: input.publicJwk })
    .sign(input.privateKey)
}

export function decodeJwt(token: string): { header: jose.ProtectedHeaderParameters; payload: jose.JWTPayload } | null {
  if (token.split('.').length !== 3) return null
  try {
    return {
      header: jose.decodeProtectedHeader(token),
      payload: jose.decodeJwt(token),
    }
  } catch {
    return null
  }
}

export function readConfirmationJkt(payload: jose.JWTPayload): string | null {
  const record = payload as Record<string, unknown>
  const cnf = record.cnf
  if (!cnf || typeof cnf !== 'object' || !('jkt' in cnf)) return null
  const jkt = (cnf as { jkt?: unknown }).jkt
  return typeof jkt === 'string' ? jkt : null
}
