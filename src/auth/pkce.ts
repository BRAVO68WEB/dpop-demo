import { base64url, randomId } from './base64url'

export type PkcePair = {
  verifier: string
  challenge: string
}

/** RFC 7636 S256. The verifier is 43 characters from 32 random bytes. */
export async function createPkce(): Promise<PkcePair> {
  const verifier = randomId(32)
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return { verifier, challenge: base64url(new Uint8Array(digest)) }
}
