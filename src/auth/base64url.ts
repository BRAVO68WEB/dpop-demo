export function base64url(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
}

export function randomId(byteLength = 16): string {
  return base64url(crypto.getRandomValues(new Uint8Array(byteLength)))
}
