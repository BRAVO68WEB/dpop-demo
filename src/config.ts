export type AppConfig = {
  issuer: string
  clientId: string
  redirectUri: string
  scopes: string
  problems: string[]
}

export function appConfig(): AppConfig {
  const issuer = (import.meta.env.VITE_LR_ISSUER ?? '').trim().replace(/\/$/, '')
  const clientId = (import.meta.env.VITE_LR_CLIENT_ID ?? '').trim()
  const configuredRedirect = (import.meta.env.VITE_LR_REDIRECT_URI ?? '').trim()
  const redirectUri =
    configuredRedirect ||
    (typeof location === 'undefined' ? 'http://localhost:5173/callback' : `${location.origin}/callback`)
  const scopes = (import.meta.env.VITE_LR_SCOPES ?? '').trim() || 'openid profile email'
  const problems: string[] = []

  if (!issuer) problems.push('Set VITE_LR_ISSUER.')
  else {
    try {
      const url = new URL(issuer)
      if (url.protocol !== 'https:' && url.protocol !== 'http:') {
        problems.push('VITE_LR_ISSUER must be an http or https URL.')
      }
    } catch {
      problems.push('VITE_LR_ISSUER must be an absolute URL.')
    }
  }
  if (!clientId) problems.push('Set VITE_LR_CLIENT_ID.')

  return { issuer, clientId, redirectUri, scopes, problems }
}
