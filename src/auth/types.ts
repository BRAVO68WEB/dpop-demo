export type Discovery = {
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  userinfo_endpoint: string
  jwks_uri: string
  dpop_signing_alg_values_supported?: string[]
}

export type TokenResponse = {
  access_token: string
  token_type: string
  expires_in?: number
  refresh_token?: string
  id_token?: string
  scope?: string
}

export type EndpointResult = {
  status: number
  wwwAuthenticate: string | null
  body: unknown
}
