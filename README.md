# LoginRadius DPoP demo

This app signs a user in with LoginRadius OpenID Connect using
authorization code and PKCE, then sender-constrains the tokens with
DPoP (RFC 9449). After login it shows the key in this browser and the
key LoginRadius attached to the access token.

The private key is generated with WebCrypto and is non-extractable. It
is not sent to LoginRadius. Each proof is a short-lived `dpop+jwt`
signed by that key.

## What you need

You need a LoginRadius tenant with DPoP turned on, and an OIDC app that
can act as a public client.

- Turn on the tenant feature `ENABLE_DPOP`.
- Use an OIDC app of type SPA, with PKCE enforced and no client secret.
- Set `DPoP.Required` on that app. `NonceRequired` can be on or off.
  The app retries once when LoginRadius returns `use_dpop_nonce`.
- Register the redirect URI `http://localhost:5173/callback`.
- Allow the scopes `openid`, `profile`, and `email`.

Discovery must advertise `ES256` in
`dpop_signing_alg_values_supported`. The app reads
`authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, and
`jwks_uri` from discovery. It does not hardcode those paths.

## Configure the app

Copy the sample environment file and fill in the issuer and client id.

```bash
cp .env.example .env.local
```

`VITE_LR_ISSUER` is the issuer URL for the OIDC app, without a trailing
slash. A hosted app looks like this:

```text
https://your-app.hub.loginradius.com/service/oidc/YourApp
```

`VITE_LR_CLIENT_ID` is the public client id. Do not put a client secret
in this app.

`VITE_LR_REDIRECT_URI` must match the registered redirect URI exactly.

## Run the demo

Install dependencies, then start the dev server.

```bash
npm install
npm test
npm run dev
```

Open `http://localhost:5173`. Restart the dev server after you change
`.env.local`. The page and the proxy both read the issuer at startup.
**Sign in** stays disabled until discovery loads and advertises ES256.

1. Choose **Sign in**. The browser stores a P-256 key, then redirects
   to LoginRadius with `code_challenge` and `dpop_jkt`.
2. Finish login on the LoginRadius page.
3. The app exchanges the code at the token endpoint. The `DPoP` header
   is a proof for that `POST`. There is no `ath` claim on this call.
4. The session page lists the browser key, `cnf.jkt` on the access
   token, the refresh binding, and the LoginRadius signing key (`kid`)
   from the app JWKS.

From the session page you can refresh the tokens, call userinfo with a
new proof (`Authorization: DPoP` plus `ath`), and call userinfo with
the same token as Bearer. LoginRadius must reject the Bearer call for
a DPoP-bound token.

## How the requests are made

The dev server proxies token, userinfo, JWKS, and discovery calls
through `/lr/forward`. The proxy only forwards to the origin of
`VITE_LR_ISSUER`.

The proof's `htu` claim is the LoginRadius URL, not
`http://localhost`. The proxy exists so the page can read the
`DPoP-Nonce` response header. Browsers hide that header on a
cross-origin response unless the authorization server exposes it.

The proxy also sends `X-Forwarded-Proto` set to the scheme of that
LoginRadius URL. The API rebuilds `htu` from this header. Without it,
an origin-form request is treated as `http`, and an `https` proof is
rejected.

Authorize is a full-page redirect. The proxy does not see the
password.

## Storage

The CryptoKey lives in IndexedDB. The PKCE verifier and the token
response live in `sessionStorage` so a reload of the session page can
still show them.

<!-- prettier-ignore -->
> [!NOTE]
> `sessionStorage` is for this demo. A production client keeps tokens
> in memory and still keeps the private key non-extractable.

**Sign out** deletes the key, the verifier, and the tokens.

## Next steps

Run `npm test` after a change to the proof, PKCE, or nonce retry.
`npm run build` typechecks the app and writes `dist/`. A live login
still needs the tenant values in `.env.local`.
