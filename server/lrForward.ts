import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Plugin } from 'vite'

export class TargetError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'TargetError'
  }
}

/** Only the configured issuer origin may be called through the dev proxy. */
export function assertAllowedTarget(target: string, issuer: string): URL {
  let allowed: URL
  try {
    allowed = new URL(issuer)
  } catch {
    throw new TargetError('VITE_LR_ISSUER is not a valid URL.')
  }
  let url: URL
  try {
    url = new URL(target)
  } catch {
    throw new TargetError('X-LR-Target is not a valid URL.')
  }
  if (url.origin !== allowed.origin) {
    throw new TargetError('The target origin does not match VITE_LR_ISSUER.')
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new TargetError('The target must be http or https.')
  }
  return url
}

async function readBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = []
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk))
  }
  return Buffer.concat(chunks)
}

function headerValue(value: string | string[] | undefined): string | undefined {
  if (typeof value === 'string') return value
  return undefined
}

/**
 * Headers for the upstream call. X-Forwarded-Proto is the target scheme.
 * LoginRadius rebuilds the DPoP htu from that header. fasthttp otherwise
 * reports the scheme as http, and the https proof is rejected.
 */
export function upstreamHeaders(req: IncomingMessage, target: URL): Headers {
  const headers = new Headers()
  const contentType = headerValue(req.headers['content-type'])
  const accept = headerValue(req.headers['accept'])
  const dpop = headerValue(req.headers['dpop'])
  const authorization = headerValue(req.headers['authorization'])
  if (contentType) headers.set('content-type', contentType)
  if (accept) headers.set('accept', accept)
  if (dpop) headers.set('dpop', dpop)
  if (authorization) headers.set('authorization', authorization)
  headers.set('x-forwarded-proto', target.protocol === 'http:' ? 'http' : 'https')
  return headers
}

async function handleForward(req: IncomingMessage, res: ServerResponse, issuer: string) {
  try {
    const target = headerValue(req.headers['x-lr-target'])
    if (!target) {
      throw new TargetError('Missing X-LR-Target.')
    }
    const url = assertAllowedTarget(target, issuer)
    const method = req.method ?? 'GET'
    const body = await readBody(req)
    const headers = upstreamHeaders(req, url)

    const upstream = await fetch(url, {
      method,
      headers,
      body: method === 'GET' || method === 'HEAD' ? undefined : body,
      redirect: 'manual',
    })

    res.statusCode = upstream.status
    for (const name of ['content-type', 'dpop-nonce', 'www-authenticate', 'cache-control']) {
      const value = upstream.headers.get(name)
      if (value) res.setHeader(name, value)
    }
    res.end(Buffer.from(await upstream.arrayBuffer()))
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Forward failed.'
    const status = error instanceof TargetError ? 400 : 502
    res.statusCode = status
    res.setHeader('content-type', 'application/json')
    res.end(JSON.stringify({ error: 'proxy_error', error_description: message }))
  }
}

export function lrForwardPlugin(issuer: string): Plugin {
  const attach = (middlewares: { use: (path: string, handler: (req: IncomingMessage, res: ServerResponse) => void) => void }) => {
    middlewares.use('/lr/forward', (req, res) => {
      void handleForward(req, res, issuer.trim())
    })
  }
  return {
    name: 'lr-forward',
    configureServer(server) {
      attach(server.middlewares)
    },
    configurePreviewServer(server) {
      attach(server.middlewares)
    },
  }
}
