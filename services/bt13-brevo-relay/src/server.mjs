import http from 'node:http'
import { pathToFileURL } from 'node:url'
import { createRelay, MAX_BODY_BYTES } from './relay.mjs'

const REQUEST_TIMEOUT_MS = 15_000

async function readBody(request, maxBytes = MAX_BODY_BYTES) {
  let totalBytes = 0
  let tooLarge = false
  const chunks = []

  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
    totalBytes += buffer.length
    if (totalBytes <= maxBytes) chunks.push(buffer)
    else tooLarge = true
  }

  return { tooLarge, body: tooLarge ? Buffer.alloc(0) : Buffer.concat(chunks) }
}

function writeJson(response, status, body) {
  if (response.headersSent) return
  response.statusCode = status
  response.setHeader('content-type', 'application/json; charset=utf-8')
  response.setHeader('cache-control', 'no-store')
  response.end(JSON.stringify(body))
}

export function createRelayServer({ env = process.env, relay = createRelay({ env }), maxBodyBytes = MAX_BODY_BYTES } = {}) {
  const server = http.createServer(async (request, response) => {
    try {
      const declaredLengthText = request.headers['content-length']
      const declaredLength = declaredLengthText ? Number(declaredLengthText) : 0
      if (Number.isFinite(declaredLength) && declaredLength > maxBodyBytes) {
        request.resume()
        writeJson(response, 413, { code: 'body_too_large' })
        return
      }

      const { tooLarge, body } = await readBody(request, maxBodyBytes)
      if (tooLarge) {
        writeJson(response, 413, { code: 'body_too_large' })
        return
      }

      const headers = new Headers()
      for (const [key, value] of Object.entries(request.headers)) {
        if (Array.isArray(value)) headers.set(key, value.join(', '))
        else if (value != null) headers.set(key, value)
      }
      const req = new Request(`http://${request.headers.host || 'localhost'}${request.url}`, {
        method: request.method,
        headers,
        body: request.method === 'GET' || request.method === 'HEAD' ? undefined : body,
      })
      const result = await relay.handle(req)
      response.statusCode = result.status
      for (const [key, value] of result.headers) response.setHeader(key, value)
      response.end(Buffer.from(await result.arrayBuffer()))
    } catch {
      writeJson(response, 500, { code: 'internal_error' })
    }
  })

  server.requestTimeout = REQUEST_TIMEOUT_MS
  server.headersTimeout = REQUEST_TIMEOUT_MS + 5_000
  server.keepAliveTimeout = 5_000
  return server
}

export { MAX_BODY_BYTES, REQUEST_TIMEOUT_MS, readBody }

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href
if (isMain) {
  const server = createRelayServer()
  const port = Number(process.env.PORT || 10000)
  server.listen(port, '0.0.0.0', () => {
    process.stdout.write(`bt13-brevo-relay listening on ${port}\n`)
  })
}
