import crypto from 'node:crypto'

const MAX_BODY_BYTES = 16 * 1024
const SIGNATURE_DRIFT_SECONDS = 5 * 60
const REQUEST_TTL_MS = 15 * 60 * 1000
const RATE_LIMIT_WINDOW_MS = 60 * 60 * 1000
const RATE_LIMIT_MAX = 5
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
const REQUEST_ID_PATTERN = /^[A-Za-z0-9._:-]{8,120}$/

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  })
}

function envText(env, key) {
  const value = env?.[key]
  return typeof value === 'string' ? value.trim() : ''
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;')
}

function hmacHex(secret, value) {
  return crypto.createHmac('sha256', secret).update(value).digest('hex')
}

function sha256Hex(value) {
  return crypto.createHash('sha256').update(value).digest('hex')
}

function safeEqualHex(left, right) {
  if (!/^[a-f0-9]{64}$/.test(left) || !/^[a-f0-9]{64}$/.test(right)) return false
  return crypto.timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'))
}

function purge(store, now) {
  for (const [key, record] of store.entries()) {
    if (record.expiresAt <= now) store.delete(key)
  }
}

function verificationHtml(to, code, expiresAt) {
  const safeTo = escapeHtml(to)
  const safeCode = escapeHtml(code)
  const safeExpiry = escapeHtml(expiresAt)
  return `<!doctype html><html><body style="font-family:Arial,sans-serif;color:#18222b;line-height:1.5"><p>BT13 Black Tiger email verification</p><p>We received a request to start your BT13 evaluation.</p><p style="font-size:28px;letter-spacing:6px;font-weight:700">${safeCode}</p><p>This code expires at ${safeExpiry} UTC and can be used once.</p><p>Recipient: ${safeTo}</p><p>If you did not request this, you can ignore this email.</p></body></html>`
}

function validatePayload(payload, currentMs = Date.now()) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return 'body must be a JSON object'
  if (payload.template !== 'trial_verification') return 'template must be trial_verification'
  if (typeof payload.to !== 'string' || !EMAIL_PATTERN.test(payload.to) || payload.to.length > 254) return 'to must be a valid email address'
  if (typeof payload.code !== 'string' || !/^\d{6}$/.test(payload.code)) return 'code must be a six-digit string'
  if (typeof payload.request_id !== 'string' || !REQUEST_ID_PATTERN.test(payload.request_id)) return 'request_id is invalid'
  if (typeof payload.expires_at !== 'string') return 'expires_at must be an ISO timestamp'
  const expiresAtMs = Date.parse(payload.expires_at)
  if (!Number.isFinite(expiresAtMs)) return 'expires_at must be an ISO timestamp'
  if (expiresAtMs <= currentMs || expiresAtMs > currentMs + 15 * 60 * 1000) return 'expires_at must be within the next 15 minutes'
  return null
}

function requestPayload(payload) {
  return {
    sender: { name: 'BT13 Black Tiger', email: payload.senderEmail },
    to: [{ email: payload.to }],
    subject: 'Your BT13 evaluation verification code',
    htmlContent: verificationHtml(payload.to, payload.code, payload.expires_at),
  }
}

function timestampMs(timestampText) {
  if (!/^\d{10,13}$/.test(timestampText)) return null
  const timestamp = Number(timestampText)
  if (!Number.isFinite(timestamp)) return null
  return timestampText.length === 10 ? timestamp * 1000 : timestamp
}

function verifySignature(request, secret, currentMs, signedValue) {
  const timestampText = request.headers.get('x-bt13-timestamp') || ''
  const signature = request.headers.get('x-bt13-signature') || ''
  const parsedMs = timestampMs(timestampText)
  if (parsedMs == null || Math.abs(currentMs - parsedMs) > SIGNATURE_DRIFT_SECONDS * 1000) {
    return { ok: false, response: json({ code: parsedMs == null ? 'invalid_signature' : 'stale_signature' }, 401) }
  }
  const expected = hmacHex(secret, `${timestampText}.${signedValue}`)
  if (!safeEqualHex(expected, signature)) return { ok: false, response: json({ code: 'invalid_signature' }, 401) }
  return { ok: true }
}

export function createRelay({ env = {}, fetchImpl = globalThis.fetch, now = () => Date.now(), requestStore = new Map(), rateStore = new Map() } = {}) {
  async function handle(request) {
    const url = new URL(request.url)
    const secret = envText(env, 'RELAY_SHARED_SECRET')
    const brevoKey = envText(env, 'BREVO_API_KEY')
    const senderEmail = envText(env, 'BREVO_SENDER_EMAIL')
    const currentMs = now()
    purge(requestStore, currentMs)
    purge(rateStore, currentMs)

    if (request.method === 'GET' && url.pathname === '/health') {
      const configured = Boolean(secret && brevoKey && senderEmail)
      return json({ service: 'bt13-brevo-relay', status: configured ? 'ok' : 'not_configured', provider: 'brevo', configured })
    }

    if (request.method === 'GET' && url.pathname === '/v1/provider-status') {
      if (!secret || !brevoKey || !senderEmail) return json({ code: 'relay_not_configured', status: 'not_configured' }, 503)
      const signed = verifySignature(request, secret, currentMs, `${request.method}.${url.pathname}`)
      if (!signed.ok) return signed.response

      let providerResponse
      try {
        providerResponse = await fetchImpl('https://api.brevo.com/v3/senders', {
          method: 'GET',
          headers: { accept: 'application/json', 'api-key': brevoKey },
        })
      } catch {
        return json({ code: 'email_provider_unavailable' }, 502)
      }
      let providerBody = {}
      try { providerBody = await providerResponse.json() } catch { providerBody = {} }
      if (!providerResponse.ok) return json({ code: 'email_provider_unavailable' }, 502)
      const senders = Array.isArray(providerBody.senders) ? providerBody.senders : []
      const senderActive = senders.some((entry) => entry && entry.email === senderEmail && entry.active === true)
      return json({ status: 'ok', sender_active: senderActive }, 200)
    }

    if (request.method !== 'POST' || url.pathname !== '/v1/send-verification') {
      return json({ code: 'not_found' }, 404)
    }
    if (!secret || !brevoKey || !senderEmail) return json({ code: 'relay_not_configured', status: 'not_configured' }, 503)

    const declaredLength = Number(request.headers.get('content-length') || '0')
    if (Number.isFinite(declaredLength) && declaredLength > MAX_BODY_BYTES) return json({ code: 'body_too_large' }, 413)
    const rawBody = await request.text()
    if (Buffer.byteLength(rawBody, 'utf8') > MAX_BODY_BYTES) return json({ code: 'body_too_large' }, 413)

    const signed = verifySignature(request, secret, currentMs, rawBody)
    if (!signed.ok) return signed.response

    let payload
    try {
      payload = JSON.parse(rawBody)
    } catch {
      return json({ code: 'invalid_json' }, 400)
    }
    const validationError = validatePayload(payload, currentMs)
    if (validationError) return json({ code: 'invalid_request', detail: validationError }, 400)

    const requestId = payload.request_id
    const bodyHash = sha256Hex(rawBody)
    const existing = requestStore.get(requestId)
    if (existing) {
      if (existing.bodyHash !== bodyHash) return json({ code: 'idempotency_conflict' }, 409)
      return json({ status: 'already_sent', request_id: requestId, message_id: existing.messageId || null }, 200)
    }

    const normalizedRecipient = payload.to.trim().toLowerCase()
    const rate = rateStore.get(normalizedRecipient) || { count: 0, expiresAt: currentMs + RATE_LIMIT_WINDOW_MS }
    if (rate.expiresAt <= currentMs) {
      rate.count = 0
      rate.expiresAt = currentMs + RATE_LIMIT_WINDOW_MS
    }
    if (rate.count >= RATE_LIMIT_MAX) return json({ code: 'rate_limited' }, 429)
    rate.count += 1
    rateStore.set(normalizedRecipient, rate)

    let response
    try {
      response = await fetchImpl('https://api.brevo.com/v3/smtp/email', {
        method: 'POST',
        headers: { accept: 'application/json', 'content-type': 'application/json', 'api-key': brevoKey },
        body: JSON.stringify(requestPayload({ ...payload, senderEmail })),
      })
    } catch {
      return json({ code: 'email_provider_unavailable', status: 'provider_error', request_id: requestId }, 502)
    }
    let responseText = ''
    try { responseText = await response.text() } catch { responseText = '' }
    if (!response.ok) return json({ code: 'email_provider_unavailable', status: 'provider_error', request_id: requestId }, 502)

    let providerBody = {}
    try { providerBody = responseText ? JSON.parse(responseText) : {} } catch { providerBody = {} }
    const messageId = typeof providerBody.messageId === 'string' ? providerBody.messageId : null
    requestStore.set(requestId, { messageId, bodyHash, expiresAt: currentMs + REQUEST_TTL_MS })
    return json({ status: 'sent', request_id: requestId, message_id: messageId }, 200)
  }

  return { handle }
}

export { MAX_BODY_BYTES, SIGNATURE_DRIFT_SECONDS, RATE_LIMIT_MAX }
