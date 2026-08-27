import test from 'node:test'
import assert from 'node:assert/strict'
import { Readable } from 'node:stream'
import crypto from 'node:crypto'
import { createRelay, MAX_BODY_BYTES } from '../src/relay.mjs'
import { readBody } from '../src/server.mjs'

const secret = 'relay-test-secret'
const sender = 'bt.black.tiger.13@gmail.com'
const fixedNow = Date.parse('2026-08-27T00:00:00.000Z')
const env = { RELAY_SHARED_SECRET: secret, BREVO_API_KEY: 'key', BREVO_SENDER_EMAIL: sender }

function signature(body, timestamp = String(Math.floor(fixedNow / 1000))) {
  return crypto.createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex')
}

function providerStatusSignature(timestamp = String(Math.floor(fixedNow / 1000))) {
  return crypto.createHmac('sha256', secret).update(`${timestamp}.GET./v1/provider-status`).digest('hex')
}

function request(body, { timestamp = String(Math.floor(fixedNow / 1000)), sig = signature(body), path = '/v1/send-verification', method = 'POST', headers = {} } = {}) {
  return new Request(`https://relay.test${path}`, {
    method,
    headers: { 'content-type': 'application/json', 'x-bt13-timestamp': timestamp, 'x-bt13-signature': sig, ...headers },
    body: method === 'GET' || method === 'HEAD' ? undefined : body,
  })
}

function payload(overrides = {}) {
  return JSON.stringify({
    template: 'trial_verification',
    to: 'brahimlag177@gmail.com',
    code: '123456',
    expires_at: '2026-08-27T00:10:00.000Z',
    request_id: 'trial_req_001',
    ...overrides,
  })
}

function configuredRelay(overrides = {}) {
  return createRelay({ env, now: () => fixedNow, ...overrides })
}

test('health is configured only when all secrets exist', async () => {
  const configured = configuredRelay()
  const response = await configured.handle(new Request('https://relay.test/health'))
  assert.equal(response.status, 200)
  assert.deepEqual(await response.json(), { service: 'bt13-brevo-relay', status: 'ok', provider: 'brevo', configured: true })

  const incomplete = createRelay({ env: { RELAY_SHARED_SECRET: secret }, now: () => fixedNow })
  const incompleteResponse = await incomplete.handle(new Request('https://relay.test/health'))
  assert.equal(incompleteResponse.status, 200)
  assert.equal((await incompleteResponse.json()).status, 'not_configured')
})

test('rejects missing configuration and unsupported paths', async () => {
  const incomplete = createRelay({ env: { RELAY_SHARED_SECRET: secret }, now: () => fixedNow })
  const missing = await incomplete.handle(request(payload()))
  assert.equal(missing.status, 503)
  assert.deepEqual(await missing.json(), { code: 'relay_not_configured', status: 'not_configured' })

  const relay = configuredRelay()
  const unsupportedGet = await relay.handle(request('', { method: 'GET', path: '/v1/send-verification' }))
  assert.equal(unsupportedGet.status, 404)
  assert.deepEqual(await unsupportedGet.json(), { code: 'not_found' })
  const unsupportedPost = await relay.handle(request(payload(), { path: '/v1/not-supported' }))
  assert.equal(unsupportedPost.status, 404)
  assert.deepEqual(await unsupportedPost.json(), { code: 'not_found' })
})

test('rejects invalid signatures without calling Brevo', async () => {
  let calls = 0
  const relay = configuredRelay({ fetchImpl: async () => { calls += 1; return new Response('{}', { status: 201 }) } })
  const response = await relay.handle(request(payload(), { sig: '0'.repeat(64) }))
  assert.equal(response.status, 401)
  assert.deepEqual(await response.json(), { code: 'invalid_signature' })
  assert.equal(calls, 0)
})

test('rejects malformed and stale timestamps before provider access', async () => {
  const relay = configuredRelay({ fetchImpl: async () => { throw new Error('must not call') } })
  const body = payload()
  const malformedTimestamp = await relay.handle(request(body, { timestamp: 'not-a-timestamp', sig: signature(body, 'not-a-timestamp') }))
  assert.equal(malformedTimestamp.status, 401)
  assert.deepEqual(await malformedTimestamp.json(), { code: 'invalid_signature' })

  const staleTimestamp = String(Math.floor((fixedNow - 10 * 60 * 1000) / 1000))
  const stale = await relay.handle(request(body, { timestamp: staleTimestamp, sig: signature(body, staleTimestamp) }))
  assert.equal(stale.status, 401)
  assert.deepEqual(await stale.json(), { code: 'stale_signature' })

  const malformedPayload = JSON.stringify({ template: 'other', to: 'not-an-email', code: '12', expires_at: 'bad', request_id: 'x' })
  const bad = await relay.handle(request(malformedPayload))
  assert.equal(bad.status, 400)
  assert.equal((await bad.json()).code, 'invalid_request')
})

test('rejects oversized bodies before parsing', async () => {
  const relay = configuredRelay({ fetchImpl: async () => { throw new Error('must not call') } })
  const body = 'x'.repeat(MAX_BODY_BYTES + 1)
  const response = await relay.handle(request(body, { headers: { 'content-length': String(Buffer.byteLength(body)) } }))
  assert.equal(response.status, 413)
  assert.deepEqual(await response.json(), { code: 'body_too_large' })

  const streamResult = await readBody(Readable.from([Buffer.alloc(MAX_BODY_BYTES), Buffer.from('x')]))
  assert.equal(streamResult.tooLarge, true)
  assert.equal(streamResult.body.length, 0)
})

test('sends exactly once, stores a body hash, and makes a duplicate request idempotent', async () => {
  const seen = []
  const relay = configuredRelay({ fetchImpl: async (url, options) => { seen.push({ url, body: JSON.parse(options.body), headers: options.headers }); return new Response(JSON.stringify({ messageId: '<test@brevo>' }), { status: 201 }) } })
  const body = payload()
  const first = await relay.handle(request(body))
  assert.equal(first.status, 200)
  const firstText = await first.text()
  assert.deepEqual(JSON.parse(firstText), { status: 'sent', request_id: 'trial_req_001', message_id: '<test@brevo>' })
  assert.equal(firstText.includes('123456'), false)
  assert.equal(seen.length, 1)
  assert.equal(seen[0].url, 'https://api.brevo.com/v3/smtp/email')
  assert.equal(seen[0].body.sender.email, sender)
  assert.equal(seen[0].body.to[0].email, 'brahimlag177@gmail.com')
  assert.equal(seen[0].headers['api-key'], 'key')

  const duplicate = await relay.handle(request(body))
  assert.equal(duplicate.status, 200)
  const duplicateText = await duplicate.text()
  assert.deepEqual(JSON.parse(duplicateText), { status: 'already_sent', request_id: 'trial_req_001', message_id: '<test@brevo>' })
  assert.equal(duplicateText.includes('123456'), false)
  assert.equal(seen.length, 1)
})

test('rejects same request id with a different signed payload', async () => {
  let calls = 0
  const relay = configuredRelay({ fetchImpl: async () => { calls += 1; return new Response('{}', { status: 201 }) } })
  const firstBody = payload()
  const secondBody = payload({ code: '654321' })
  assert.equal((await relay.handle(request(firstBody))).status, 200)
  const conflict = await relay.handle(request(secondBody))
  assert.equal(conflict.status, 409)
  assert.deepEqual(await conflict.json(), { code: 'idempotency_conflict' })
  assert.equal(calls, 1)
})

test('does not expose provider errors, codes, or rate-limit details', async () => {
  let calls = 0
  const relay = configuredRelay({ fetchImpl: async () => { calls += 1; return new Response(JSON.stringify({ message: 'provider secret detail', code: '123456' }), { status: 500 }) } })
  for (let index = 0; index < 5; index += 1) {
    const response = await relay.handle(request(payload({ request_id: `trial_req_${String(index + 10).padStart(3, '0')}` })))
    assert.equal(response.status, 502)
    const text = await response.text()
    assert.deepEqual(JSON.parse(text), { code: 'email_provider_unavailable', status: 'provider_error', request_id: `trial_req_${String(index + 10).padStart(3, '0')}` })
    assert.equal(text.includes('123456'), false)
    assert.equal(text.includes('provider secret'), false)
  }
  const limited = await relay.handle(request(payload({ request_id: 'trial_req_099' })))
  assert.equal(limited.status, 429)
  assert.deepEqual(await limited.json(), { code: 'rate_limited' })
  assert.equal(calls, 5)
})

test('maps Brevo timeout or thrown fetch to a sanitized 502', async () => {
  const relay = configuredRelay({ fetchImpl: async () => { throw new Error('timeout with provider secret') } })
  const response = await relay.handle(request(payload({ request_id: 'trial_req_throw' })))
  assert.equal(response.status, 502)
  const text = await response.text()
  assert.deepEqual(JSON.parse(text), { code: 'email_provider_unavailable', status: 'provider_error', request_id: 'trial_req_throw' })
  assert.equal(text.includes('timeout'), false)
  assert.equal(text.includes('123456'), false)
})

test('ignores arbitrary HTML and template controls', async () => {
  let outbound
  const relay = configuredRelay({ fetchImpl: async (_url, options) => { outbound = JSON.parse(options.body); return new Response('{}', { status: 201 }) } })
  const response = await relay.handle(request(payload({ html: '<script>alert(1)</script>', template: 'trial_verification', subject: 'attacker subject', sender: 'attacker@example.com' })))
  assert.equal(response.status, 200)
  assert.equal(outbound.subject, 'Your BT13 evaluation verification code')
  assert.equal('html' in outbound, false)
  assert.equal(outbound.sender.email, sender)
  assert.equal(outbound.htmlContent.includes('<script>'), false)
})

test('provider-status is signed, read-only, and returns only sender activity', async () => {
  let calls = 0
  const relay = configuredRelay({ fetchImpl: async (url, options) => {
    calls += 1
    assert.equal(url, 'https://api.brevo.com/v3/senders')
    assert.equal(options.method, 'GET')
    assert.equal(options.headers['api-key'], 'key')
    return new Response(JSON.stringify({ senders: [{ email: sender, active: true }, { email: 'other@example.com', active: false }] }), { status: 200 })
  } })
  const response = await relay.handle(new Request('https://relay.test/v1/provider-status', { method: 'GET', headers: { 'x-bt13-timestamp': String(Math.floor(fixedNow / 1000)), 'x-bt13-signature': providerStatusSignature() } }))
  assert.equal(response.status, 200)
  assert.deepEqual(await response.json(), { status: 'ok', sender_active: true })
  assert.equal(calls, 1)
})

test('provider-status sanitizes provider failures and thrown fetch', async () => {
  const failed = configuredRelay({ fetchImpl: async () => new Response(JSON.stringify({ message: 'secret' }), { status: 401 }) })
  const failedResponse = await failed.handle(new Request('https://relay.test/v1/provider-status', { method: 'GET', headers: { 'x-bt13-timestamp': String(Math.floor(fixedNow / 1000)), 'x-bt13-signature': providerStatusSignature() } }))
  assert.equal(failedResponse.status, 502)
  assert.deepEqual(await failedResponse.json(), { code: 'email_provider_unavailable' })

  const thrown = configuredRelay({ fetchImpl: async () => { throw new Error('timeout') } })
  const thrownResponse = await thrown.handle(new Request('https://relay.test/v1/provider-status', { method: 'GET', headers: { 'x-bt13-timestamp': String(Math.floor(fixedNow / 1000)), 'x-bt13-signature': providerStatusSignature() } }))
  assert.equal(thrownResponse.status, 502)
  assert.deepEqual(await thrownResponse.json(), { code: 'email_provider_unavailable' })
})
