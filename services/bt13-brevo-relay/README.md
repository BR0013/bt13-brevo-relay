# BT13 Brevo Relay

This service is a deliberately narrow backend relay for BT13 email-verification messages. It is not a general SMTP proxy and does not accept arbitrary recipients, HTML, templates, attachments, or campaigns.

## Runtime secrets

Set these as Render environment secrets:

- `BREVO_API_KEY`: the Brevo REST API key.
- `BREVO_SENDER_EMAIL`: verified BT13 sender email.
- `RELAY_SHARED_SECRET`: long random secret shared only with the BT13 Cloudflare Worker.

The Brevo key must never be placed in the frontend, GitHub source, or Worker. The Worker only receives the relay shared secret.

## Endpoints

- `GET /health` returns configuration state only.
- `POST /v1/send-verification` accepts a signed JSON body with `template=trial_verification`, a recipient, a six-digit code, an ISO expiry, and an idempotency request ID.

The request must include `x-bt13-timestamp` and `x-bt13-signature`, where the signature is an HMAC-SHA256 hex digest over `${timestamp}.${rawBody}` using `RELAY_SHARED_SECRET`.

## Local verification

```bash
npm test
BREVO_API_KEY=redacted BREVO_SENDER_EMAIL=bt.black.tiger.13@gmail.com RELAY_SHARED_SECRET=local-secret npm start
curl http://localhost:10000/health
```

## Render

The service is intended to run as a Render Web Service in one region on the free plan for the first MVP experiment. Render's shared outbound addresses are region-specific CIDR ranges; Brevo supports IP ranges in CIDR notation. This is a cost-saving compromise, not an exclusive egress security boundary. If Render changes its shared ranges, the Brevo allowlist must be updated, or the service must be moved to Render Dedicated IPs or another static-egress provider.
