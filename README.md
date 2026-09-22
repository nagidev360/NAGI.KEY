# NAGI.KEY

NAGI.KEY is the signing and verification service for **CODEVAULT**.

## Features

- CODEVAULT-only signed keys
- HMAC-SHA256 signatures
- Random nonce per key
- Client ID support
- 1–3650 day expiry
- Server-side verification
- Public verification API
- Protected generation API
- Rate limiting and security headers
- Render-ready deployment
- Web dashboard for Generate + Verify

## API

### Generate

`POST /api/key/generate`

Headers:
- `X-Generator-Token: GENERATOR_TOKEN`

Body:
```json
{"clientId":"user-123","days":30}
```

### Verify

`POST /api/key/verify`

Body:
```json
{"key":"NAGI-..."}
```

A valid response includes:
```json
{
  "valid": true,
  "reason": "VALID",
  "product": "CODEVAULT",
  "clientId": "user-123",
  "issuedAt": "2026-01-01T00:00:00.000Z",
  "expiresAt": "2026-01-31T00:00:00.000Z"
}
```

## CODEVAULT integration

Use the verification endpoint from your CODEVAULT server/backend:

`https://nagi-key-4sli.onrender.com/api/key/verify`

Send:
```json
{"key":"USER_KEY"}
```

Do not place `KEY_SECRET` or `GENERATOR_TOKEN` inside CODEVAULT frontend code.

## Render

Build command:
`npm install`

Start command:
`npm start`

Required environment variables:

- `KEY_SECRET` — long random signing secret, 32+ characters
- `GENERATOR_TOKEN` — private generation token, 16+ characters
- `PORT` — optional; Render supplies this automatically

Never commit secrets to GitHub.

## Security model

The key payload is signed with HMAC-SHA256. The server validates the signature, product, version, and expiry before returning `valid: true`.

Current version is stateless: generated keys cannot be individually revoked without adding persistent storage and a revocation list.
