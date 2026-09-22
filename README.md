# NAGI.KEY

NAGI.KEY is the signing authority for CODEVAULT keys.

## API

### Generate
POST /api/key/generate

Headers:
- X-Generator-Token: GENERATOR_TOKEN

Body:
\`\`\`json
{"product":"CODEVAULT","clientId":"user-123","days":30}
\`\`\`

### Verify
POST /api/key/verify

Body:
\`\`\`json
{"key":"NAGI-...","product":"CODEVAULT"}
\`\`\`

A valid response contains:
\`\`\`json
{"valid":true,"reason":"VALID","product":"CODEVAULT", "...":"..."}
\`\`\`

## Render

Build command: \`npm install\`
Start command: \`npm start\`

Required environment variables:
- KEY_SECRET
- GENERATOR_TOKEN

Never put either secret in frontend code or GitHub.

## Security model

Keys are HMAC-SHA256 signed and contain product, client ID, issue time, expiry, and a random nonce. Verification is server-side and does not trust frontend claims.
