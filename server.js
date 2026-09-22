require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = Number(process.env.PORT) || 10000;
const KEY_SECRET = process.env.KEY_SECRET;
const GENERATOR_TOKEN = process.env.GENERATOR_TOKEN;
const DEFAULT_PRODUCT = "CODEVAULT";
const MAX_DAYS = 3650;

if (!KEY_SECRET || KEY_SECRET.length < 32) {
  console.error("KEY_SECRET must be set and at least 32 characters long.");
  process.exit(1);
}

if (!GENERATOR_TOKEN || GENERATOR_TOKEN.length < 16) {
  console.error("GENERATOR_TOKEN must be set and at least 16 characters long.");
  process.exit(1);
}

app.set("trust proxy", 1);
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors({
  origin: true,
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Generator-Token"]
}));
app.use(express.json({ limit: "16kb" }));

const verifyLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: true,
  legacyHeaders: false
});
const generateLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false
});

function encode(value) {
  return Buffer.from(value).toString("base64url");
}

function sign(encodedPayload) {
  return crypto.createHmac("sha256", KEY_SECRET).update(encodedPayload).digest("base64url");
}

function safeEqualText(a, b) {
  const aa = Buffer.from(String(a || ""));
  const bb = Buffer.from(String(b || ""));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

function normalizeDays(value) {
  const days = Number(value);
  if (!Number.isFinite(days)) return 30;
  return Math.max(1, Math.min(Math.floor(days), MAX_DAYS));
}

function createKey({ clientId, days }) {
  const now = Date.now();
  const expiresAt = now + normalizeDays(days) * 86400000;
  const payload = {
    v: 1,
    product: DEFAULT_PRODUCT,
    clientId: clientId ? String(clientId).slice(0, 128) : null,
    iat: now,
    exp: expiresAt,
    nonce: crypto.randomBytes(16).toString("hex")
  };

  const encoded = encode(JSON.stringify(payload));
  return {
    key: "NAGI-" + encoded + "." + sign(encoded),
    payload
  };
}

function verifyKey(key) {
  if (typeof key !== "string" || !key.startsWith("NAGI-")) {
    return { valid: false, reason: "INVALID_FORMAT" };
  }

  const parts = key.slice(5).split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    return { valid: false, reason: "INVALID_FORMAT" };
  }

  const [encoded, signature] = parts;
  if (!safeEqualText(signature, sign(encoded))) {
    return { valid: false, reason: "INVALID_SIGNATURE" };
  }

  let payload;
  try {
    payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  } catch {
    return { valid: false, reason: "INVALID_PAYLOAD" };
  }

  if (payload.v !== 1 || payload.product !== DEFAULT_PRODUCT) {
    return { valid: false, reason: "PRODUCT_MISMATCH" };
  }

  if (!Number.isFinite(Number(payload.exp)) || Date.now() >= Number(payload.exp)) {
    return { valid: false, reason: "EXPIRED" };
  }

  return { valid: true, reason: "VALID", payload };
}

function generatorAuthorized(req) {
  const token = req.get("X-Generator-Token") ||
    (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  return safeEqualText(token, GENERATOR_TOKEN);
}

function publicPayload(payload) {
  return {
    product: payload.product,
    clientId: payload.clientId,
    issuedAt: new Date(payload.iat).toISOString(),
    expiresAt: new Date(payload.exp).toISOString()
  };
}

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "NAGI.KEY",
    product: DEFAULT_PRODUCT,
    time: new Date().toISOString()
  });
});

app.post("/api/key/generate", generateLimiter, (req, res) => {
  if (!generatorAuthorized(req)) {
    return res.status(401).json({
      success: false,
      error: "GENERATOR_UNAUTHORIZED"
    });
  }

  const { clientId = null, days = 30 } = req.body || {};
  const result = createKey({ clientId, days });

  res.status(201).json({
    success: true,
    key: result.key,
    ...publicPayload(result.payload)
  });
});

app.post("/api/key/verify", verifyLimiter, (req, res) => {
  const { key } = req.body || {};
  const result = verifyKey(key);

  if (!result.valid) {
    return res.status(401).json(result);
  }

  res.json({
    valid: true,
    reason: result.reason,
    ...publicPayload(result.payload)
  });
});

app.get("/api/key/verify", verifyLimiter, (req, res) => {
  const result = verifyKey(req.query.key);

  if (!result.valid) {
    return res.status(401).json(result);
  }

  res.json({
    valid: true,
    reason: result.reason,
    ...publicPayload(result.payload)
  });
});

app.use(express.static(path.join(__dirname, "public")));

app.use((req, res) => {
  res.status(404).json({ error: "NOT_FOUND" });
});

app.listen(PORT, () => {
  console.log("NAGI.KEY running on port " + PORT);
});
