require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 10000;
const KEY_SECRET = process.env.KEY_SECRET;
const GENERATOR_TOKEN = process.env.GENERATOR_TOKEN;
const DEFAULT_PRODUCT = "CODEVAULT";

if (!KEY_SECRET) {
  console.error("Missing KEY_SECRET environment variable.");
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

const verifyLimiter = rateLimit({ windowMs: 60 * 1000, limit: 120, standardHeaders: true });
const generateLimiter = rateLimit({ windowMs: 60 * 1000, limit: 20, standardHeaders: true });

function b64url(value) {
  return Buffer.from(value).toString("base64url");
}

function sign(payload) {
  return crypto.createHmac("sha256", KEY_SECRET).update(payload).digest("base64url");
}

function createKey({ product, clientId, days }) {
  const now = Date.now();
  const expiresAt = now + Math.max(1, Math.min(Number(days) || 30, 3650)) * 86400000;
  const payload = {
    v: 1,
    product: product || DEFAULT_PRODUCT,
    clientId: clientId || null,
    iat: now,
    exp: expiresAt,
    nonce: crypto.randomBytes(16).toString("hex")
  };
  const encoded = b64url(JSON.stringify(payload));
  return {
    key: "NAGI-" + encoded + "." + sign(encoded),
    payload
  };
}

function verifyKey(key, expectedProduct = DEFAULT_PRODUCT) {
  if (typeof key !== "string" || !key.startsWith("NAGI-")) {
    return { valid: false, reason: "INVALID_FORMAT" };
  }

  const raw = key.slice(5);
  const parts = raw.split(".");
  if (parts.length !== 2) return { valid: false, reason: "INVALID_FORMAT" };

  const [encoded, signature] = parts;
  const expected = sign(encoded);
  const a = Buffer.from(signature);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return { valid: false, reason: "INVALID_SIGNATURE" };
  }

  let payload;
  try {
    payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  } catch {
    return { valid: false, reason: "INVALID_PAYLOAD" };
  }

  if (payload.product !== expectedProduct) {
    return { valid: false, reason: "PRODUCT_MISMATCH" };
  }

  if (!payload.exp || Date.now() >= Number(payload.exp)) {
    return { valid: false, reason: "EXPIRED" };
  }

  return { valid: true, reason: "VALID", payload };
}

function generatorAuthorized(req) {
  const token = req.get("X-Generator-Token") ||
    (req.headers.authorization || "").replace(/^Bearer\\s+/i, "");
  return Boolean(GENERATOR_TOKEN && token && crypto.timingSafeEqual(
    Buffer.from(token),
    Buffer.from(GENERATOR_TOKEN)
  ));
}

app.get("/api/health", (req, res) => {
  res.json({ ok: true, service: "NAGI.KEY", time: new Date().toISOString() });
});

app.post("/api/key/generate", generateLimiter, (req, res) => {
  if (!generatorAuthorized(req)) {
    return res.status(401).json({ valid: false, error: "GENERATOR_UNAUTHORIZED" });
  }

  const { product = DEFAULT_PRODUCT, clientId = null, days = 30 } = req.body || {};
  const result = createKey({ product, clientId, days });

  res.status(201).json({
    success: true,
    key: result.key,
    product: result.payload.product,
    clientId: result.payload.clientId,
    issuedAt: new Date(result.payload.iat).toISOString(),
    expiresAt: new Date(result.payload.exp).toISOString()
  });
});

app.post("/api/key/verify", verifyLimiter, (req, res) => {
  const { key, product = DEFAULT_PRODUCT } = req.body || {};
  const result = verifyKey(key, product);

  if (!result.valid) {
    return res.status(401).json(result);
  }

  res.json({
    valid: true,
    reason: result.reason,
    product: result.payload.product,
    clientId: result.payload.clientId,
    issuedAt: new Date(result.payload.iat).toISOString(),
    expiresAt: new Date(result.payload.exp).toISOString()
  });
});

app.get("/api/key/verify", verifyLimiter, (req, res) => {
  const result = verifyKey(req.query.key, req.query.product || DEFAULT_PRODUCT);
  if (!result.valid) return res.status(401).json(result);
  res.json({
    valid: true,
    reason: result.reason,
    product: result.payload.product,
    clientId: result.payload.clientId,
    expiresAt: new Date(result.payload.exp).toISOString()
  });
});

app.use(express.static(path.join(__dirname, "public")));

app.use((req, res) => {
  res.status(404).json({ error: "NOT_FOUND" });
});

app.listen(PORT, () => {
  console.log("NAGI.KEY running on port " + PORT);
});
