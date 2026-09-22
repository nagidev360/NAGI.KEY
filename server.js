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
const SESSION_SECRET = process.env.SESSION_SECRET;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const DEFAULT_PRODUCT = "CODEVAULT";
const MAX_DAYS = 3650;
const SESSION_TTL = 8 * 60 * 60 * 1000;

if (!KEY_SECRET || KEY_SECRET.length < 32) throw new Error("KEY_SECRET must be at least 32 characters.");
if (!SESSION_SECRET || SESSION_SECRET.length < 32) throw new Error("SESSION_SECRET must be at least 32 characters.");
if (!ADMIN_EMAIL || !ADMIN_PASSWORD) throw new Error("ADMIN_EMAIL and ADMIN_PASSWORD are required.");

app.set("trust proxy", 1);
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors({ origin: true, credentials: true, methods: ["GET","POST","OPTIONS"], allowedHeaders: ["Content-Type"] }));
app.use(express.json({ limit: "16kb" }));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false });
const verifyLimiter = rateLimit({ windowMs: 60 * 1000, limit: 120, standardHeaders: true, legacyHeaders: false });
const generateLimiter = rateLimit({ windowMs: 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false });

function safeEqualText(a,b){const aa=Buffer.from(String(a||""));const bb=Buffer.from(String(b||""));return aa.length===bb.length&&crypto.timingSafeEqual(aa,bb);}
function encode(v){return Buffer.from(v).toString("base64url");}
function sign(v,secret=KEY_SECRET){return crypto.createHmac("sha256",secret).update(v).digest("base64url");}
function normalizeDays(v){const d=Number(v);return Number.isFinite(d)?Math.max(1,Math.min(Math.floor(d),MAX_DAYS)):30;}

function createSession(email){
  const payload=encode(JSON.stringify({email,exp:Date.now()+SESSION_TTL,nonce:crypto.randomBytes(16).toString("hex")}));
  return payload+"."+sign(payload,SESSION_SECRET);
}
function readSession(req){
  const raw=req.headers.cookie?.split(";").map(x=>x.trim()).find(x=>x.startsWith("nagi_session="))?.slice("nagi_session=".length);
  if(!raw)return null;
  const [payload,sig]=raw.split(".");
  if(!payload||!sig||!safeEqualText(sig,sign(payload,SESSION_SECRET)))return null;
  try{const data=JSON.parse(Buffer.from(payload,"base64url").toString("utf8"));if(data.email!==ADMIN_EMAIL||Date.now()>=Number(data.exp))return null;return data;}catch{return null;}
}
function requireAuth(req,res,next){if(!readSession(req))return res.status(401).json({error:"LOGIN_REQUIRED"});next();}
function cookie(res,value,maxAge=SESSION_TTL){res.setHeader("Set-Cookie",`nagi_session=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${Math.floor(maxAge/1000)}`);}

function createKey({clientId,days}){
  const now=Date.now(),exp=now+normalizeDays(days)*86400000;
  const payload={v:1,product:DEFAULT_PRODUCT,clientId:clientId?String(clientId).slice(0,128):null,iat:now,exp,nonce:crypto.randomBytes(16).toString("hex")};
  const encoded=encode(JSON.stringify(payload));
  return {key:"NAGI-"+encoded+"."+sign(encoded),payload};
}
function verifyKey(key){
  if(typeof key!=="string"||!key.startsWith("NAGI-"))return{valid:false,reason:"INVALID_FORMAT"};
  const parts=key.slice(5).split(".");if(parts.length!==2||!parts[0]||!parts[1])return{valid:false,reason:"INVALID_FORMAT"};
  const [encoded,sig]=parts;if(!safeEqualText(sig,sign(encoded)))return{valid:false,reason:"INVALID_SIGNATURE"};
  let payload;try{payload=JSON.parse(Buffer.from(encoded,"base64url").toString("utf8"));}catch{return{valid:false,reason:"INVALID_PAYLOAD"}}
  if(payload.v!==1||payload.product!==DEFAULT_PRODUCT)return{valid:false,reason:"PRODUCT_MISMATCH"};
  if(!Number.isFinite(Number(payload.exp))||Date.now()>=Number(payload.exp))return{valid:false,reason:"EXPIRED"};
  return{valid:true,reason:"VALID",payload};
}
function publicPayload(p){return{product:p.product,clientId:p.clientId,issuedAt:new Date(p.iat).toISOString(),expiresAt:new Date(p.exp).toISOString()};}

app.get("/api/health",(req,res)=>res.json({ok:true,service:"NAGI.KEY",product:DEFAULT_PRODUCT,time:new Date().toISOString()}));

app.post("/api/auth/login",loginLimiter,(req,res)=>{
  const {email,password}=req.body||{};
  if(!safeEqualText(email,ADMIN_EMAIL)||!safeEqualText(password,ADMIN_PASSWORD))return res.status(401).json({success:false,error:"INVALID_CREDENTIALS"});
  cookie(res,createSession(ADMIN_EMAIL));
  res.json({success:true,email:ADMIN_EMAIL});
});
app.post("/api/auth/logout",(req,res)=>{cookie(res,"",0);res.json({success:true});});
app.get("/api/auth/me",(req,res)=>{const s=readSession(req);if(!s)return res.status(401).json({authenticated:false});res.json({authenticated:true,email:s.email});});

app.post("/api/key/generate",generateLimiter,requireAuth,(req,res)=>{
  const {clientId=null,days=30}=req.body||{};
  const result=createKey({clientId,days});
  res.status(201).json({success:true,key:result.key,...publicPayload(result.payload)});
});
app.post("/api/key/verify",verifyLimiter,(req,res)=>{
  const result=verifyKey(req.body?.key);
  if(!result.valid)return res.status(401).json(result);
  res.json({valid:true,reason:result.reason,...publicPayload(result.payload)});
});
app.get("/api/key/verify",verifyLimiter,(req,res)=>{
  const result=verifyKey(req.query.key);
  if(!result.valid)return res.status(401).json(result);
  res.json({valid:true,reason:result.reason,...publicPayload(result.payload)});
});

app.use(express.static(path.join(__dirname,"public")));
app.use((req,res)=>res.status(404).json({error:"NOT_FOUND"}));
app.listen(PORT,()=>console.log("NAGI.KEY running on port "+PORT));