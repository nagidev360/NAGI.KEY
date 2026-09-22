require("dotenv").config();
const express=require("express"),cors=require("cors"),helmet=require("helmet"),rateLimit=require("express-rate-limit"),crypto=require("crypto"),path=require("path");
const app=express(),PORT=Number(process.env.PORT)||10000;
const KEY_SECRET=process.env.KEY_SECRET,SESSION_SECRET=process.env.SESSION_SECRET,ADMIN_EMAIL=process.env.ADMIN_EMAIL,ADMIN_PASSWORD=process.env.ADMIN_PASSWORD;
const DEFAULT_PRODUCT="CODEVAULT",MAX_DAYS=3650,SESSION_TTL=8*60*60*1000;
if(!KEY_SECRET||KEY_SECRET.length<32)throw new Error("KEY_SECRET must be at least 32 characters.");
if(!SESSION_SECRET||SESSION_SECRET.length<32)throw new Error("SESSION_SECRET must be at least 32 characters.");
if(!ADMIN_EMAIL||!ADMIN_PASSWORD)throw new Error("ADMIN_EMAIL and ADMIN_PASSWORD are required.");
app.set("trust proxy",1);
app.use(helmet({crossOriginResourcePolicy:false,contentSecurityPolicy:false}));
const allowedOrigins=new Set(["https://nagi-key-clean.onrender.com","https://nagi-key-4sli.onrender.com","https://codevault-mouk.onrender.com"]);
const corsOptions={origin:(origin,cb)=>{if(!origin||allowedOrigins.has(origin))return cb(null,true);return cb(null,false)},credentials:true,methods:["GET","POST","OPTIONS"],allowedHeaders:["Content-Type","Accept"]};
app.use(cors(corsOptions));app.use(express.json({limit:"16kb"}));
const loginLimiter=rateLimit({windowMs:15*60*1000,limit:10,standardHeaders:true,legacyHeaders:false}),verifyLimiter=rateLimit({windowMs:60*1000,limit:120,standardHeaders:true,legacyHeaders:false}),generateLimiter=rateLimit({windowMs:60*1000,limit:20,standardHeaders:true,legacyHeaders:false});
function safeEqualText(a,b){const aa=Buffer.from(String(a||"")),bb=Buffer.from(String(b||""));return aa.length===bb.length&&crypto.timingSafeEqual(aa,bb)}
function encode(v){return Buffer.from(v).toString("base64url")}function sign(v,secret=KEY_SECRET){return crypto.createHmac("sha256",secret).update(v).digest("base64url")}
function normalizeDays(v){const d=Number(v);return Number.isFinite(d)?Math.max(1,Math.min(Math.floor(d),MAX_DAYS)):30}
function createSession(email){const p=encode(JSON.stringify({email,exp:Date.now()+SESSION_TTL,nonce:crypto.randomBytes(16).toString("hex")}));return p+"."+sign(p,SESSION_SECRET)}
function readSession(req){const raw=req.headers.cookie?.split(";").map(x=>x.trim()).find(x=>x.startsWith("nagi_session="))?.slice(13);if(!raw)return null;const[p,s]=raw.split(".");if(!p||!s||!safeEqualText(s,sign(p,SESSION_SECRET)))return null;try{const d=JSON.parse(Buffer.from(p,"base64url").toString("utf8"));if(d.email!==ADMIN_EMAIL||Date.now()>=Number(d.exp))return null;return d}catch{return null}}
function requireAuth(req,res,next){if(!readSession(req))return res.status(401).json({error:"LOGIN_REQUIRED"});next()}
function cookie(res,value,maxAge=SESSION_TTL){res.setHeader("Set-Cookie",`nagi_session=${value}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=${Math.floor(maxAge/1000)}`)}
function createKey({clientId,days}){const now=Date.now(),exp=now+normalizeDays(days)*86400000,p={v:1,product:DEFAULT_PRODUCT,clientId:clientId?String(clientId).slice(0,128):null,iat:now,exp,nonce:crypto.randomBytes(16).toString("hex")},e=encode(JSON.stringify(p));return{key:"NAGI-"+e+"."+sign(e),payload:p}}
function verifyKey(key){if(typeof key!=="string"||!key.startsWith("NAGI-"))return{valid:false,reason:"INVALID_FORMAT"};const x=key.slice(5).split(".");if(x.length!==2)return{valid:false,reason:"INVALID_FORMAT"};const[e,s]=x;if(!safeEqualText(s,sign(e)))return{valid:false,reason:"INVALID_SIGNATURE"};let p;try{p=JSON.parse(Buffer.from(e,"base64url").toString("utf8"))}catch{return{valid:false,reason:"INVALID_PAYLOAD"}}if(p.v!==1||p.product!==DEFAULT_PRODUCT)return{valid:false,reason:"PRODUCT_MISMATCH"};if(!Number.isFinite(Number(p.exp))||Date.now()>=Number(p.exp))return{valid:false,reason:"EXPIRED"};return{valid:true,reason:"VALID",payload:p}}
function publicPayload(p){return{product:p.product,clientId:p.clientId,issuedAt:new Date(p.iat).toISOString(),expiresAt:new Date(p.exp).toISOString()}}
app.get("/api/health",(req,res)=>res.json({ok:true,service:"NAGI.KEY",product:DEFAULT_PRODUCT,time:new Date().toISOString()}));
app.post("/api/auth/login",loginLimiter,(req,res)=>{const{email,password}=req.body||{};if(!safeEqualText(email,ADMIN_EMAIL)||!safeEqualText(password,ADMIN_PASSWORD))return res.status(401).json({success:false,error:"INVALID_CREDENTIALS"});cookie(res,createSession(ADMIN_EMAIL));res.json({success:true,email:ADMIN_EMAIL})});
app.post("/api/auth/logout",(req,res)=>{cookie(res,"",0);res.json({success:true})});app.get("/api/auth/me",(req,res)=>{const s=readSession(req);if(!s)return res.status(401).json({authenticated:false});res.json({authenticated:true,email:s.email})});
app.post("/api/key/generate",generateLimiter,requireAuth,(req,res)=>{const{clientId=null,days=30}=req.body||{};const r=createKey({clientId,days});res.status(201).json({success:true,key:r.key,...publicPayload(r.payload)})});
app.post("/api/key/verify",verifyLimiter,(req,res)=>{const r=verifyKey(req.body?.key);if(!r.valid)return res.status(401).json(r);res.json({valid:true,reason:r.reason,...publicPayload(r.payload)})});
app.get("/api/key/verify",verifyLimiter,(req,res)=>{const r=verifyKey(req.query.key);if(!r.valid)return res.status(401).json(r);res.json({valid:true,reason:r.reason,...publicPayload(r.payload)})});
app.use(express.static(path.join(__dirname,"public")));app.use((req,res)=>res.status(404).json({error:"NOT_FOUND"}));app.listen(PORT,()=>console.log("NAGI.KEY running on port "+PORT));