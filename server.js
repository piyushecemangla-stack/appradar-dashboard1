const express = require('express');
const cors    = require('cors');
const session = require('express-session');
const path    = require('path');
const fs      = require('fs');
const axios   = require('axios');
const jwt     = require('jsonwebtoken');
const crypto  = require('crypto');
const {google}= require('googleapis');

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cors({ origin:'*', credentials:true }));
app.use(express.json());
app.use(express.urlencoded({ extended:true }));
app.use(session({ secret: process.env.SESSION_SECRET||'appradar-secret', resave:false, saveUninitialized:false, cookie:{ secure:false, maxAge:7*24*60*60*1000 } }));
app.use(express.static(path.join(__dirname,'public')));

// token store
const TF = path.join(__dirname,'tokens.json');
let T = {};
try { if(fs.existsSync(TF)) T = JSON.parse(fs.readFileSync(TF,'utf8')); } catch(e){}
const save = () => { try{ fs.writeFileSync(TF,JSON.stringify(T,null,2)); }catch(e){} };

// ── GOOGLE PLAY: OAuth2 redirect flow ──────────────────────────────────────────
app.get('/auth/google/start', (req,res) => {
  const oa = new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET, process.env.GOOGLE_REDIRECT||`http://localhost:${PORT}/auth/google/callback`);
  res.redirect(oa.generateAuthUrl({ access_type:'offline', prompt:'consent', scope:['https://www.googleapis.com/auth/androidpublisher','https://www.googleapis.com/auth/userinfo.email'] }));
});
app.get('/auth/google/callback', async (req,res) => {
  try {
    const oa = new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET, process.env.GOOGLE_REDIRECT||`http://localhost:${PORT}/auth/google/callback`);
    const {tokens:t} = await oa.getToken(req.query.code);
    oa.setCredentials(t);
    const ui = await google.oauth2({version:'v2',auth:oa}).userinfo.get();
    T.google = { ...t, email:ui.data.email, connectedAt:new Date().toISOString() };
    save();
    res.redirect('/?connected=google');
  } catch(e) { res.redirect('/?error='+encodeURIComponent(e.message)); }
});

// ── APPLE: paste Key ID + Issuer ID + private key ─────────────────────────────
app.post('/auth/apple/connect', async (req,res) => {
  const {keyId,issuerId,privateKey} = req.body;
  if (!keyId||!issuerId||!privateKey) return res.json({ok:false,error:'Missing fields'});
  try {
    const now = Math.floor(Date.now()/1000);
    const tok = jwt.sign({iss:issuerId,iat:now,exp:now+1200,aud:'appstoreconnect-v1'}, privateKey.replace(/\\n/g,'\n'), {algorithm:'ES256',header:{kid:keyId,typ:'JWT'}});
    await axios.get('https://api.appstoreconnect.apple.com/v1/apps?limit=1',{headers:{Authorization:`Bearer ${tok}`}});
    T.apple = {keyId,issuerId,privateKey:privateKey.replace(/\\n/g,'\n'),connectedAt:new Date().toISOString()};
    save(); res.json({ok:true});
  } catch(e) { res.json({ok:false,error:e.response?.data?.errors?.[0]?.detail||e.message}); }
});

// ── AMAZON: client ID + secret ────────────────────────────────────────────────
app.post('/auth/amazon/connect', async (req,res) => {
  const {clientId,clientSecret} = req.body;
  if (!clientId||!clientSecret) return res.json({ok:false,error:'Missing fields'});
  try {
    const r = await axios.post('https://api.amazon.com/auth/o2/token',
      new URLSearchParams({grant_type:'client_credentials',client_id:clientId,client_secret:clientSecret,scope:'appstore::submissions'}).toString(),
      {headers:{'Content-Type':'application/x-www-form-urlencoded'}});
    if (!r.data.access_token) throw new Error('No token');
    T.amazon = {clientId,clientSecret,connectedAt:new Date().toISOString()};
    save(); res.json({ok:true});
  } catch(e) { res.json({ok:false,error:e.response?.data?.error_description||e.message}); }
});

// ── SAMSUNG ───────────────────────────────────────────────────────────────────
app.post('/auth/samsung/connect', async (req,res) => {
  const {clientId,clientSecret} = req.body;
  if (!clientId||!clientSecret) return res.json({ok:false,error:'Missing fields'});
  try {
    const r = await axios.post('https://seller.samsungapps.com/oauth/token',
      new URLSearchParams({grant_type:'client_credentials',client_id:clientId,client_secret:clientSecret}).toString(),
      {headers:{'Content-Type':'application/x-www-form-urlencoded'}});
    if (!r.data.access_token) throw new Error('No token');
    T.samsung = {clientId,clientSecret,connectedAt:new Date().toISOString()};
    save(); res.json({ok:true});
  } catch(e) { res.json({ok:false,error:e.message}); }
});

// ── LG ────────────────────────────────────────────────────────────────────────
app.post('/auth/lg/connect', (req,res) => {
  const {apiKey,secretKey} = req.body;
  if (!apiKey) return res.json({ok:false,error:'Missing apiKey'});
  T.lg = {apiKey,secretKey:secretKey||'',connectedAt:new Date().toISOString()};
  save(); res.json({ok:true});
});

// ── ROKU ──────────────────────────────────────────────────────────────────────
app.post('/auth/roku/connect', async (req,res) => {
  const {clientId,clientSecret} = req.body;
  if (!clientId||!clientSecret) return res.json({ok:false,error:'Missing fields'});
  try {
    const r = await axios.post('https://oauth.roku.com/token',
      new URLSearchParams({grant_type:'client_credentials',client_id:clientId,client_secret:clientSecret,scope:'channel_management'}).toString(),
      {headers:{'Content-Type':'application/x-www-form-urlencoded'}});
    if (!r.data.access_token) throw new Error('No token');
    T.roku = {clientId,clientSecret,connectedAt:new Date().toISOString()};
    save(); res.json({ok:true});
  } catch(e) { res.json({ok:false,error:e.message}); }
});

// ── STATUS ────────────────────────────────────────────────────────────────────
app.get('/api/status', (_,res) => {
  const s={};
  ['google','apple','amazon','samsung','lg','roku'].forEach(k=>{
    s[k]={connected:!!T[k],email:T[k]?.email||null,connectedAt:T[k]?.connectedAt||null};
  });
  res.json({ok:true,status:s});
});

// ── LIVE DATA ─────────────────────────────────────────────────────────────────
app.get('/api/data', async (_,res) => {
  const D = {};

  // Google Play
  if (T.google) {
    try {
      const oa = new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID,process.env.GOOGLE_CLIENT_SECRET);
      oa.setCredentials({access_token:T.google.access_token,refresh_token:T.google.refresh_token});
      const pub  = google.androidpublisher({version:'v3',auth:oa});
      const pkgs = (process.env.GOOGLE_PACKAGE_NAMES||'').split(',').map(s=>s.trim()).filter(Boolean);
      const apps = await Promise.all(pkgs.map(async pkg => {
        try {
          const edit   = await pub.edits.insert({packageName:pkg});
          const trks   = await pub.edits.tracks.list({packageName:pkg,editId:edit.data.id});
          await pub.edits.delete({packageName:pkg,editId:edit.data.id});
          const prod   = trks.data.tracks?.find(t=>t.track==='production')||trks.data.tracks?.[0];
          const rel    = prod?.releases?.[0]||{};
          const sm     = {completed:'approved',inProgress:'approved',draft:'pending',halted:'review'};
          return {name:pkg.split('.').pop(),packageName:pkg,version:rel.name||'—',build:String(rel.versionCodes?.[0]||'—'),status:sm[rel.status]||'pending',rollout:rel.userFraction?Math.round(rel.userFraction*100):100,crash:null,anr:null};
        } catch(e){return {packageName:pkg,error:e.message};}
      }));
      D.google={connected:true,email:T.google.email,apps};
    } catch(e){D.google={connected:true,error:e.message};}
  } else D.google={connected:false};

  // Apple
  if (T.apple) {
    try {
      const now=Math.floor(Date.now()/1000);
      const tok=jwt.sign({iss:T.apple.issuerId,iat:now,exp:now+1200,aud:'appstoreconnect-v1'},T.apple.privateKey,{algorithm:'ES256',header:{kid:T.apple.keyId,typ:'JWT'}});
      const r=await axios.get('https://api.appstoreconnect.apple.com/v1/apps?limit=10&fields[apps]=name,bundleId',{headers:{Authorization:`Bearer ${tok}`}});
      const sm={READY_FOR_SALE:'approved',IN_REVIEW:'review',REJECTED:'rejected',PREPARE_FOR_SUBMISSION:'pending',PROCESSING_FOR_APP_STORE:'review'};
      const apps=await Promise.all((r.data.data||[]).map(async a=>{
        try{
          const vr=await axios.get(`https://api.appstoreconnect.apple.com/v1/apps/${a.id}/appStoreVersions?limit=1`,{headers:{Authorization:`Bearer ${tok}`}});
          const v=vr.data.data?.[0]?.attributes||{};
          return {name:a.attributes?.name,bundleId:a.attributes?.bundleId,version:v.versionString||'—',build:v.buildNumber||'—',status:sm[v.appStoreState]||'pending',rollout:100,crash:null,anr:null};
        }catch(e){return {name:a.attributes?.name,error:e.message};}
      }));
      D.apple={connected:true,apps};
    } catch(e){D.apple={connected:true,error:e.message};}
  } else D.apple={connected:false};

  // Amazon
  if (T.amazon) {
    try {
      const tr=await axios.post('https://api.amazon.com/auth/o2/token',new URLSearchParams({grant_type:'client_credentials',client_id:T.amazon.clientId,client_secret:T.amazon.clientSecret,scope:'appstore::submissions'}).toString(),{headers:{'Content-Type':'application/x-www-form-urlencoded'}});
      const ar=await axios.get('https://developer.amazon.com/api/appstore/v1/applications',{headers:{Authorization:`Bearer ${tr.data.access_token}`}});
      const apps=(Array.isArray(ar.data)?ar.data:ar.data?.applications||[]).map(a=>({name:a.title||a.name,version:a.defaultListing?.versionCode||'—',status:a.status==='LIVE'?'approved':a.status?.toLowerCase()||'pending',rollout:100,crash:null,anr:null}));
      D.amazon={connected:true,apps};
    } catch(e){D.amazon={connected:true,error:e.message};}
  } else D.amazon={connected:false};

  // Samsung
  if (T.samsung) {
    try {
      const tr=await axios.post('https://seller.samsungapps.com/oauth/token',new URLSearchParams({grant_type:'client_credentials',client_id:T.samsung.clientId,client_secret:T.samsung.clientSecret}).toString(),{headers:{'Content-Type':'application/x-www-form-urlencoded'}});
      const ar=await axios.get('https://seller.samsungapps.com/api/v2/seller/applications',{headers:{Authorization:`Bearer ${tr.data.access_token}`}});
      const sm={FOR_SALE:'approved',REVIEW:'review',REJECTED:'rejected',REGISTERED:'pending'};
      const apps=(ar.data?.applications||[]).map(a=>({name:a.contentName||a.title,version:a.version||'—',status:sm[a.contentStatus]||'pending',rollout:100,crash:null,anr:null}));
      D.samsung={connected:true,apps};
    } catch(e){D.samsung={connected:true,error:e.message};}
  } else D.samsung={connected:false};

  // LG
  if (T.lg) {
    try {
      const ts=Date.now().toString();
      const sig=crypto.createHmac('sha256',T.lg.secretKey).update(T.lg.apiKey+ts).digest('hex');
      const ar=await axios.get('https://seller.lgappstv.com/api/v1/applications',{headers:{'X-Api-Key':T.lg.apiKey,'X-Timestamp':ts,'X-Signature':sig}});
      const sm={PUBLISHED:'approved',REVIEW:'review',REJECTED:'rejected',SAVED:'pending'};
      const apps=(ar.data?.applications||ar.data?.data||[]).map(a=>({name:a.appName||a.title,version:a.version||'—',status:sm[a.status]||'pending',rollout:100,crash:null,anr:null}));
      D.lg={connected:true,apps};
    } catch(e){D.lg={connected:true,error:e.message};}
  } else D.lg={connected:false};

  // Roku
  if (T.roku) {
    try {
      const tr=await axios.post('https://oauth.roku.com/token',new URLSearchParams({grant_type:'client_credentials',client_id:T.roku.clientId,client_secret:T.roku.clientSecret,scope:'channel_management'}).toString(),{headers:{'Content-Type':'application/x-www-form-urlencoded'}});
      const cr=await axios.get('https://api.roku.com/developer/v1/channels',{headers:{Authorization:`Bearer ${tr.data.access_token}`}});
      const sm={published:'approved',under_review:'review',rejected:'rejected',unpublished:'pending'};
      const apps=(Array.isArray(cr.data)?cr.data:cr.data?.channels||[]).map(c=>({name:c.name||c.title,version:c.version||'—',status:sm[c.status?.toLowerCase()]||'pending',rollout:100,crash:null,anr:null}));
      D.roku={connected:true,apps};
    } catch(e){D.roku={connected:true,error:e.message};}
  } else D.roku={connected:false};

  res.json({ok:true,lastUpdated:new Date().toISOString(),data:D});
});

// ── DISCONNECT ────────────────────────────────────────────────────────────────
app.post('/api/disconnect/:store',(req,res)=>{
  delete T[req.params.store]; save(); res.json({ok:true});
});

app.get('/health',(_,res)=>res.json({ok:true,uptime:process.uptime()}));

app.listen(PORT,()=>console.log(`\n🚀 AppRadar Server → http://localhost:${PORT}\n`));
