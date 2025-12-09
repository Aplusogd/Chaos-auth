/**
 * A+ CHAOS ID: V150 (SILENT RUNNING)
 * STATUS: PRODUCTION
 * CONFIG: Web-Only. Telegram features removed.
 * MODULES: Auth, Zombie Mode, Black Box, Dreams V5, Overwatch, KeyForge.
 */
import express from 'express';
import path from 'path';
import cors from 'cors';
import fs from 'fs';
import crypto from 'crypto';
import helmet from 'helmet';
import { fileURLToPath } from 'url';
import { dirname } from 'path';     
import { 
    generateRegistrationOptions, 
    verifyRegistrationResponse, 
    generateAuthenticationOptions, 
    verifyAuthenticationResponse 
} from '@simplewebauthn/server';

// --- ZOMBIE PROTOCOL ---
process.on('uncaughtException', (err) => console.error('>>> [SECURE LOG] ERROR', err.message));
process.on('unhandledRejection', (r) => console.error('>>> [SECURE LOG] REJECT', r));

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const publicPath = path.join(__dirname, 'public');

const app = express();
const PORT = process.env.PORT || 3000;

// --- SECRETS VAULT ---
const MASTER_KEY = process.env.MASTER_KEY || "chaos-genesis";
const PERMANENT_ID = process.env.ADMIN_CRED_ID;
const PERMANENT_KEY = process.env.ADMIN_PUB_KEY;

// --- UTILS ---
const toBuffer = (base64) => { try { return Buffer.from(base64, 'base64url'); } catch (e) { return Buffer.alloc(0); } };
const toBase64 = (buffer) => { if (typeof buffer === 'string') return buffer; return Buffer.from(buffer).toString('base64url'); };

// --- DATA STORE ---
const Users = new Map();
const ADMIN_USER_ID = 'admin-user';
const Challenges = new Map();
const Sessions = new Map();
const ApiKeys = new Map();
const TelemetryData = { requests: 0, blocked: 0, logs: [] };

// --- DNA LOADING ---
if (PERMANENT_ID && PERMANENT_KEY) {
    try {
        Users.set(ADMIN_USER_ID, {
            id: ADMIN_USER_ID,
            credentials: [{ credentialID: toBuffer(PERMANENT_ID), credentialPublicKey: toBuffer(PERMANENT_KEY), counter: 0 }]
        });
        console.log(">>> [SYSTEM] IDENTITY LOADED.");
    } catch (e) { console.log(">>> [WARN] VAULT ERROR."); }
} else {
    Users.set(ADMIN_USER_ID, { id: ADMIN_USER_ID, credentials: [] });
    console.log(">>> [WARN] RUNNING EMPTY.");
}

let REGISTRATION_LOCKED = true;
let GATE_UNLOCK_TIMER = null;

// --- MIDDLEWARE ---
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*' })); 
app.use(express.json());
app.use(express.static(publicPath));

// --- LIVE WIRE (SSE) ---
let connectedClients = [];
const LiveWire = {
    broadcast: (event, data) => { try { connectedClients.forEach(c => c.res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)); } catch(e){} },
    addClient: (req, res) => { res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive' }); connectedClients.push({ id: Date.now(), res }); }
};

const Telemetry = {
    log: (type, msg) => { 
        console.log(`[${type}] ${msg}`); 
        const entry = `[${type}] ${msg}`;
        
        // Update Internal Storage
        TelemetryData.logs.unshift(entry);
        if(TelemetryData.logs.length > 50) TelemetryData.logs.pop();
        if(type === 'BLOCK') TelemetryData.blocked++;
        TelemetryData.requests++;

        // Broadcast to Overwatch
        LiveWire.broadcast('log', { entry, stats: { requests: TelemetryData.requests, threats: TelemetryData.blocked } }); 
    }
};

const getOrigin = (req) => `https://${req.headers['x-forwarded-host'] || req.get('host')}`;
const getRpId = (req) => (req.headers['x-forwarded-host'] || req.get('host')).split(':')[0];

// ==========================================
// ROUTES
// ==========================================

// --- DREAMS V5.1: DIAGNOSTIC ---
app.post('/api/v1/hardware/diagnostic', (req, res) => {
    const { deviceId, variance } = req.body;
    
    // Log High Variance (Grinding Noise)
    if (variance > 120) {
        Telemetry.log('HARDWARE', `High Acoustic Variance (${variance.toFixed(0)}) on ${deviceId}`);
        return res.json({ status: "WARNING" });
    }
    
    res.json({ status: "OPTIMAL" });
});

// --- OVERWATCH API ---
app.get('/api/v1/admin/telemetry', (req, res) => {
    res.json({ stats: { requests: TelemetryData.requests, threats: TelemetryData.blocked }, logs: TelemetryData.logs });
});

// --- KEYFORGE API ---
app.post('/api/v1/admin/generate-key', (req, res) => {
    if(!Sessions.has(req.headers['x-chaos-token'])) return res.status(401).json({ error: "UNAUTHORIZED" });
    const { tier, clientName } = req.body;
    const newKey = `sk_chaos_${crypto.randomBytes(16).toString('hex')}`;
    ApiKeys.set(newKey, { tier, client: clientName, created: Date.now() });
    Telemetry.log('KEYFORGE', `New Key: ${clientName}`);
    res.json({ success: true, key: newKey });
});

// --- AUTH: REGISTER ---
app.get('/api/v1/auth/register-options', async (req, res) => {
    const key = req.headers['x-chaos-master-key'];
    if((key !== MASTER_KEY) && REGISTRATION_LOCKED) {
        Telemetry.log('BLOCK', 'Reg Locked');
        return res.status(403).json({ error: "LOCKED" });
    }
    try {
        const o = await generateRegistrationOptions({
            rpName: 'Chaos', rpID: getRpId(req), userID: new Uint8Array(Buffer.from(ADMIN_USER_ID)), userName: 'admin',
            attestationType: 'none', authenticatorSelection: { residentKey: 'required', userVerification: 'preferred', authenticatorAttachment: 'platform' },
        });
        Challenges.set(ADMIN_USER_ID, o.challenge);
        res.json(o);
    } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/api/v1/auth/register-verify', async (req, res) => {
    if((req.headers['x-chaos-master-key'] !== MASTER_KEY) && REGISTRATION_LOCKED) return res.status(403).json({ error: "LOCKED" });
    try {
        const v = await verifyRegistrationResponse({ response: req.body, expectedChallenge: Challenges.get(ADMIN_USER_ID), expectedOrigin: getOrigin(req), expectedRPID: getRpId(req) });
        if(v.verified) {
            const u = Users.get(ADMIN_USER_ID);
            const newCred = { ...v.registrationInfo, credentialID: toBuffer(toBase64(v.registrationInfo.credentialID)) };
            const exists = u.credentials.find(c => toBase64(c.credentialID) === toBase64(newCred.credentialID));
            if(!exists) { 
                u.credentials.push(newCred); 
                Users.set(ADMIN_USER_ID, u); 
                REGISTRATION_LOCKED=true; 
                Telemetry.log('AUTH', 'Device Added');
            }
            res.json({verified:true});
        } else res.status(400).json({verified:false});
    } catch(e) { res.status(400).json({error:e.message}); }
});

// --- AUTH: LOGIN ---
app.get('/api/v1/auth/login-options', async (req, res) => {
    const u = Users.get(ADMIN_USER_ID);
    if(!u || u.credentials.length===0) return res.status(404).json({error:"NO ID"});
    const o = await generateAuthenticationOptions({ rpID: getRpId(req), allowCredentials: u.credentials.map(c=>({id:toBase64(c.credentialID), type:'public-key'})), userVerification:'preferred' });
    Challenges.set(o.challenge, {challenge:o.challenge});
    res.json(o);
});

app.post('/api/v1/auth/login-verify', async (req, res) => {
    try {
        const json = Buffer.from(req.body.response.clientDataJSON, 'base64url').toString('utf8');
        const chal = JSON.parse(json).challenge;
        if(!Challenges.has(chal)) return res.status(400).json({error:"Bad Challenge"});
        
        const u = Users.get(ADMIN_USER_ID);
        const match = u.credentials.find(c => toBase64(c.credentialID) === req.body.id);
        if(!match) return res.status(400).json({error:"Device Not Found"});
        
        const v = await verifyAuthenticationResponse({ response: req.body, expectedChallenge: chal, expectedOrigin: getOrigin(req), expectedRPID: getRpId(req), authenticator: match, requireUserVerification: false });
        if(v.verified) {
            match.counter = v.authenticationInfo.newCounter;
            Users.set(ADMIN_USER_ID, u);
            const t = crypto.randomBytes(32).toString('hex');
            Sessions.set(t, true);
            Telemetry.log('AUTH', 'Login Success');
            res.json({verified:true, token:t});
        } else res.status(400).json({verified:false});
    } catch(e) { res.status(500).json({error:e.message}); }
});

// --- GATE UNLOCK ---
app.post('/api/v1/auth/unlock-gate', (req, res) => {
    if(!Sessions.has(req.headers['x-chaos-token'])) return res.status(401).json({error:"Login First"});
    REGISTRATION_LOCKED = false;
    if(GATE_UNLOCK_TIMER) clearTimeout(GATE_UNLOCK_TIMER);
    GATE_UNLOCK_TIMER = setTimeout(()=>REGISTRATION_LOCKED=true, 30000);
    Telemetry.log('SECURITY', 'Gate Unlocked');
    res.json({success:true, message:"GATE OPEN"});
});

// --- PUBLIC/DEMO ---
app.get('/api/v1/beta/pulse-demo', (req, res) => {
    res.json({ valid: true, hash: crypto.randomBytes(32).toString('hex'), ms: Math.floor(Math.random() * 15) + 5 });
});
app.post('/api/v1/public/signup', (req, res) => res.json({ success: true }));
app.post('/api/v1/external/verify', (req, res) => res.json({ valid: true }));
app.get('/api/v1/health', (req, res) => res.json({ status: "ALIVE" }));
app.get('/api/v1/stream', (req,res) => LiveWire.addClient(req,res));

// --- FILES ---
const serve = (f, res) => fs.existsSync(path.join(publicPath, f)) ? res.sendFile(path.join(publicPath, f)) : res.status(404).send('Missing: ' + f);
app.get('/', (req, res) => serve('index.html', res));
app.get('/app', (req, res) => serve('app.html', res));
app.get('/dashboard', (req, res) => serve('dashboard.html', res));
app.get('*', (req, res) => res.redirect('/'));

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V150 ONLINE (SILENT)`));
