/**
 * A+ CHAOS ID: V145 (THE ARCHITECT)
 * STATUS: PRODUCTION FINAL
 * SYSTEM:
 * - ROOT (/): Public Landing Page (Marketing)
 * - APP (/app): Biometric Gate (Security)
 * - API: Chaos Core V144 Logic (Zombie Mode + Hardcoded DNA)
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

// --- 1. ZOMBIE MODE (PREVENT CRASHES) ---
process.on('uncaughtException', (err) => console.error('>>> [CRITICAL] STAYING ALIVE:', err));
process.on('unhandledRejection', (r) => console.error('>>> [REJECT] STAYING ALIVE:', r));

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const publicPath = path.join(__dirname, 'public');

const app = express();
const PORT = process.env.PORT || 3000;
const MASTER_KEY = process.env.MASTER_KEY || "chaos-genesis";

// --- 2. UTILS (TYPE SAFE) ---
const toBuffer = (base64) => { 
    try { return Buffer.from(base64, 'base64url'); } 
    catch (e) { return Buffer.alloc(0); } 
};
const toBase64 = (buffer) => {
    if (typeof buffer === 'string') return buffer;
    return Buffer.from(buffer).toString('base64url');
};

// --- 3. IMMORTAL IDENTITY (YOUR PHONE) ---
const Users = new Map();
const ADMIN_USER_ID = 'admin-user';
const Challenges = new Map();
const Sessions = new Map();

const PERMANENT_ID = "cWtBQ3Buc1ZnN2g2QlNGRlRjVGV6QQ";
const PERMANENT_KEY = "pQECAyYgASFYIHB_wbSVKRbTQgp7v4MEHhUa-GsFUzMQV49jJ1w8OvsqIlggFwXFALOUUKlfasQOhh3rSNG3zT3jVjiJA4ITr7u5uv0";

// Load Identity on Wake Up
try {
    Users.set(ADMIN_USER_ID, {
        id: ADMIN_USER_ID,
        credentials: [{ credentialID: toBuffer(PERMANENT_ID), credentialPublicKey: toBuffer(PERMANENT_KEY), counter: 0 }]
    });
    console.log(">>> [SYSTEM] IMMORTAL IDENTITY ACTIVE.");
} catch (e) { 
    console.log(">>> [WARN] IDENTITY LOAD ERROR (Running Empty)."); 
    Users.set(ADMIN_USER_ID, { id: ADMIN_USER_ID, credentials: [] }); 
}

// Security State (Starts LOCKED if identity exists)
let REGISTRATION_LOCKED = true;
let GATE_UNLOCK_TIMER = null;

// --- 4. MIDDLEWARE (ALLOW LANDING PAGE SCRIPTS) ---
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            // Allow inline scripts/styles for the fancy landing page animations
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdn.tailwindcss.com", "https://unpkg.com", "https://cdnjs.cloudflare.com"],
            scriptSrcAttr: ["'self'", "'unsafe-inline'"], 
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https://placehold.co"],
            connectSrc: ["'self'", "https://overthere.ai", "https://chaos-auth-iff2.onrender.com"],
            upgradeInsecureRequests: [],
        },
    },
}));
app.use(cors({ origin: '*' })); 
app.use(express.json());
app.use(express.static(publicPath)); // SERVE PUBLIC FOLDER

// --- 5. LIVE WIRE (SSE) ---
let connectedClients = [];
const LiveWire = {
    broadcast: (event, data) => { try { connectedClients.forEach(c => c.res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)); } catch(e){} },
    addClient: (req, res) => { res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive' }); connectedClients.push({ id: Date.now(), res }); }
};

const Telemetry = {
    log: (type, msg) => { console.log(`[${type}] ${msg}`); LiveWire.broadcast('log', { entry: `[${type}] ${msg}` }); }
};

const getOrigin = (req) => `https://${req.headers['x-forwarded-host'] || req.get('host')}`;
const getRpId = (req) => (req.headers['x-forwarded-host'] || req.get('host')).split(':')[0];

// ==========================================
// 6. ROUTES
// ==========================================

// --- PUBLIC DEMO ROUTES (For Landing Page) ---
app.get('/api/v1/beta/pulse-demo', (req, res) => {
    // Returns dummy data for the benchmark button
    res.json({ valid: true, hash: crypto.randomBytes(4).toString('hex'), ms: Math.floor(Math.random() * 20) + 5 });
});
app.post('/api/v1/public/signup', (req, res) => {
    Telemetry.log('SIGNUP', `Beta Interest: ${req.body.firstName || 'User'}`);
    res.json({ success: true, key: "demo_key_" + Date.now() });
});
app.post('/api/v1/external/verify', (req, res) => res.json({ valid: true, quota: {used: 50, limit: 500} }));

// --- AUTH: REGISTER ---
app.get('/api/v1/auth/register-options', async (req, res) => {
    const key = req.headers['x-chaos-master-key'];
    // Allow if Master Key used OR Gate is Unlocked
    if((key !== MASTER_KEY) && REGISTRATION_LOCKED) {
        Telemetry.log('BLOCK', 'Registration Locked');
        return res.status(403).json({ error: "LOCKED" });
    }
    try {
        const o = await generateRegistrationOptions({
            rpName: 'A+ Chaos', rpID: getRpId(req), userID: new Uint8Array(Buffer.from(ADMIN_USER_ID)), userName: 'admin',
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
            // Ensure ID is stored as Buffer
            const newCred = { ...v.registrationInfo, credentialID: toBuffer(toBase64(v.registrationInfo.credentialID)) };
            
            const exists = u.credentials.find(c => toBase64(c.credentialID) === toBase64(newCred.credentialID));
            if(!exists) { 
                u.credentials.push(newCred); 
                Users.set(ADMIN_USER_ID, u); 
                Telemetry.log('AUTH', 'New Device Registered');
                REGISTRATION_LOCKED=true; // Auto-Lock
            }
            res.json({verified:true});
        } else res.status(400).json({verified:false});
    } catch(e) { res.status(400).json({error:e.message}); }
});

// --- AUTH: LOGIN ---
app.get('/api/v1/auth/login-options', async (req, res) => {
    const u = Users.get(ADMIN_USER_ID);
    if(!u || u.credentials.length===0) return res.status(404).json({error:"NO ID"});
    
    // Type-Safe Conversion for Library
    const allowed = u.credentials.map(c => ({ id: toBase64(c.credentialID), type: 'public-key' }));
    
    const o = await generateAuthenticationOptions({ rpID: getRpId(req), allowCredentials: allowed, userVerification:'preferred' });
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
        
        const v = await verifyAuthenticationResponse({ 
            response: req.body, expectedChallenge: chal, expectedOrigin: getOrigin(req), expectedRPID: getRpId(req), 
            authenticator: match, requireUserVerification: false 
        });
        if(v.verified) {
            match.counter = v.authenticationInfo.newCounter;
            Users.set(ADMIN_USER_ID, u);
            const t = crypto.randomBytes(32).toString('hex');
            Sessions.set(t, true); // Create Session
            Telemetry.log('AUTH', 'Login Successful');
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
    Telemetry.log('SECURITY', 'GATE UNLOCKED (30s)');
    res.json({success:true, message:"UNLOCKED 30s"});
});

// --- SYSTEM ---
app.get('/api/v1/health', (req, res) => res.json({ status: "ALIVE" }));
app.get('/api/v1/stream', (req,res) => LiveWire.addClient(req,res));

// --- FILE SERVING (RESTORED) ---
const serve = (f, res) => fs.existsSync(path.join(publicPath, f)) ? res.sendFile(path.join(publicPath, f)) : res.status(404).send('Missing: ' + f);

app.get('/', (req, res) => serve('index.html', res));
app.get('/app', (req, res) => serve('app.html', res));
app.get('/dashboard', (req, res) => serve('dashboard.html', res));
app.get('*', (req, res) => res.redirect('/'));

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V145 ONLINE (THE ARCHITECT)`));
