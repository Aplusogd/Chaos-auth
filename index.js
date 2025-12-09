/**
 * A+ CHAOS ID: V133 (PLATINUM CORE)
 * STATUS: PRODUCTION.
 * FEATURES:
 * - Hardcoded Identity Lock (N054...)
 * - DREAMS V4 Kinetic Defense
 * - Live Wire Telemetry (SSE)
 * - Ghost Traffic Filter
 */
import express from 'express';
import path from 'path';
import cors from 'cors';
import fs from 'fs';
import crypto from 'crypto';
import helmet from 'helmet';
import { fileURLToPath } from 'url';
import { dirname } from 'path';     
import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import { EventEmitter } from 'events';
import { 
    generateRegistrationOptions, 
    verifyRegistrationResponse, 
    generateAuthenticationOptions, 
    verifyAuthenticationResponse 
} from '@simplewebauthn/server';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const publicPath = path.join(__dirname, 'public');

const app = express();
const PORT = process.env.PORT || 3000;

// --- 1. LIVE WIRE ENGINE (SSE) ---
let connectedClients = [];
const LiveWire = {
    broadcast: (event, data) => {
        const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
        connectedClients.forEach(client => client.res.write(payload));
    },
    addClient: (req, res) => {
        res.writeHead(200, {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive'
        });
        const clientId = Date.now();
        connectedClients.push({ id: clientId, res });
        req.on('close', () => connectedClients = connectedClients.filter(c => c.id !== clientId));
    }
};

// --- REAL-TIME TELEMETRY ---
const Telemetry = {
    requests: 0,
    blocked: 0,
    logs: [],
    log: (type, msg) => {
        const entry = `[${type}] ${msg}`;
        Telemetry.logs.unshift(entry);
        if (Telemetry.logs.length > 50) Telemetry.logs.pop();
        if (type === 'BLOCK') Telemetry.blocked++;
        LiveWire.broadcast('log', { entry, stats: { requests: Telemetry.requests, threats: Telemetry.blocked } });
    }
};

// --- MIDDLEWARE ---
app.use((req, res, next) => {
    // Ghost Filter: Only count external traffic
    if (!req.path.includes('/api/v1/stream') && !req.path.includes('/health')) {
        Telemetry.requests++;
        if (Telemetry.requests % 5 === 0) LiveWire.broadcast('stats', { requests: Telemetry.requests, threats: Telemetry.blocked });
    }
    next();
});

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdn.tailwindcss.com", "https://unpkg.com", "https://cdnjs.cloudflare.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https://placehold.co", "https://via.placeholder.com", "https://www.transparenttextures.com"],
            connectSrc: ["'self'", "https://cdn.skypack.dev", "https://overthere.ai", "https://chaos-auth-iff2.onrender.com"],
            upgradeInsecureRequests: [],
        },
    },
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
    strictTransportSecurity: { maxAge: 63072000, includeSubDomains: true, preload: true },
    frameguard: { action: "deny" },
}));

app.use(cors({ origin: '*' })); 
app.use(express.json());
app.use(express.static(publicPath, { maxAge: '1h' })); 

// --- UTILITIES ---
const toBuffer = (base64) => Buffer.from(base64, 'base64url');
const toBase64 = (buffer) => Buffer.from(buffer).toString('base64url');
const jsObjectToBuffer = (obj) => {
    if (obj instanceof Uint8Array) return obj;
    if (obj instanceof Buffer) return obj;
    if (typeof obj !== 'object' || obj === null) return new Uint8Array();
    return Buffer.from(Object.values(obj));
};

function extractChallengeFromClientResponse(clientResponse) {
    try {
        const json = Buffer.from(clientResponse.response.clientDataJSON, 'base64url').toString('utf8');
        return JSON.parse(json).challenge;
    } catch (e) { return null; }
}

const DreamsEngine = {
    start: () => process.hrtime.bigint(),
    score: (durationMs, kinetic) => {
        let score = 100;
        if (durationMs < 100) score -= 50; 
        if (kinetic) {
            if (kinetic.velocity > 15.0) score -= 40; 
            if (kinetic.entropy < 0.1) score -= 60;  
        } else { score -= 10; }
        return Math.max(0, score);
    },
    check: (durationMs, kinetic) => {
        const s = DreamsEngine.score(durationMs, kinetic);
        if (s < 20) {
            Telemetry.log('BLOCK', `Bot Detected (Score: ${s})`);
            return false;
        }
        return true; 
    },
    update: (durationMs, user) => {
         const profile = user.dreamProfile;
         if (!profile.window) profile.window = [];
         if (profile.window.length >= 10) profile.window.shift();
         profile.window.push(durationMs);
         const n = profile.window.length;
         const mu = profile.window.reduce((a,b)=>a+b, 0) / n;
         const variance = profile.window.reduce((a,b)=>a + Math.pow(b-mu, 2), 0) / n;
         profile.mu = mu; profile.sigma = Math.sqrt(variance);
    }
};

// ==========================================
// 1. CORE IDENTITY (HARDCODED LOCK)
// ==========================================
const Users = new Map();
const ADMIN_USER_ID = 'admin-user';

// --- YOUR CREDENTIALS ---
const HARDCODED_ID = "N054N1pZTjVwMlI2SXFYVVNHZzA0dw";
const HARDCODED_KEY = "pQECAyYgASFYIOPudmzq6ZKpZnbZK9WmF-vN6mCyDn4T_SPKm8z3xADGIlggTVEIV3nwyJ-qetlCM164vIEQ670GxHhToJopPlhuuAU";

try {
    const dna = {
        credentialID: HARDCODED_ID, // String
        credentialPublicKey: new Uint8Array(toBuffer(HARDCODED_KEY)), // Buffer
        counter: 0,
        dreamProfile: { window: [], sum_T: 0, sum_T2: 0, mu: 0, sigma: 0 }
    };
    Users.set(ADMIN_USER_ID, dna);
    console.log(">>> [SYSTEM] HARDCODED DNA LOCKED.");
} catch (e) { console.error("!!! [ERROR] DNA LOAD FAILED:", e); }

const Abyss = { partners: new Map(), agents: new Map(), feedback: [], hash: (k) => crypto.createHash('sha256').update(k).digest('hex') };
Abyss.partners.set(Abyss.hash('sk_chaos_public_beta'), { company: 'Public Dev', plan: 'BETA', usage: 0, limit: 5000, active: true });
Abyss.agents.set('DEMO_AGENT_V1', { id: 'DEMO_AGENT_V1', usage: 0, limit: 500 });
Abyss.sessions = new Map();

const Nightmare = { 
    guardSaaS: (req, res, next) => {
        const rawKey = req.get('X-CHAOS-API-KEY');
        if (!rawKey) return res.status(401).json({ error: "MISSING_KEY" });
        const partner = Abyss.partners.get(Abyss.hash(rawKey));
        if (!partner) return res.status(403).json({ error: "INVALID_KEY" });
        if (partner.usage >= partner.limit) return res.status(429).json({ error: "QUOTA_EXCEEDED" });
        partner.usage++;
        next();
    }
};

const Chaos = { mintToken: () => crypto.randomBytes(32).toString('hex') };
const Challenges = new Map();

const getOrigin = (req) => {
    const host = req.get('host');
    if (host && host.includes('overthere.ai')) return 'https://overthere.ai';
    return `https://${req.headers['x-forwarded-host'] || host}`;
};
const getRpId = (req) => {
    const host = req.get('host');
    if (host && host.includes('overthere.ai')) return 'overthere.ai';
    return host ? host.split(':')[0] : 'localhost';
};

let ADMIN_PW_HASH = process.env.ADMIN_PW_HASH || bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'chaos2025', 12);
let adminSession = new Map();
const adminGuard = (req, res, next) => {
    const pwSession = req.headers['x-admin-session'];
    const bioToken = req.headers['x-chaos-token'];
    if (pwSession && adminSession.has(pwSession)) return next();
    if (bioToken && Abyss.sessions.has(bioToken)) return next();
    return res.status(401).json({ error: 'Unauthorized.' });
};

// ==========================================
// 2. ROUTES
// ==========================================

// --- LIVE WIRE ---
app.get('/api/v1/stream', adminGuard, (req, res) => {
    LiveWire.addClient(req, res);
    Telemetry.log('SYSTEM', 'Admin Connected to War Room');
});

// AUTH
app.post('/api/v1/auth/reset', (req, res) => res.status(403).json({ error: "HARDCODED MODE: RESET DISABLED" }));
app.get('/api/v1/auth/register-options', (req, res) => res.status(403).json({ error: "LOCKED" }));
app.post('/api/v1/auth/register-verify', (req, res) => res.status(403).json({ error: "LOCKED" }));

app.get('/api/v1/auth/login-options', async (req, res) => {
    const user = Users.get(ADMIN_USER_ID);
    if (!user) return res.status(404).json({ error: "CRITICAL: KEY MISSING" });
    try {
        const options = await generateAuthenticationOptions({ rpID: getRpId(req), allowCredentials: [], userVerification: 'preferred' });
        Challenges.set(options.challenge, { challenge: options.challenge, startTime: DreamsEngine.start() });
        res.json(options);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/v1/auth/login-verify', async (req, res) => {
    const user = Users.get(ADMIN_USER_ID);
    let challengeString;
    try { const json = Buffer.from(req.body.response.clientDataJSON, 'base64url').toString('utf8'); challengeString = JSON.parse(json).challenge; } catch(e) { return res.status(400).json({error: "Bad Payload"}); }
    const challengeData = Challenges.get(challengeString); 
    if (!user || !challengeData) return res.status(400).json({ error: "Invalid State" });
    
    const durationMs = Number(process.hrtime.bigint() - challengeData.startTime) / 1000000;
    const kineticData = req.body.kinetic_data;
    const chaosScore = DreamsEngine.score(durationMs, kineticData);

    if (chaosScore < 20) { 
         Challenges.delete(challengeString);
         Telemetry.log('BLOCK', `Bot Detected (Score: ${chaosScore})`);
         return res.status(403).json({ verified: false, error: "BOT DETECTED" });
    }
    
    try {
        const verification = await verifyAuthenticationResponse({
            response: req.body, expectedChallenge: challengeString, expectedOrigin: getOrigin(req), expectedRPID: getRpId(req),
            authenticator: { credentialID: toBuffer(user.credentialID), credentialPublicKey: user.credentialPublicKey, counter: user.counter }, requireUserVerification: false
        });
        if (verification.verified) {
            DreamsEngine.update(durationMs, user);
            user.counter = verification.authenticationInfo.newCounter; Users.set(ADMIN_USER_ID, user); Challenges.delete(challengeString);
            const token = Chaos.mintToken(); Abyss.sessions.set(token, { user: 'Admin', level: 'High' }); 
            Telemetry.log('AUTH', 'Admin Login Successful');
            res.json({ verified: true, token: token, chaos_score: chaosScore });
        } else { res.status(400).json({ verified: false }); }
    } catch (error) { res.status(400).json({ error: error.message }); } 
});

// ADMIN & PUBLIC
app.post('/admin/login', async (req, res) => {
    const { password } = req.body;
    if (await bcrypt.compare(password, ADMIN_PW_HASH)) {
        const session = crypto.randomBytes(32).toString('hex'); adminSession.set(session, { timestamp: Date.now() }); Telemetry.log('ADMIN', 'Portal Login'); return res.json({ success: true, session });
    }
    res.status(401).json({ error: 'Invalid Credentials' });
});
app.post('/admin/generate-key', adminGuard, async (req, res) => {
    const { tier } = req.body; const key = `sk_chaos_${uuidv4().replace(/-/g, '').slice(0, 32)}`; const hashedKey = Abyss.hash(key);
    Abyss.partners.set(hashedKey, { quota_current: 0, quota_limit: tier === 'Enterprise' ? 99999999 : 5000, tier, company: 'New Partner' });
    Telemetry.log('ADMIN', `Key Generated (${tier})`); res.json({ success: true, key, tier });
});
app.get('/admin/partners', adminGuard, (req, res) => { const partners = Array.from(Abyss.partners.entries()).map(([hash, p]) => ({ id: p.company, tier: p.tier, usage: p.quota_current })); res.json({ partners }); });
app.post('/api/v1/public/signup', (req, res) => {
    const { firstName, lastInitial, reason } = req.body; const key = `sk_chaos_${uuidv4().replace(/-/g, '').slice(0, 32)}`; const hashedKey = Abyss.hash(key);
    Abyss.partners.set(hashedKey, { company: `${firstName} ${lastInitial}.`, plan: 'Free', usage: 0, limit: 500, active: true });
    Telemetry.log('SIGNUP', `User: ${firstName}`); res.json({ success: true, key });
});
app.post('/api/v1/public/feedback', (req, res) => { const entry = { id: uuidv4(), name: req.body.name, message: req.body.message, timestamp: Date.now() }; Abyss.feedback.unshift(entry); Telemetry.log('FEEDBACK', 'Msg Recv'); res.json({ success: true }); });
app.get('/api/v1/admin/feedback', adminGuard, (req, res) => { res.json({ feedback: Abyss.feedback }); });
app.post('/api/v1/external/verify', Nightmare.guardSaaS, (req, res) => res.json({ valid: true, quota: { used: req.partner.usage, limit: req.partner.limit } }));
app.get('/api/v1/beta/pulse-demo', (req, res) => { res.json({ valid: true, hash: Chaos.mintToken(), ms: 5 }); });

// TELEMETRY
app.get('/api/v1/admin/telemetry', (req, res) => { res.json({ stats: { requests: Telemetry.requests, threats: Telemetry.blocked }, logs: Telemetry.logs }); });
app.get('/api/v1/admin/profile-stats', (req, res) => {
    const user = Users.get(ADMIN_USER_ID);
    if (!user || !user.dreamProfile.mu) res.json({ mu: 0, sigma: 0, cv: 0, status: "LEARNING..." });
    else res.json({ mu: user.dreamProfile.mu.toFixed(0), sigma: user.dreamProfile.sigma.toFixed(2), cv: user.dreamProfile.cv.toFixed(3), status: "ACTIVE" });
});
app.get('/api/v1/health', (req, res) => res.json({ status: "ALIVE" }));
app.use('/api/*', (req, res) => res.status(404).json({ error: "API Route Not Found" }));

const serve = (f, res) => fs.existsSync(path.join(publicPath, f)) ? res.sendFile(path.join(publicPath, f)) : res.status(404).send('Missing: ' + f);
app.get('/', (req, res) => serve('index.html', res));
app.get('/app', (req, res) => serve('app.html', res));
app.get('/dashboard', (req, res) => serve('dashboard.html', res));
app.get('/admin', (req, res) => serve('admin.html', res));
app.get('/sdk', (req, res) => serve('sdk.html', res));
app.get('/admin/portal', (req, res) => serve('portal.html', res));
app.get('*', (req, res) => res.redirect('/'));

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V133 (PLATINUM CORE) ONLINE: ${PORT}`));
