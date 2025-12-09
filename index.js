/**
 * A+ CHAOS ID: V132 (THE WAR ROOM)
 * STATUS: PRODUCTION GOLD MASTER.
 * FEATURES:
 * - Active Defense (Ban System)
 * - Kinetic Forensic Replay
 * - Real-Time Heartbeat
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

// --- SECURITY & BLACKLIST ---
const Blacklist = new Set(); // Active Ban List (In-Memory)

// --- LIVE WIRE ENGINE ---
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

// --- TELEMETRY ---
const Telemetry = {
    requests: 0,
    blocked: 0,
    logs: [],
    log: (type, msg, meta = {}) => {
        const entry = `[${type}] ${msg}`;
        Telemetry.logs.unshift(entry);
        if (Telemetry.logs.length > 50) Telemetry.logs.pop();
        if (type === 'BLOCK') Telemetry.blocked++;
        
        // Broadcast with Meta (IP for banning, Path for replay)
        LiveWire.broadcast('log', { entry, meta, stats: { requests: Telemetry.requests, threats: Telemetry.blocked } });
    }
};

// --- MIDDLEWARE ---
app.use((req, res, next) => {
    // 1. Check Blacklist
    const ip = req.headers['x-forwarded-for'] || req.ip;
    if (Blacklist.has(ip)) {
        return res.status(403).json({ error: "ACCESS_TERMINATED_BY_ADMIN" });
    }

    if (!req.path.includes('/api/v1/stream') && !req.path.includes('/health')) {
        Telemetry.requests++;
        if (Telemetry.requests % 5 === 0) LiveWire.broadcast('stats', { requests: Telemetry.requests, threats: Telemetry.blocked });
    }
    next();
});

// --- HELMET & CORS ---
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com", "https://unpkg.com", "https://cdnjs.cloudflare.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https://placehold.co", "https://via.placeholder.com", "https://www.transparenttextures.com"],
            connectSrc: ["'self'", "https://cdn.skypack.dev"],
            upgradeInsecureRequests: [],
        },
    },
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
    strictTransportSecurity: { maxAge: 63072000, includeSubDomains: true, preload: true },
    frameguard: { action: "deny" },
}));

app.use((req, res, next) => {
    const host = req.get('host');
    const targetDomain = 'overthere.ai';
    if (host && (host.includes('localhost') || host.includes('127.0.0.1'))) return next();
    if (host && host !== targetDomain && host !== `www.${targetDomain}`) {
        return res.redirect(301, `https://${targetDomain}${req.originalUrl}`);
    }
    next();
});

app.use(cors({ origin: '*' })); 
app.use(express.json());
app.use(express.static(publicPath, { maxAge: '1h' })); 

// --- UTILITIES ---
const toBuffer = (base64) => Buffer.from(base64, 'base64url');
const toBase64 = (buffer) => Buffer.from(buffer).toString('base64url');
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
    update: (T_new, profile) => {
        const window = profile.window || [];
        if (window.length >= 10) window.shift();
        window.push(T_new);
        profile.window = window;
        
        const n = window.length;
        const mu = window.reduce((a,b)=>a+b, 0) / n;
        const variance = window.reduce((a,b)=>a + Math.pow(b-mu, 2), 0) / n;
        const sigma = Math.sqrt(variance);
        profile.mu = mu; profile.sigma = sigma; profile.cv = sigma / (mu || 1); 
    }
};

// ==========================================
// 1. CORE IDENTITY
// ==========================================
const Users = new Map();
const ADMIN_USER_ID = 'admin-user';
let adminSession = new Map();
let ADMIN_PW_HASH = process.env.ADMIN_PW_HASH || bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'chaos2025', 12);

if (process.env.ADMIN_CRED_ID && process.env.ADMIN_PUB_KEY) {
    try {
        const dna = {
            credentialID: process.env.ADMIN_CRED_ID,
            credentialPublicKey: new Uint8Array(toBuffer(process.env.ADMIN_PUB_KEY)),
            counter: 0,
            dreamProfile: { window: [], sum_T: 0, sum_T2: 0, mu: 0, sigma: 0, cv: 0 } 
        };
        Users.set(ADMIN_USER_ID, dna);
        console.log(">>> [SYSTEM] IDENTITY RESTORED.");
    } catch (e) { console.error("!!! [ERROR] VAULT CORRUPT:", e); }
}

const Abyss = { partners: new Map(), agents: new Map(), feedback: [], hash: (k) => crypto.createHash('sha256').update(k).digest('hex') };
Abyss.partners.set(Abyss.hash('sk_chaos_public_beta'), { company: 'Public Dev', plan: 'BETA', usage: 0, limit: 5000, active: true });
Abyss.agents.set('DEMO_AGENT_V1', { id: 'DEMO_AGENT_V1', usage: 0, limit: 500 });
const Nightmare = { guardSaaS: (req, res, next) => next() }; // Simplified for now
const Chaos = { mintToken: () => crypto.randomBytes(32).toString('hex') };
const Challenges = new Map();
const getOrigin = (req) => `https://${req.headers['x-forwarded-host'] || req.get('host')}`;
const getRpId = (req) => req.get('host').split(':')[0];

const adminGuard = (req, res, next) => {
    const pwSession = req.headers['x-admin-session'];
    const bioToken = req.headers['x-chaos-token'];
    if (pwSession && adminSession.has(pwSession)) return next();
    if (bioToken && Abyss.sessions.has(bioToken)) return next();
    return res.status(401).json({ error: 'Unauthorized. Login Required.' });
};
Abyss.sessions = new Map();

// ==========================================
// 2. ROUTES
// ==========================================
// LIVE WIRE
app.get('/api/v1/stream', adminGuard, (req, res) => {
    LiveWire.addClient(req, res);
    Telemetry.log('SYSTEM', 'Admin Connected to War Room');
});

// BAN HAMMER (New)
app.post('/api/v1/admin/ban', adminGuard, (req, res) => {
    const { ip } = req.body;
    if(ip) {
        Blacklist.add(ip);
        Telemetry.log('BLOCK', `IP BANNED BY ADMIN: ${ip}`);
        return res.json({ success: true });
    }
    res.status(400).json({ error: "No IP" });
});

app.post('/api/v1/auth/reset', (req, res) => { Users.clear(); Telemetry.log('SYSTEM', 'Memory Wiped'); res.json({ success: true }); });

app.get('/api/v1/auth/register-options', async (req, res) => {
    if (Users.has(ADMIN_USER_ID)) { res.setHeader('Content-Type', 'application/json'); return res.status(403).send(JSON.stringify({ error: "SYSTEM LOCKED." })); }
    try {
        const options = await generateRegistrationOptions({ rpName: 'A+ Chaos ID', rpID: getRpId(req), userID: new Uint8Array(Buffer.from(ADMIN_USER_ID)), userName: 'admin@aplus.com', attestationType: 'none', authenticatorSelection: { residentKey: 'required', userVerification: 'preferred', authenticatorAttachment: 'platform' } });
        Challenges.set(ADMIN_USER_ID, options.challenge); res.json(options);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/v1/auth/register-verify', async (req, res) => {
    const clientResponse = req.body;
    const expectedChallenge = Challenges.get(ADMIN_USER_ID);
    if (!expectedChallenge) return res.status(400).json({ error: "Expired" });
    try {
        const verification = await verifyRegistrationResponse({ response: clientResponse, expectedChallenge, expectedOrigin: getOrigin(req), expectedRPID: getRpId(req) });
        if (verification.verified) {
            const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
            const userData = { credentialID: toBase64(credentialID), credentialPublicKey: credentialPublicKey, counter, dreamProfile: { window: [], sum_T: 0, sum_T2: 0, mu: 0, sigma: 0, cv: 0 } };
            Users.set(ADMIN_USER_ID, userData); Challenges.delete(ADMIN_USER_ID); 
            Telemetry.log('AUTH', 'New Identity Registered');
            res.json({ verified: true, env_ID: userData.credentialID, env_KEY: toBase64(credentialPublicKey) });
        } else { res.status(400).json({ verified: false }); }
    } catch (e) { res.status(400).json({ error: e.message }); }
});

app.get('/api/v1/auth/login-options', async (req, res) => {
    const user = Users.get(ADMIN_USER_ID);
    if (!user) return res.status(404).json({ error: "NO IDENTITY" });
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

    const clientIP = req.headers['x-forwarded-for'] || req.ip;

    if (chaosScore < 20) { 
         Challenges.delete(challengeString);
         // Log the IP for Banning
         Telemetry.log('BLOCK', `Bot Detected (Score: ${chaosScore})`, { ip: clientIP });
         return res.status(403).json({ verified: false, error: "BOT DETECTED" });
    }
    
    try {
        const verification = await verifyAuthenticationResponse({ response: req.body, expectedChallenge: challengeString, expectedOrigin: getOrigin(req), expectedRPID: getRpId(req), authenticator: { credentialID: toBuffer(user.credentialID), credentialPublicKey: user.credentialPublicKey, counter: user.counter }, requireUserVerification: false });
        if (verification.verified) {
            DreamsEngine.update(durationMs, user);
            user.counter = verification.authenticationInfo.newCounter; Users.set(ADMIN_USER_ID, user); Challenges.delete(challengeString);
            const token = Chaos.mintToken(); Abyss.sessions.set(token, { user: 'Admin', level: 'High' }); 
            // Broadcast the Path Data for Replay
            Telemetry.log('AUTH', 'Admin Login Successful', { path: kineticData.path, ip: clientIP });
            res.json({ verified: true, token: token, chaos_score: chaosScore });
        } else { res.status(400).json({ verified: false }); }
    } catch (error) { res.status(400).json({ error: error.message }); } 
});

// ADMIN
app.post('/admin/login', async (req, res) => {
    const { password } = req.body;
    if (await bcrypt.compare(password, ADMIN_PW_HASH)) {
        const session = crypto.randomBytes(32).toString('hex'); adminSession.set(session, { timestamp: Date.now() }); Telemetry.log('ADMIN', 'Portal Login'); return res.json({ success: true, session });
    }
    res.status(401).json({ error: 'Invalid Credentials' });
});
app.post('/admin/generate-key', adminGuard, async (req, res) => {
    const { tier } = req.body; const key = `sk_chaos_${uuidv4().replace(/-/g, '').slice(0, 32)}`; const hashedKey = Abyss.hash(key);
    Abyss.partners.set(hashedKey, { quota_current: 0, quota_limit: tier === 'Enterprise' ? 99999999 : (tier === 'Pro' ? 50000 : 5000), tier, company: 'New Partner' });
    Telemetry.log('ADMIN', `Key Generated (${tier})`); res.json({ success: true, key, tier });
});
app.get('/admin/partners', adminGuard, (req, res) => { const partners = Array.from(Abyss.partners.entries()).map(([hash, p]) => ({ id: p.company, tier: p.tier, usage: p.quota_current })); res.json({ partners }); });

app.post('/api/v1/public/signup', (req, res) => {
    const { firstName, lastInitial, reason } = req.body; if (!firstName || !lastInitial || !reason) return res.status(400).json({ error: "Incomplete" });
    const key = `sk_chaos_${uuidv4().replace(/-/g, '').slice(0, 32)}`; const hashedKey = Abyss.hash(key);
    Abyss.partners.set(hashedKey, { company: `${firstName} ${lastInitial}.`, plan: 'Free', usage: 0, limit: 500, active: true, meta: { reason, joined: Date.now() } });
    Telemetry.log('SIGNUP', `User Joined: ${firstName}`); res.json({ success: true, key: key, limit: 500 });
});
app.post('/api/v1/public/feedback', (req, res) => { const entry = { id: uuidv4(), name: req.body.name, message: req.body.message, timestamp: Date.now() }; Abyss.feedback.unshift(entry); Telemetry.log('FEEDBACK', 'New Message'); res.json({ success: true }); });
app.get('/api/v1/admin/feedback', adminGuard, (req, res) => { res.json({ feedback: Abyss.feedback }); });

app.post('/api/v1/external/verify', Nightmare.guardSaaS, (req, res) => res.json({ valid: true, quota: { used: req.partner.usage, limit: req.partner.limit } }));
app.get('/api/v1/beta/pulse-demo', (req, res) => { res.json({ valid: true, hash: Chaos.mintToken(), ms: 5 }); });

// TELEMETRY
app.get('/api/v1/admin/telemetry', (req, res) => { res.json({ stats: { requests: Telemetry.requests, threats: Telemetry.blocked }, logs: Telemetry.logs }); });
app.get('/api/v1/admin/profile-stats', (req, res) => {
    const user = Users.get(ADMIN_USER_ID);
    if (!user || !user.dreamProfile.mu) { res.json({ mu: 0, sigma: 0, cv: 0, status: "LEARNING..." }); } 
    else { res.json({ mu: user.dreamProfile.mu.toFixed(0), sigma: user.dreamProfile.sigma.toFixed(2), cv: user.dreamProfile.cv.toFixed(3), status: "ACTIVE" }); }
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

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V132 (WAR ROOM) ONLINE: ${PORT}`));


