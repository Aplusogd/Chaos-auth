/**
 * A+ CHAOS ID: V142 (RESTORATION)
 * STATUS: PRODUCTION.
 * FIX: Restored /health and /stream routes to fix "System Offline" errors.
 * SECURITY: Master Key Enrollment + Hardcoded Identity.
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

// --- TELEMETRY ---
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
    update: (T_new, profile) => {}
};

// ==========================================
// 1. CORE IDENTITY
// ==========================================
const Users = new Map();
const ADMIN_USER_ID = 'admin-user';

// --- CONFIGURATION ---
const MASTER_KEY = process.env.MASTER_KEY || "chaos-genesis";
let ADMIN_PW_HASH = process.env.ADMIN_PW_HASH || bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'chaos2025', 12);
let adminSession = new Map();

// --- KEY #1 (DESKTOP) ---
const DESKTOP_ID = "cWtBQ3Buc1ZnN2g2QlNGRlRjVGV6QQ";
const DESKTOP_KEY = "pQECAyYgASFYIHB_wbSVKRbTQgp7v4MEHhUa-GsFUzMQV49jJ1w8OvsqIlggFwXFALOUUKlfasQOhh3rSNG3zT3jVjiJA4ITr7u5uv0";

// INIT KEYRING
const adminData = {
    id: ADMIN_USER_ID,
    credentials: [], 
    dreamProfile: { window: [], sum_T: 0, sum_T2: 0 }
};

try {
    adminData.credentials.push({
        credentialID: toBuffer(DESKTOP_ID),
        credentialID_String: DESKTOP_ID,
        credentialPublicKey: new Uint8Array(toBuffer(DESKTOP_KEY)),
        counter: 0
    });
    Users.set(ADMIN_USER_ID, adminData);
    console.log(">>> [SYSTEM] DESKTOP KEY LOADED.");
} catch(e) { console.error("Key Load Error", e); }

const Abyss = { partners: new Map(), agents: new Map(), feedback: [], hash: (k) => crypto.createHash('sha256').update(k).digest('hex') };
Abyss.partners.set(Abyss.hash('sk_chaos_public_beta'), { company: 'Public Dev', plan: 'BETA', usage: 0, limit: 5000, active: true });
Abyss.agents.set('DEMO_AGENT_V1', { id: 'DEMO_AGENT_V1', usage: 0, limit: 500 });
Abyss.sessions = new Map();

const Nightmare = { guardSaaS: (req, res, next) => next() };
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

// --- HEALTH CHECK (VITAL FOR CLIENT) ---
app.get('/api/v1/health', (req, res) => res.json({ status: "ALIVE", timestamp: Date.now() }));

// --- LIVE WIRE ---
app.get('/api/v1/stream', adminGuard, (req, res) => {
    LiveWire.addClient(req, res);
    Telemetry.log('SYSTEM', 'Admin Connected to War Room');
});

// AUTH
app.get('/api/v1/auth/register-options', async (req, res) => {
    const authHeader = req.headers['x-chaos-master-key'];
    if (authHeader !== MASTER_KEY) return res.status(403).json({ error: "ACCESS DENIED" });

    try {
        const options = await generateRegistrationOptions({
            rpName: 'A+ Chaos ID', rpID: getRpId(req), userID: new Uint8Array(Buffer.from(ADMIN_USER_ID)), userName: 'admin@aplus.com',
            attestationType: 'none', authenticatorSelection: { residentKey: 'required', userVerification: 'preferred', authenticatorAttachment: 'platform' },
        });
        Challenges.set(ADMIN_USER_ID, options.challenge);
        res.json(options);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/v1/auth/register-verify', async (req, res) => {
    const authHeader = req.headers['x-chaos-master-key'];
    if (authHeader !== MASTER_KEY) return res.status(403).json({ error: "ACCESS DENIED" });

    const clientResponse = req.body;
    const expectedChallenge = Challenges.get(ADMIN_USER_ID);
    if (!expectedChallenge) return res.status(400).json({ error: "Expired" });

    try {
        const verification = await verifyRegistrationResponse({ response: clientResponse, expectedChallenge, expectedOrigin: getOrigin(req), expectedRPID: getRpId(req) });
        if (verification.verified) {
            const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
            const user = Users.get(ADMIN_USER_ID);
            
            user.credentials.push({
                credentialID: credentialID,
                credentialID_String: toBase64(credentialID),
                credentialPublicKey: credentialPublicKey,
                counter: counter
            });
            Users.set(ADMIN_USER_ID, user);
            Challenges.delete(ADMIN_USER_ID);
            
            Telemetry.log('AUTH', 'New Device Added to Keyring');
            res.json({ verified: true, env_ID: toBase64(credentialID), env_KEY: toBase64(credentialPublicKey) });
        } else { res.status(400).json({ verified: false }); }
    } catch (e) { res.status(400).json({ error: e.message }); }
});

app.get('/api/v1/auth/login-options', async (req, res) => {
    const user = Users.get(ADMIN_USER_ID);
    if (!user) return res.status(404).json({ error: "NO IDENTITY" });
    try {
        const allowed = user.credentials.map(c => ({ id: c.credentialID, type: 'public-key' }));
        const options = await generateAuthenticationOptions({ rpID: getRpId(req), allowCredentials: allowed, userVerification: 'preferred' });
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
    if (!DreamsEngine.check(durationMs, kineticData)) {
         Challenges.delete(challengeString);
         Telemetry.log('BLOCK', 'Bot Detected');
         return res.status(403).json({ verified: false, error: "BOT DETECTED" });
    }
    
    // Find Matching Key
    const credIDBuffer = toBuffer(req.body.id);
    const match = user.credentials.find(c => Buffer.compare(c.credentialID, credIDBuffer) === 0);
    if (!match) return res.status(400).json({ error: "Unknown Device" });

    try {
        const verification = await verifyAuthenticationResponse({
            response: req.body, expectedChallenge: challengeString, expectedOrigin: getOrigin(req), expectedRPID: getRpId(req),
            authenticator: { credentialID: match.credentialID, credentialPublicKey: match.credentialPublicKey, counter: match.counter },
            requireUserVerification: false,
        });

        if (verification.verified) {
            match.counter = verification.authenticationInfo.newCounter;
            Users.set(ADMIN_USER_ID, user); 
            Challenges.delete(challengeString);
            const token = Chaos.mintToken();
            Abyss.sessions.set(token, { user: 'Admin', level: 'High' });
            Telemetry.log('AUTH', 'Login Success');
            res.json({ verified: true, token: token });
        } else { res.status(400).json({ verified: false }); }
    } catch (error) { res.status(400).json({ error: error.message }); } 
});

// --- ADMIN & PUBLIC ROUTES ---
app.post('/admin/login', async (req, res) => {
    const { password } = req.body;
    if (await bcrypt.compare(password, ADMIN_PW_HASH)) {
        const session = crypto.randomBytes(32).toString('hex');
        adminSession.set(session, { timestamp: Date.now() });
        Telemetry.log('ADMIN', 'Portal Login');
        return res.json({ success: true, session });
    }
    res.status(401).json({ error: 'Invalid Credentials' });
});

app.post('/admin/generate-key', adminGuard, async (req, res) => {
    const { tier } = req.body; const key = `sk_chaos_${uuidv4().replace(/-/g, '').slice(0, 32)}`; const hashedKey = Abyss.hash(key);
    Abyss.partners.set(hashedKey, { quota_current: 0, quota_limit: tier === 'Enterprise' ? 99999999 : 5000, tier, company: 'New Partner' });
    Telemetry.log('ADMIN', `Key Generated (${tier})`);
    res.json({ success: true, key, tier });
});

app.get('/admin/partners', adminGuard, (req, res) => { const partners = Array.from(Abyss.partners.entries()).map(([hash, p]) => ({ id: p.company, tier: p.tier, usage: p.quota_current })); res.json({ partners }); });

app.post('/api/v1/public/signup', (req, res) => {
    const { firstName, lastInitial, reason } = req.body;
    if (!firstName || !lastInitial || !reason) return res.status(400).json({ error: "Incomplete" });
    const key = `sk_chaos_${uuidv4().replace(/-/g, '').slice(0, 32)}`;
    const hashedKey = Abyss.hash(key);
    Abyss.partners.set(hashedKey, { company: `${firstName} ${lastInitial}.`, plan: 'Free', usage: 0, limit: 500, active: true, meta: { reason, joined: Date.now() } });
    Telemetry.log('SIGNUP', `User Joined: ${firstName}`);
    res.json({ success: true, key: key, limit: 500 });
});

app.post('/api/v1/public/feedback', (req, res) => { 
    const entry = { id: uuidv4(), name: req.body.name, message: req.body.message, timestamp: Date.now() };
    Abyss.feedback.unshift(entry);
    Telemetry.log('FEEDBACK', 'Msg Recv');
    res.json({ success: true }); 
});
app.get('/api/v1/admin/feedback', adminGuard, (req, res) => { res.json({ feedback: Abyss.feedback }); });

app.post('/api/v1/external/verify', Nightmare.guardSaaS, (req, res) => res.json({ valid: true, quota: { used: req.partner.usage, limit: req.partner.limit } }));
app.get('/api/v1/beta/pulse-demo', (req, res) => { res.json({ valid: true, hash: Chaos.mintToken(), ms: 5 }); });

// TELEMETRY
app.get('/api/v1/admin/telemetry', (req, res) => { res.json({ stats: { requests: Telemetry.requests, threats: Telemetry.blocked }, logs: Telemetry.logs }); });
app.get('/api/v1/admin/profile-stats', (req, res) => res.json({ mu: 200, sigma: 20, cv: 0.1, status: "ACTIVE" }));
app.use('/api/*', (req, res) => res.status(404).json({ error: "API Route Not Found" }));

const serve = (f, res) => fs.existsSync(path.join(publicPath, f)) ? res.sendFile(path.join(publicPath, f)) : res.status(404).send('Missing: ' + f);
app.get('/', (req, res) => serve('index.html', res));
app.get('/app', (req, res) => serve('app.html', res));
app.get('/dashboard', (req, res) => serve('dashboard.html', res));
app.get('/admin', (req, res) => serve('admin.html', res));
app.get('/sdk', (req, res) => serve('sdk.html', res));
app.get('/admin/portal', (req, res) => serve('portal.html', res));
app.get('*', (req, res) => res.redirect('/'));

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V142 (RESTORATION) ONLINE: ${PORT}`));


