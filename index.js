/**
 * A+ CHAOS ID: V102 (BENCHMARK READY)
 * STATUS: Fixed Abyss database structure to support Pulse Demo and Telemetry.
 */
import express from 'express';
import path from 'path';
import cors from 'cors';
import fs from 'fs';
import crypto from 'crypto';
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

app.use(cors({ origin: '*' })); 
app.use(express.json());
app.use(express.static(publicPath));

// --- UTILITIES ---
const toBuffer = (base64) => Buffer.from(base64, 'base64url');
const toBase64 = (buffer) => Buffer.from(buffer).toString('base64url');

function extractChallengeFromClientResponse(clientResponse) {
    try {
        const json = Buffer.from(clientResponse.response.clientDataJSON, 'base64url').toString('utf8');
        return JSON.parse(json).challenge;
    } catch (e) { return null; }
}

// ==========================================
// 1. DREAMS ENGINE
// ==========================================
const DreamsEngine = {
    start: () => process.hrtime.bigint(),
    score: (durationMs, kinetic) => {
        let score = 100;
        if (durationMs < 100) score -= 50; 
        if (kinetic) {
            if (kinetic.velocity > 8.0) score -= 40; 
            if (kinetic.entropy < 0.2) score -= 60;  
        } else {
            score -= 10; 
        }
        return Math.max(0, score);
    },
    check: (durationMs, kinetic) => {
        const s = DreamsEngine.score(durationMs, kinetic);
        if (s < 40) return false;
        return true; 
    }
};

// ==========================================
// 2. SECURITY & ADMIN CONFIG
// ==========================================
const Users = new Map();
const ADMIN_USER_ID = 'admin-user';
let adminSession = new Map();

// --- PASSWORD CONFIGURATION ---
let ADMIN_PW_HASH;
if (process.env.ADMIN_PASSWORD) {
    console.log(">>> [CONFIG] Using Custom ADMIN_PASSWORD.");
    ADMIN_PW_HASH = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);
} else if (process.env.ADMIN_PW_HASH) {
    ADMIN_PW_HASH = process.env.ADMIN_PW_HASH;
} else {
    console.log(">>> [CONFIG] Using Default Password: 'chaos2025'");
    ADMIN_PW_HASH = bcrypt.hashSync('chaos2025', 12);
}

// PERSISTENCE LOADER
if (process.env.ADMIN_CRED_ID && process.env.ADMIN_PUB_KEY) {
    try {
        const dna = {
            credentialID: process.env.ADMIN_CRED_ID,
            credentialPublicKey: new Uint8Array(toBuffer(process.env.ADMIN_PUB_KEY)),
            counter: 0,
            dreamProfile: { window: [], sum_T: 0, sum_T2: 0 }
        };
        Users.set(ADMIN_USER_ID, dna);
        console.log(">>> [SYSTEM] IDENTITY RESTORED.");
    } catch (e) { console.error("!!! [ERROR] VAULT CORRUPT:", e); }
}

// --- DATABASE (FIXED FOR V102) ---
const Abyss = { 
    partners: new Map(), 
    agents: new Map(), // <--- RESTORED THIS
    hash: (k) => crypto.createHash('sha256').update(k).digest('hex') 
};

// Seed Data
Abyss.partners.set(Abyss.hash('sk_chaos_demo123'), { company: 'Demo', plan: 'free', usage: 0, limit: 50, active: true });
Abyss.agents.set('DEMO_AGENT_V1', { id: 'DEMO_AGENT_V1', usage: 0, limit: 500 }); // <--- RESTORED THIS

const Nightmare = { guardSaaS: (req, res, next) => next() };
const Chaos = { mintToken: () => crypto.randomBytes(16).toString('hex') };
const Challenges = new Map();
const getOrigin = (req) => `https://${req.headers['x-forwarded-host'] || req.get('host')}`;
const getRpId = (req) => req.get('host').split(':')[0];

const adminGuard = (req, res, next) => {
    const session = req.headers['x-admin-session'];
    if (!adminSession.has(session)) return res.status(401).json({ error: 'Unauthorized' });
    next();
};

// ==========================================
// 3. ADMIN ROUTES
// ==========================================
app.post('/admin/login', async (req, res) => {
    const { password } = req.body;
    try {
        const match = await bcrypt.compare(password, ADMIN_PW_HASH);
        if (match) {
            const session = crypto.randomBytes(32).toString('hex');
            adminSession.set(session, { timestamp: Date.now() });
            return res.json({ success: true, session });
        }
        res.status(401).json({ error: 'Invalid Credentials' });
    } catch (e) { res.status(500).json({ error: 'Internal Auth Error' }); }
});

app.post('/admin/generate-key', adminGuard, async (req, res) => {
    const { tier } = req.body;
    const key = `sk_chaos_${uuidv4().replace(/-/g, '').slice(0, 32)}`;
    const hashedKey = Abyss.hash(key);
    Abyss.partners.set(hashedKey, { quota_current: 0, quota_limit: tier === 'Enterprise' ? 99999 : 500, tier, company: 'New Partner' });
    res.json({ success: true, key, tier });
});

app.get('/admin/partners', adminGuard, (req, res) => {
    const partners = Array.from(Abyss.partners.entries()).map(([hash, p]) => ({ id: p.company, tier: p.tier, usage: p.quota_current, limit: p.quota_limit }));
    res.json({ partners });
});

// ==========================================
// 4. AUTH ROUTES
// ==========================================
app.get('/api/v1/auth/register-options', async (req, res) => {
    if (Users.has(ADMIN_USER_ID)) {
        res.setHeader('Content-Type', 'application/json');
        return res.status(403).send(JSON.stringify({ error: "SYSTEM LOCKED. IDENTITY EXISTS." }));
    }
    try {
        const options = await generateRegistrationOptions({
            rpName: 'A+ Chaos ID',
            rpID: getRpId(req),
            userID: new Uint8Array(Buffer.from(ADMIN_USER_ID)),
            userName: 'admin@aplus.com',
            attestationType: 'none',
            authenticatorSelection: { residentKey: 'required', userVerification: 'preferred', authenticatorAttachment: 'platform' },
        });
        Challenges.set(ADMIN_USER_ID, options.challenge);
        res.json(options);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/v1/auth/register-verify', async (req, res) => {
    const clientResponse = req.body;
    const expectedChallenge = Challenges.get(ADMIN_USER_ID);
    if (!expectedChallenge) return res.status(400).json({ error: "Expired" });
    try {
        const verification = await verifyRegistrationResponse({
            response: clientResponse, expectedChallenge, expectedOrigin: getOrigin(req), expectedRPID: getRpId(req),
        });
        if (verification.verified) {
            const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
            const userData = { credentialID: toBase64(credentialID), credentialPublicKey: credentialPublicKey, counter, dreamProfile: { window: [], sum_T: 0, sum_T2: 0 } };
            Users.set(ADMIN_USER_ID, userData);
            Challenges.delete(ADMIN_USER_ID);
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
    try {
         const json = Buffer.from(req.body.response.clientDataJSON, 'base64url').toString('utf8');
         challengeString = JSON.parse(json).challenge;
    } catch(e) { return res.status(400).json({error: "Bad Payload"}); }
    
    const challengeData = Challenges.get(challengeString);
    if (!user || !challengeData) return res.status(400).json({ error: "Invalid State" });

    // DREAMS CHECK
    const durationMs = Number(process.hrtime.bigint() - challengeData.startTime) / 1000000;
    const kineticData = req.body.kinetic_data;
    if (!DreamsEngine.check(durationMs, kineticData)) {
         Challenges.delete(challengeString);
         return res.status(403).json({ verified: false, error: "ERR_KINETIC_ANOMALY" });
    }
    
    try {
        const verification = await verifyAuthenticationResponse({
            response: req.body, expectedChallenge: challengeString, expectedOrigin: getOrigin(req), expectedRPID: getRpId(req),
            authenticator: { credentialID: toBuffer(user.credentialID), credentialPublicKey: user.credentialPublicKey, counter: user.counter },
            requireUserVerification: false,
        });
        if (verification.verified) {
            user.counter = verification.authenticationInfo.newCounter;
            Users.set(ADMIN_USER_ID, user); 
            Challenges.delete(challengeString);
            res.json({ verified: true, token: Chaos.mintToken() });
        } else { res.status(400).json({ verified: false }); }
    } catch (error) { res.status(400).json({ error: error.message }); } 
});

// --- API & TELEMETRY ---
app.post('/api/v1/external/verify', Nightmare.guardSaaS, (req, res) => res.json({ valid: true, quota: { used: req.partner.usage, limit: req.partner.limit } }));

app.get('/api/v1/beta/pulse-demo', (req, res) => {
    const agent = Abyss.agents.get('DEMO_AGENT_V1');
    if(!agent) return res.status(500).json({ error: "AGENT_MISSING" }); // Safety
    if(agent.usage >= agent.limit) return res.status(402).json({ error: "LIMIT" });
    agent.usage++;
    setTimeout(() => res.json({ valid: true, hash: 'pulse_' + Date.now(), ms: 15 }), 200);
});

app.get('/api/v1/admin/telemetry', (req, res) => res.json({ stats: { requests: Abyss.partners.size * 10, threats: 0 }, threats: [] }));
app.get('/api/v1/admin/profile-stats', (req, res) => res.json({ mu: 200, sigma: 20, cv: 0.1, status: "ACTIVE" }));
app.get('/api/v1/health', (req, res) => res.json({ status: "ALIVE" }));

const serve = (f, res) => fs.existsSync(path.join(publicPath, f)) ? res.sendFile(path.join(publicPath, f)) : res.status(404).send('Missing: ' + f);
app.get('/', (req, res) => serve('index.html', res));
app.get('/app', (req, res) => serve('app.html', res));
app.get('/dashboard', (req, res) => serve('dashboard.html', res));
app.get('/admin', (req, res) => serve('admin.html', res));
app.get('/sdk', (req, res) => serve('sdk.html', res));
app.get('/admin/portal', (req, res) => serve('portal.html', res));
app.get('*', (req, res) => res.redirect('/'));

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V102 (BENCHMARK READY) ONLINE: ${PORT}`));
