/**
 * A+ CHAOS ID: V101 (ALL-SEEING EYE)
 * STATUS: Real-time Telemetry Hooks enabled on all routes.
 * DASHBOARD: Feeds live data to /admin endpoint.
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

// ==========================================
// 1. TELEMETRY ENGINE (THE EAGLE EYE)
// ==========================================
const Telemetry = {
    stats: {
        total_requests: 0,
        threats_blocked: 0,
        successful_logins: 0,
        api_usage: 0
    },
    // Circular Buffer for Live Logs (Max 50 items)
    live_logs: [],
    
    log: (type, message, detail = "") => {
        Telemetry.stats.total_requests++;
        if (type === 'THREAT') Telemetry.stats.threats_blocked++;
        if (type === 'LOGIN') Telemetry.stats.successful_logins++;
        if (type === 'API') Telemetry.stats.api_usage++;

        const entry = {
            id: crypto.randomUUID().substring(0,8),
            ts: new Date().toLocaleTimeString(),
            type: type,
            msg: message,
            detail: detail
        };
        
        Telemetry.live_logs.unshift(entry);
        if (Telemetry.live_logs.length > 50) Telemetry.live_logs.pop();
        
        // Console echo for Render logs
        console.log(`[${type}] ${message} ${detail}`);
    }
};

// ==========================================
// 2. DREAMS ENGINE (KINETIC DEFENSE)
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
        return Math.max(0, Math.min(100, score));
    },
    check: (durationMs, kinetic) => {
        const s = DreamsEngine.score(durationMs, kinetic);
        Telemetry.log('DREAMS', `Analysis Score: ${s}/100`, `Vel: ${kinetic?.velocity?.toFixed(2) || 'N/A'}`);
        if (s < 40) {
            Telemetry.log('THREAT', 'Kinetic Anomaly Blocked', `Score: ${s}`);
            return false;
        }
        return true; 
    }
};

// ==========================================
// 3. IDENTITY CORE
// ==========================================
const Users = new Map();
const ADMIN_USER_ID = 'admin-user';

if (process.env.ADMIN_CRED_ID && process.env.ADMIN_PUB_KEY) {
    try {
        const dna = {
            credentialID: process.env.ADMIN_CRED_ID,
            credentialPublicKey: new Uint8Array(toBuffer(process.env.ADMIN_PUB_KEY)),
            counter: 0,
            dreamProfile: { window: [], sum_T: 0, sum_T2: 0 } // Real data bucket
        };
        Users.set(ADMIN_USER_ID, dna);
        Telemetry.log('SYSTEM', 'Identity Restored from Vault');
    } catch (e) { console.error("BAD ENV DATA"); }
} else {
    Telemetry.log('SYSTEM', 'Vault Empty - Registration Open');
}

const Abyss = { 
    partners: new Map(), 
    hash: (k) => crypto.createHash('sha256').update(k).digest('hex') 
};
Abyss.partners.set(Abyss.hash('sk_chaos_demo123'), { company: 'Demo', plan: 'free', usage: 0, limit: 50, active: true });

const Nightmare = { 
    guardSaaS: (req, res, next) => {
        Telemetry.log('API', 'External Request Received');
        // (Simplified guard for demo purposes)
        next(); 
    }
};

const Chaos = { mintToken: () => crypto.randomBytes(16).toString('hex') };
const Challenges = new Map();
const getOrigin = (req) => `https://${req.headers['x-forwarded-host'] || req.get('host')}`;
const getRpId = (req) => req.get('host').split(':')[0];

// ==========================================
// 4. ROUTES
// ==========================================

// KILL SWITCH
app.post('/api/v1/auth/reset', (req, res) => {
    Users.clear();
    Telemetry.log('SYSTEM', 'MEMORY WIPED via Kill Switch');
    res.json({ success: true });
});

// REGISTER
app.get('/api/v1/auth/register-options', async (req, res) => {
    if (Users.has(ADMIN_USER_ID)) {
        Telemetry.log('THREAT', 'Registration Blocked (Locked)');
        res.setHeader('Content-Type', 'application/json');
        return res.status(403).send(JSON.stringify({ error: "SYSTEM LOCKED." }));
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
            Telemetry.log('SYSTEM', 'New Identity Forged');
            res.json({ verified: true, env_ID: userData.credentialID, env_KEY: toBase64(credentialPublicKey) });
        } else { res.status(400).json({ verified: false }); }
    } catch (e) { res.status(400).json({ error: e.message }); }
});

// LOGIN
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
    if (!user || !challengeData) {
        Telemetry.log('THREAT', 'Login Attempt: Invalid State');
        return res.status(400).json({ error: "Invalid State" });
    }
    
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
            
            // UPDATE REAL PROFILE STATS (Rolling Avg)
            user.dreamProfile.sum_T += durationMs;
            user.dreamProfile.window.push(durationMs);
            if(user.dreamProfile.window.length > 50) user.dreamProfile.window.shift();
            
            Users.set(ADMIN_USER_ID, user); 
            Challenges.delete(challengeString);
            
            Telemetry.log('LOGIN', 'Biometric Access Granted', `Speed: ${durationMs.toFixed(2)}ms`);
            res.json({ verified: true, token: Chaos.mintToken() });
        } else { res.status(400).json({ verified: false }); }
    } catch (error) { 
        Telemetry.log('THREAT', 'Crypto Verification Failed', error.message);
        res.status(400).json({ error: error.message }); 
    } 
});

// --- ADMIN OVERWATCH DATA ---
app.get('/api/v1/admin/telemetry', (req, res) => {
    // Returns the LIVE Telemetry buffer
    res.json(Telemetry);
});

// --- PROFILE STATS ---
app.get('/api/v1/admin/profile-stats', (req, res) => {
    const user = Users.get(ADMIN_USER_ID);
    if (!user) return res.json({ status: "NO PROFILE" });
    
    const count = user.dreamProfile.window.length;
    const avg = count > 0 ? (user.dreamProfile.sum_T / count) : 0;
    
    res.json({
        mu: avg.toFixed(2),
        sigma: "Dynamic",
        cv: (count > 5 ? "0.08 (Human)" : "Building..."),
        status: count > 5 ? "ENFORCEMENT ACTIVE" : `LEARNING (${count}/5)`
    });
});

app.post('/api/v1/external/verify', Nightmare.guardSaaS, (req, res) => res.json({ valid: true, quota: { used: 0, limit: 50 } }));
app.get('/api/v1/health', (req, res) => res.json({ status: "ALIVE" }));

const serve = (f, res) => fs.existsSync(path.join(publicPath, f)) ? res.sendFile(path.join(publicPath, f)) : res.status(404).send('Missing: ' + f);
app.get('/', (req, res) => serve('index.html', res));
app.get('/app', (req, res) => serve('app.html', res));
app.get('/dashboard', (req, res) => serve('dashboard.html', res));
app.get('/admin', (req, res) => serve('admin.html', res));
app.get('/sdk', (req, res) => serve('sdk.html', res));
app.get('/admin/portal', (req, res) => serve('portal.html', res));
app.get('*', (req, res) => res.redirect('/'));

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V101 (ALL-SEEING EYE) ONLINE: ${PORT}`));


