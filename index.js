/**
 * A+ CHAOS ID: V93 (BENCHMARK READY)
 * STATUS: DreamsEngine Active. Bot Defense Enabled.
 */
import express from 'express';
import path from 'path';
import cors from 'cors';
import fs from 'fs';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { dirname } from 'path';     
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
// 1. DREAMS ENGINE (ACTIVE DEFENSE)
// ==========================================
const DreamsEngine = {
    start: () => process.hrtime.bigint(),
    
    // THIS IS THE BOT TRAP
    check: (durationMs, user, kinetic) => {
        // 1. Speed Check: Bots are too fast (<100ms)
        if (durationMs < 100) return false; 

        // 2. Kinetic Check (Benchmark Data)
        if (kinetic) {
            console.log(`[DREAMS SCAN] Velocity: ${kinetic.velocity} | Entropy: ${kinetic.entropy}`);
            
            // TRAP: High velocity (>10) or Zero Entropy (Straight line) = BOT
            if (kinetic.velocity > 10.0) return false; 
            if (kinetic.entropy < 0.1) return false; 
        }
        
        return true; // Human Passed
    }, 
    
    update: (T_new, profile) => {}
};

// ==========================================
// 2. CORE IDENTITY
// ==========================================
const Users = new Map();
const ADMIN_USER_ID = 'admin-user';

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
    } catch (e) { console.error("!!! [ERROR] BAD ENV DATA:", e); }
}

const Abyss = { partners: new Map(), hash: (k) => crypto.createHash('sha256').update(k).digest('hex') };
Abyss.partners.set(Abyss.hash('sk_chaos_demo123'), { company: 'Demo', plan: 'free', usage: 0, limit: 50, active: true });
const Nightmare = { guardSaaS: (req, res, next) => next() };
const Chaos = { mintToken: () => crypto.randomBytes(16).toString('hex') };
const Challenges = new Map();
const getOrigin = (req) => `https://${req.headers['x-forwarded-host'] || req.get('host')}`;
const getRpId = (req) => req.get('host').split(':')[0];

// ==========================================
// 3. AUTH ROUTES
// ==========================================
app.get('/api/v1/health', (req, res) => res.json({ status: "ALIVE", timestamp: Date.now() }));
app.post('/api/v1/auth/reset', (req, res) => { Users.clear(); res.json({ success: true }); });

app.get('/api/v1/auth/register-options', async (req, res) => {
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
            response: clientResponse,
            expectedChallenge,
            expectedOrigin: getOrigin(req),
            expectedRPID: getRpId(req),
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
        const options = await generateAuthenticationOptions({
            rpID: getRpId(req),
            allowCredentials: [], 
            userVerification: 'preferred',
        });
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
    
    if (!user || !Challenges.has(challengeString)) return res.status(400).json({ error: "Invalid State" });
    
    const expectedChallenge = Challenges.get(challengeString);
    const durationMs = Number(process.hrtime.bigint() - expectedChallenge.startTime) / 1000000;
    
    // --- V93: ACTIVATE DEFENSE ---
    // Reads kinetic_data from benchmark payload
    const kineticData = req.body.kinetic_data; 
    
    if (!DreamsEngine.check(durationMs, user, kineticData)) {
         Challenges.delete(challengeString);
         // Return 403 Forbidden on Bot Detection
         return res.status(403).json({ verified: false, error: "ERR_KINETIC_ANOMALY: Bot Detected" });
    }
    
    try {
        const verification = await verifyAuthenticationResponse({
            response: req.body,
            expectedChallenge: challengeString,
            expectedOrigin: getOrigin(req),
            expectedRPID: getRpId(req),
            authenticator: {
                credentialID: toBuffer(user.credentialID),
                credentialPublicKey: user.credentialPublicKey,
                counter: user.counter,
            },
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

app.post('/api/v1/external/verify', Nightmare.guardSaaS, (req, res) => res.json({ valid: true }));
const serve = (f, res) => fs.existsSync(path.join(publicPath, f)) ? res.sendFile(path.join(publicPath, f)) : res.status(404).send('Missing: ' + f);
app.get('/', (req, res) => serve('index.html', res));
app.get('/app', (req, res) => serve('app.html', res));
app.get('/dashboard', (req, res) => serve('dashboard.html', res));
app.get('*', (req, res) => res.redirect('/'));

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V93 (ACTIVE DEFENSE) ONLINE: ${PORT}`));
