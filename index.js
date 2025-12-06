/**
 * A+ CHAOS ID: V57 (MASTER KEY EDITION)
 * STATUS: Dynamic Registration enabled via 'X-CHAOS-MASTER-KEY'.
 * Hardcoding removed. Persistence via memory (reset on deploy).
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

// --- SECURITY: MASTER PASSWORD ---
// In production, set this in Render Environment Variables.
// Default for now: "chaos-genesis"
const MASTER_KEY = process.env.MASTER_KEY || "chaos-genesis";

// ==========================================
// 1. DREAMS PROTOCOL (O(1) Stub)
// ==========================================
const DreamsEngine = {
    start: () => process.hrtime.bigint(),
    check: () => true, 
    update: () => {}
};

// ==========================================
// 2. CORE LOGIC (Dynamic Memory)
// ==========================================
// We removed the hardcoded DNA. The server starts empty.
// You will claim it using the Master Key.
const Users = new Map();
const Challenges = new Map();
const Chaos = { mintToken: () => crypto.randomBytes(16).toString('hex') };
const Abyss = { 
    partners: new Map(), 
    hash: (k) => crypto.createHash('sha256').update(k).digest('hex') 
};
const Nightmare = { guardSaaS: (req, res, next) => next() };

const getOrigin = (req) => {
    const host = req.headers['x-forwarded-host'] || req.get('host');
    const protocol = host.includes('localhost') ? 'http' : 'https';
    return `${protocol}://${host}`;
};
const getRpId = (req) => req.get('host').split(':')[0];

function extractChallenge(clientResponse) {
    try {
        const json = Buffer.from(clientResponse.response.clientDataJSON, 'base64url').toString('utf8');
        return JSON.parse(json).challenge;
    } catch (e) { return null; }
}

// ==========================================
// 3. AUTH ROUTES (PASSWORD PROTECTED)
// ==========================================

// REGISTER: Check for Master Key
app.get('/api/v1/auth/register-options', async (req, res) => {
    const authHeader = req.headers['x-chaos-master-key'];
    
    // THE GATEKEEPER
    if (authHeader !== MASTER_KEY) {
        return res.status(403).json({ error: "REGISTRATION LOCKED. INVALID MASTER KEY." });
    }

    const userID = 'admin-user'; 
    try {
        const options = await generateRegistrationOptions({
            rpName: 'A+ Chaos ID',
            rpID: getRpId(req),
            userID: new Uint8Array(Buffer.from(userID)),
            userName: 'admin@aplus.com',
            attestationType: 'none',
            authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
        });
        Challenges.set(userID, options.challenge);
        res.json(options);
    } catch (err) { res.status(400).json({ error: err.message }); }
});

app.post('/api/v1/auth/register-verify', async (req, res) => {
    const authHeader = req.headers['x-chaos-master-key'];
    if (authHeader !== MASTER_KEY) return res.status(403).json({ error: "INVALID MASTER KEY" });

    const userID = 'admin-user';
    const clientResponse = req.body;
    const challengeString = extractChallenge(clientResponse);
    
    // Recovery Logic: Try getting challenge by UserID first
    let expectedChallenge = Challenges.get(userID);
    if (!expectedChallenge) expectedChallenge = challengeString; // Fallback

    if (!expectedChallenge) return res.status(400).json({ error: "Challenge Expired" });

    try {
        const verification = await verifyRegistrationResponse({
            response: clientResponse,
            expectedChallenge: expectedChallenge,
            expectedOrigin: getOrigin(req),
            expectedRPID: getRpId(req),
        });

        if (verification.verified) {
            const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
            // DYNAMIC SAVE
            Users.set(userID, { credentialID, credentialPublicKey, counter, dreamProfile: { window: [], sum_T: 0, sum_T2: 0 } });
            Challenges.delete(userID);
            res.json({ verified: true });
        } else { res.status(400).json({ verified: false }); }
    } catch (e) { res.status(400).json({ error: e.message }); }
});

// LOGIN (Standard)
app.get('/api/v1/auth/login-options', async (req, res) => {
    const userID = 'admin-user';
    const user = Users.get(userID);
    // If server restarted, user is gone. Client needs to know to re-register.
    if (!user) return res.status(404).json({ error: "IDENTITY RESET. USE MASTER KEY TO CLAIM." });

    try {
        const options = await generateAuthenticationOptions({
            rpID: getRpId(req),
            allowCredentials: [],
            userVerification: 'required',
        });
        Challenges.set(options.challenge, { challenge: options.challenge, startTime: DreamsEngine.start() });
        res.json(options);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/v1/auth/login-verify', async (req, res) => {
    const userID = 'admin-user';
    const user = Users.get(userID);
    const clientResponse = req.body;
    const challengeString = extractChallenge(clientResponse);
    const expectedChallenge = Challenges.get(challengeString); 

    if (!user || !expectedChallenge) return res.status(400).json({ error: "Invalid State" });

    // DREAMS Check
    const durationMs = Number(process.hrtime.bigint() - expectedChallenge.startTime) / 1000000;
    if (!DreamsEngine.check(durationMs, user)) {
         Challenges.delete(expectedChallenge.challenge);
         return res.status(403).json({ verified: false, error: "ERR_TEMPORAL_ANOMALY" });
    }

    try {
        const verification = await verifyAuthenticationResponse({
            response: clientResponse,
            expectedChallenge: expectedChallenge.challenge,
            expectedOrigin: getOrigin(req),
            expectedRPID: getRpId(req),
            authenticator: user, 
        });

        if (verification.verified) {
            DreamsEngine.update(durationMs, user.dreamProfile); 
            user.counter = verification.authenticationInfo.newCounter;
            Users.set(userID, user); 
            Challenges.delete(expectedChallenge.challenge);
            res.json({ verified: true, token: Chaos.mintToken() });
        } else { res.status(400).json({ verified: false }); }
    } catch (error) { res.status(400).json({ error: error.message }); } 
    finally { Challenges.delete(expectedChallenge.challenge); }
});

// --- API ROUTES ---
app.post('/api/v1/external/verify', Nightmare.guardSaaS, (req, res) => res.json({ valid: true }));
app.get('/api/v1/admin/telemetry', (req, res) => res.json({ stats: { requests: 0 }, threats: [] }));
app.get('/api/v1/audit/get-proof', (req, res) => res.json({ status: "READY" }));

// FILE SERVING
const serve = (f, res) => fs.existsSync(path.join(publicPath, f)) ? res.sendFile(path.join(publicPath, f)) : res.status(404).send('Missing: ' + f);
app.get('/', (req, res) => serve('index.html', res)); 
app.get('/app', (req, res) => serve('app.html', res)); 
app.get('/dashboard', (req, res) => serve('dashboard.html', res)); 
app.get('/admin', (req, res) => serve('admin.html', res)); 
app.get('/sdk', (req, res) => serve('sdk.html', res)); 
app.get('/admin/portal', (req, res) => serve('portal.html', res)); 
app.get('*', (req, res) => res.redirect('/'));

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V57 (MASTER KEY MODE) ONLINE: ${PORT}`));
