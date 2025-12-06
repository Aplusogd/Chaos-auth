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
// Helper to handle the new Byte Array requirement
import { isoUint8Array } from '@simplewebauthn/server/helpers';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const publicPath = path.join(__dirname, 'public');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({ origin: '*' })); 
app.use(express.json());
app.use(express.static(publicPath));

// --- UTILS ---
const jsObjectToBuffer = (obj) => {
    if (obj instanceof Uint8Array) return obj;
    if (obj instanceof Buffer) return obj;
    if (typeof obj !== 'object' || obj === null) return new Uint8Array();
    return Buffer.from(Object.values(obj));
};

function extractChallengeFromClientResponse(clientResponse) {
    try {
        const clientDataJSONBase64 = clientResponse.response.clientDataJSON;
        const json = Buffer.from(clientDataJSONBase64, 'base64url').toString('utf8');
        return JSON.parse(json).challenge;
    } catch (e) { return null; }
}

// --- DREAMS ENGINE (Stub) ---
const DreamsEngine = {
    start: () => process.hrtime.bigint(),
    check: () => true, 
    update: () => {}
};

// --- CORE LOGIC (V51 FIXED) ---
const Users = new Map();
// Placeholder DNA (Will be overwritten by your new key)
const ADMIN_DNA = { "credentialID": { "0": 1 }, "counter": 0, "dreamProfile": { window: [], sum_T: 0, sum_T2: 0 } };
Users.set('admin-user', ADMIN_DNA); 

const Abyss = { partners: new Map(), agents: new Map(), hash: (k) => crypto.createHash('sha256').update(k).digest('hex') };
const Nightmare = { guardSaaS: (req, res, next) => next() };
const Chaos = { mintToken: () => crypto.randomBytes(16).toString('hex') };
const Challenges = new Map();

const getOrigin = (req) => {
    const host = req.headers['x-forwarded-host'] || req.get('host');
    const protocol = host.includes('localhost') ? 'http' : 'https';
    return `${protocol}://${host}`;
};
const getRpId = (req) => req.get('host').split(':')[0];

// ==========================================
// AUTH ROUTES (FIXED USER ID TYPE)
// ==========================================

// 1. REGISTER OPTIONS (OPEN)
app.get('/api/v1/auth/register-options', async (req, res) => {
    // FIX: Convert string ID to Uint8Array for V10+ Library support
    const userID = 'admin-user'; 
    const userIDBuffer = new Uint8Array(Buffer.from(userID));

    try {
        const options = await generateRegistrationOptions({
            rpName: 'A+ Chaos ID',
            rpID: getRpId(req),
            userID: userIDBuffer, // <--- THE FIX IS HERE
            userName: 'admin@aplus.com',
            attestationType: 'none',
            authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
        });
        Challenges.set(userID, options.challenge);
        res.json(options);
    } catch (err) { 
        console.error("REG OPTION ERROR:", err);
        res.status(500).json({ error: err.message }); 
    }
});

// 2. REGISTER VERIFY (OPEN)
app.post('/api/v1/auth/register-verify', async (req, res) => {
    const userID = 'admin-user';
    const clientResponse = req.body;
    const challengeString = extractChallengeFromClientResponse(clientResponse);
    
    // For recovery, we try to find challenge by ID first, then fallback to extraction
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
            const userData = { credentialID, credentialPublicKey, counter, dreamProfile: { window: [], sum_T: 0, sum_T2: 0 } };
            
            // SAVE NEW DNA TO MEMORY
            Users.set(userID, userData);
            Challenges.delete(userID);
            
            // SEND DNA TO CLIENT
            res.json({ verified: true, adminDNA: JSON.stringify(userData) });
        } else { res.status(400).json({ verified: false }); }
    } catch (e) { 
        console.error("VERIFY ERROR:", e);
        res.status(400).json({ error: e.message }); 
    }
});

// 3. LOGIN OPTIONS
app.get('/api/v1/auth/login-options', async (req, res) => {
    const userID = 'admin-user'; 
    const user = Users.get(userID);
    try {
        const options = await generateAuthenticationOptions({
            rpID: getRpId(req),
            allowCredentials: [], // Auto-discover
            userVerification: 'required',
        });
        Challenges.set(options.challenge, { challenge: options.challenge, startTime: DreamsEngine.start() });
        res.json(options);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// 4. LOGIN VERIFY
app.post('/api/v1/auth/login-verify', async (req, res) => {
    const userID = 'admin-user';
    const user = Users.get(userID);
    const clientResponse = req.body;
    const challengeString = extractChallengeFromClientResponse(clientResponse);
    const expectedChallenge = Challenges.get(challengeString);

    if (!user || !expectedChallenge) return res.status(400).json({ error: "Invalid State" });
    
    try {
        const verification = await verifyAuthenticationResponse({
            response: clientResponse,
            expectedChallenge: expectedChallenge.challenge,
            expectedOrigin: getOrigin(req),
            expectedRPID: getRpId(req),
            authenticator: user, 
        });

        if (verification.verified) {
            user.counter = verification.authenticationInfo.newCounter;
            Users.set(userID, user); 
            Challenges.delete(challengeString);
            res.json({ verified: true, token: Chaos.mintToken() });
        } else { res.status(400).json({ verified: false }); }
    } catch (error) { res.status(400).json({ error: error.message }); }
});

// --- ROUTING & SERVING ---
const serve = (f, res) => fs.existsSync(path.join(publicPath, f)) ? res.sendFile(path.join(publicPath, f)) : res.status(404).send('Missing: ' + f);
app.get('/', (req, res) => serve('app.html', res));
app.get('/app', (req, res) => serve('app.html', res));
app.get('/dashboard', (req, res) => serve('dashboard.html', res));
app.get('/admin', (req, res) => serve('admin.html', res));
app.get('/sdk', (req, res) => serve('sdk.html', res));
app.get('/admin/portal', (req, res) => serve('portal.html', res));
app.post('/api/v1/external/verify', Nightmare.guardSaaS, (req, res) => res.json({ valid: true }));
app.get('*', (req, res) => res.redirect('/'));

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V51 (BINARY ID FIXED) ONLINE: ${PORT}`));


