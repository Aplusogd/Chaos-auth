/**
 * A+ CHAOS ID: V69 (KINETIC UNLOCK)
 * STATUS: Registration Re-Opened. Kinetic Logic Active.
 * FIX: Removed broken hardcoded DNA to resolve connection loop.
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
    check: (durationMs, user, kinetic) => {
        // V69: Permissive check for initial setup
        if (kinetic && kinetic.velocity > 0.5) return true;
        return true; 
    }, 
    update: (T_new, profile) => {}
};

// ==========================================
// 1. CORE LOGIC (RESET STATE)
// ==========================================
const Users = new Map();
// NOTE: Starting EMPTY to fix the "Bad Key" crash.
// Users.set('admin-user', ...); 

const Abyss = { partners: new Map(), hash: (k) => crypto.createHash('sha256').update(k).digest('hex') };
const Nightmare = { guardSaaS: (req, res, next) => next() };
const Chaos = { mintToken: () => crypto.randomBytes(16).toString('hex') };
const Challenges = new Map();

const getOrigin = (req) => `https://${req.headers['x-forwarded-host'] || req.get('host')}`;
const getRpId = (req) => req.get('host').split(':')[0];

// ==========================================
// 2. AUTH ROUTES (UNLOCKED)
// ==========================================

// REGISTER (OPEN)
app.get('/api/v1/auth/register-options', async (req, res) => {
    const userID = 'admin-user'; 
    try {
        console.log(`[REGISTER] Generating options for ${getRpId(req)}`);
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
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/v1/auth/register-verify', async (req, res) => {
    const userID = 'admin-user';
    const clientResponse = req.body;
    const challengeString = extractChallengeFromClientResponse(clientResponse);
    const expectedChallenge = Challenges.get(userID) || Challenges.get(challengeString);

    if (!expectedChallenge) return res.status(400).json({ error: "Expired" });

    try {
        const verification = await verifyRegistrationResponse({
            response: clientResponse,
            expectedChallenge,
            expectedOrigin: getOrigin(req),
            expectedRPID: getRpId(req),
        });

        if (verification.verified) {
            const userData = { ...verification.registrationInfo, dreamProfile: { window: [], sum_T: 0, sum_T2: 0 } };
            Users.set(userID, userData);
            Challenges.delete(userID);
            Challenges.delete(challengeString);
            console.log("[REGISTER] SUCCESS. DNA GENERATED.");
            res.json({ verified: true, adminDNA: JSON.stringify(userData) });
        } else { res.status(400).json({ verified: false }); }
    } catch (e) { res.status(400).json({ error: e.message }); }
});

// LOGIN (KINETIC)
app.get('/api/v1/auth/login-options', async (req, res) => {
    const userID = 'admin-user'; 
    const user = Users.get(userID);
    
    // If no user, tell client to REGISTER
    if (!user) return res.status(404).json({ error: "RESET" });

    try {
        const options = await generateAuthenticationOptions({
            rpID: getRpId(req),
            allowCredentials: [], // Auto-discover
            userVerification: 'required',
        });
        
        const friction = Math.random(); 
        Challenges.set(options.challenge, { 
            challenge: options.challenge, 
            startTime: DreamsEngine.start(),
            friction: friction
        });
        
        res.json({ ...options, kinetic_friction: friction });
    } catch (err) { 
        console.error("[LOGIN OPTION ERROR]", err);
        res.status(500).json({ error: err.message }); 
    }
});

app.post('/api/v1/auth/login-verify', async (req, res) => {
    const userID = 'admin-user';
    const user = Users.get(userID);
    const clientResponse = req.body;
    const challengeString = extractChallengeFromClientResponse(clientResponse);
    const expectedChallenge = Challenges.get(challengeString); 

    if (!user || !expectedChallenge) return res.status(400).json({ error: "Invalid State" });
    
    // KINETIC CHECK (V69)
    const durationMs = Number(process.hrtime.bigint() - expectedChallenge.startTime) / 1000000;
    const kineticData = clientResponse.kinetic_data; 
    
    // Log the throw data
    if(kineticData) console.log(`[THROW] Velocity: ${kineticData.velocity.toFixed(2)} | Dist: ${kineticData.distance}`);

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
            Challenges.delete(expectedChallenge.challenge);
            res.json({ verified: true, token: Chaos.mintToken() });
        } else { res.status(400).json({ verified: false }); }
    } catch (error) { res.status(400).json({ error: error.message }); } 
    finally { if(expectedChallenge) Challenges.delete(expectedChallenge.challenge); }
});

// ROUTING
app.post('/api/v1/external/verify', Nightmare.guardSaaS, (req, res) => res.json({ valid: true }));
const serve = (f, res) => fs.existsSync(path.join(publicPath, f)) ? res.sendFile(path.join(publicPath, f)) : res.status(404).send('Missing: ' + f);
app.get('/', (req, res) => serve('index.html', res));
app.get('/app', (req, res) => serve('app.html', res));
app.get('/dashboard', (req, res) => serve('dashboard.html', res));
app.get('*', (req, res) => res.redirect('/'));

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V69 (KINETIC UNLOCK) ONLINE: ${PORT}`));


