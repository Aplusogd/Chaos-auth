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

// --- UTILITY: DYNAMIC DOMAIN RESOLUTION (CRITICAL FIX) ---
// This ensures the RP ID matches the URL bar exactly.
const getRpId = (req) => {
    const host = req.headers['x-forwarded-host'] || req.get('host');
    // Strip port number if present (e.g., localhost:3000 -> localhost)
    return host.split(':')[0];
};

const getOrigin = (req) => {
    const host = req.headers['x-forwarded-host'] || req.get('host');
    const proto = req.headers['x-forwarded-proto'] || 'http';
    return `${proto}://${host}`;
};

// --- UTILITY: CONVERT JS OBJECT TO BUFFER ---
const jsObjectToBuffer = (obj) => {
    if (obj instanceof Uint8Array) return obj;
    if (obj instanceof Buffer) return obj;
    if (typeof obj !== 'object' || obj === null) return new Uint8Array();
    return Buffer.from(Object.values(obj));
};

// --- UTILITY: EXTRACT CHALLENGE ---
function extractChallengeFromClientResponse(clientResponse) {
    try {
        const clientDataJSONBase64 = clientResponse.response.clientDataJSON;
        const json = Buffer.from(clientDataJSONBase64, 'base64url').toString('utf8');
        return JSON.parse(json).challenge;
    } catch (e) { return null; }
}

// ==========================================
// 1. DREAMS V4 ENGINE (Cognitive + Temporal)
// ==========================================
const DreamsEngine = (() => {
    const MIN_SAMPLES = 5; 
    const MAX_SAMPLES = 10;
    
    // O(1) Math Helper
    const analyzeTemporalVector = (timings) => {
        const n = timings.length;
        if (n <= 1) return { mu: timings[0] || 0, sigma: 0, rho1: 0, cv: 0 };
        const mu = timings.reduce((sum, t) => sum + t, 0) / n;
        const centeredVar = timings.reduce((sum, t) => sum + Math.pow(t - mu, 2), 0) / (n - 1);
        const sigma = Math.sqrt(Math.max(0, centeredVar));
        const cv = sigma / mu;
        return { mu, sigma, cv };
    };

    return {
        start: () => process.hrtime.bigint(),

        // Now checks COGNITIVE SCORE from client
        check: (durationMs, user, cognitiveData) => {
            // 1. Cognitive Check (V4)
            if (cognitiveData) {
                // Humans react to visual stimuli > 150ms but < 2000ms
                // Bots are either 0ms (scripted) or > 2000ms (vision processing)
                if (cognitiveData.reactionTime < 100 || cognitiveData.entropy < 0.2) {
                    console.log("[DREAMS V4] Cognitive Trap Triggered: Bot Movement Detected.");
                    return false; 
                }
            }

            // 2. Temporal Check (V2/V3)
            const profile = user.dreamProfile;
            if (profile.window.length < MIN_SAMPLES) return true;

            const { mu: oldMu, sigma: oldSigma } = analyzeTemporalVector(profile.window);
            
            if (oldSigma > 0 && Math.abs(durationMs - oldMu) > (oldSigma * 4)) { // 4-Sigma leniency for mobile
                console.log(`[DREAMS REJECT] Time outlier.`);
                return false;
            }
            return true;
        },

        update: (T_new, profile) => {
            const window = profile.window;
            if (window.length === MAX_SAMPLES) {
                const T_old = window[0];
                profile.sum_T -= T_old;
                profile.sum_T2 -= T_old * T_old;
                window.shift();
            }
            profile.sum_T += T_new;
            profile.sum_T2 += T_new * T_new;
            window.push(T_new);
        }
    };
})();


// ==========================================
// 2. CORE LOGIC (V49)
// ==========================================
const Users = new Map();
// HARDCODED DNA (Placeholder - You must re-register to fix domain mismatch)
const ADMIN_DNA = { "credentialID": { "0": 1 }, "counter": 0, "dreamProfile": { window: [], sum_T: 0, sum_T2: 0, mu: 0, sigma: 0 } };
Users.set('admin-user', ADMIN_DNA); 

const Abyss = { partners: new Map(), agents: new Map(), hash: (key) => crypto.createHash('sha256').update(key).digest('hex') };
Abyss.partners.set(Abyss.hash('sk_chaos_demo123'), { company: 'Demo', plan: 'free', usage: 0, limit: 50, active: true });
const Nightmare = { guardSaaS: (req, res, next) => next() };
const Chaos = { mintToken: () => crypto.randomBytes(16).toString('hex') };
const Challenges = new Map();

// --- AUTH ROUTES (Using Dynamic RP ID) ---

// TEMPORARILY UNLOCKED FOR RE-REGISTRATION
app.get('/api/v1/auth/register-options', async (req, res) => {
    const userID = 'admin-user'; 
    try {
        const rpID = getRpId(req); // DYNAMIC
        console.log(`[SETUP] Generating Register Options for RP ID: ${rpID}`);
        
        const options = await generateRegistrationOptions({
            rpName: 'A+ Chaos ID',
            rpID: rpID, // Critical Fix
            userID,
            userName: 'admin@aplus.com',
            attestationType: 'none',
            authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
        });
        Challenges.set(userID, options.challenge);
        res.json(options);
    } catch (err) { 
        console.error(err);
        res.status(400).json({ error: err.message }); 
    }
});

app.post('/api/v1/auth/register-verify', async (req, res) => {
    const userID = 'admin-user';
    const expectedChallenge = Challenges.get(userID);
    if (!expectedChallenge) return res.status(400).json({ error: "Expired" });
    
    try {
        const verification = await verifyRegistrationResponse({
            response: req.body,
            expectedChallenge,
            expectedOrigin: getOrigin(req), // DYNAMIC
            expectedRPID: getRpId(req),     // DYNAMIC
        });

        if (verification.verified) {
            const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
            const userData = { credentialID, credentialPublicKey, counter, dreamProfile: { window: [], sum_T: 0, sum_T2: 0 } };
            Users.set(userID, userData);
            Challenges.delete(userID);
            res.json({ verified: true, adminDNA: JSON.stringify(userData) });
        } else { res.status(400).json({ verified: false }); }
    } catch (e) { res.status(400).json({ error: e.message }); }
});

app.get('/api/v1/auth/login-options', async (req, res) => {
    const userID = 'admin-user'; 
    // Allow login even if hardcoded key is dummy (for reset flow)
    const user = Users.get(userID);
    
    try {
        const options = await generateAuthenticationOptions({
            rpID: getRpId(req), // DYNAMIC
            allowCredentials: [], // Auto-discover
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
    
    const challengeString = extractChallengeFromClientResponse(clientResponse);
    const expectedChallenge = Challenges.get(challengeString); 

    if (!user || !expectedChallenge) return res.status(400).json({ error: "Invalid State" });
    
    // DREAMS V4 CHECK
    const durationMs = Number(process.hrtime.bigint() - expectedChallenge.startTime) / 1000000;
    const cognitiveData = clientResponse.cognitive_data; // From client V49
    
    const dreamPassed = DreamsEngine.check(durationMs, user, cognitiveData);
    
    if (!dreamPassed) {
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

// --- API ROUTING ---
app.post('/api/v1/external/verify', Nightmare.guardSaaS, (req, res) => res.json({ valid: true, quota: { used: 1, limit: 50 } }));
app.get('/api/v1/admin/telemetry', (req, res) => res.json({ stats: { requests: 0 }, threats: [] }));
app.get('/api/v1/audit/get-proof', (req, res) => res.json({ verification_status: "READY" }));

// FILE SERVING
const serve = (f, res) => fs.existsSync(path.join(publicPath, f)) ? res.sendFile(path.join(publicPath, f)) : res.status(404).send('Missing: ' + f);
app.get('/', (req, res) => serve('index.html', res));
app.get('/app', (req, res) => serve('app.html', res));
app.get('/dashboard', (req, res) => serve('dashboard.html', res));
app.get('/admin', (req, res) => serve('admin.html', res));
app.get('/sdk', (req, res) => serve('sdk.html', res)); 
app.get('/admin/portal', (req, res) => serve('portal.html', res));
app.get('*', (req, res) => res.redirect('/'));

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V49 (DYNAMIC DOMAIN) ONLINE: ${PORT}`));


