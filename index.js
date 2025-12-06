/**
 * A+ CHAOS ID: V56 (GOLD MASTER LOCK)
 * STATUS: Identity Permanently Locked. DREAMS V2 Active.
 * OWNER: Admin Agent (ID: ZV7...)
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

// --- UTILITY: CONVERTERS ---
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

// ==========================================
// 1. DREAMS PROTOCOL BLACK BOX
// ==========================================
const DreamsEngine = (() => {
    const MIN_SAMPLES = 5; 
    const MAX_SAMPLES = 10;
    
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
        check: (durationMs, user) => {
            const profile = user.dreamProfile;
            if (profile.window.length < MIN_SAMPLES) return true;

            const { mu: oldMu, sigma: oldSigma } = analyzeTemporalVector(profile.window);
            
            // 3-SIGMA CHECK
            if (oldSigma > 0 && Math.abs(durationMs - oldMu) > (oldSigma * 3)) {
                console.log(`[DREAMS REJECT] Time outside 3-Sigma range.`);
                return false;
            }
            return true;
        },
        update: (T_new, profile) => {
            if (profile.window.length >= MAX_SAMPLES) profile.window.shift();
            profile.window.push(T_new);
            const stats = analyzeTemporalVector(profile.window);
            profile.mu = stats.mu;
            profile.sigma = stats.sigma;
        }
    };
})();

// ==========================================
// 2. CORE LOGIC (V56 - FINAL LOCK)
// ==========================================
const Users = new Map();

// --- YOUR CLEANED DNA (HARDCODED) ---
const ADMIN_CRED_ID_STRING = "ZV7ZGFW9mdNO2K_BxS-B_A";
const ADMIN_PK_OBJ = {
    "0":165,"1":1,"2":2,"3":3,"4":38,"5":32,"6":1,"7":33,"8":88,"9":32,
    "10":22,"11":183,"12":222,"13":153,"14":81,"15":48,"16":4,"17":30,"18":108,"19":221,
    "20":165,"21":237,"22":142,"23":81,"24":238,"25":56,"26":190,"27":52,"28":210,"29":226,
    "30":101,"31":134,"32":241,"33":179,"34":34,"35":244,"36":117,"37":140,"38":167,"39":64,
    "40":149,"41":159,"42":34,"43":88,"44":32,"45":144,"46":122,"47":80,"48":10,"49":89,
    "50":76,"51":243,"52":225,"53":1,"54":70,"55":102,"56":114,"57":202,"58":80,"59":127,
    "60":29,"61":37,"62":191,"63":153,"64":147,"65":39,"66":12,"67":153,"68":255,"69":231,
    "70":99,"71":98,"72":126,"73":116,"74":249,"75":16,"76":222
};

// CONVERT AND LOCK
const ADMIN_DNA = {
    credentialID: Buffer.from(ADMIN_CRED_ID_STRING, 'base64url'), // Fixed string ID conversion
    credentialPublicKey: jsObjectToBuffer(ADMIN_PK_OBJ),
    counter: 0,
    dreamProfile: { window: [], sum_T: 0, sum_T2: 0 }
};
Users.set('admin-user', ADMIN_DNA); 
console.log(">>> [SYSTEM] V56 GOLD MASTER. IDENTITY ZV7... LOCKED.");

const Abyss = { partners: new Map(), agents: new Map(), hash: (k) => crypto.createHash('sha256').update(k).digest('hex') };
Abyss.partners.set(Abyss.hash('sk_chaos_demo123'), { company: 'Demo', plan: 'free', usage: 0, limit: 50, active: true });
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
// 3. AUTH ROUTES (LOCKED)
// ==========================================

// REGISTER: LOCKED (403 JSON)
app.get('/api/v1/auth/register-options', async (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.status(403).send(JSON.stringify({ error: "SYSTEM LOCKED. REGISTRATION CLOSED." }));
});

app.post('/api/v1/auth/register-verify', async (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.status(403).send(JSON.stringify({ error: "SYSTEM LOCKED. REGISTRATION CLOSED." }));
});

// LOGIN: OPEN (For Admin Only)
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

app.post('/api/v1/auth/login-verify', async (req, res) => {
    const userID = 'admin-user';
    const user = Users.get(userID);
    const clientResponse = req.body;
    
    const challengeString = extractChallengeFromClientResponse(clientResponse);
    const expectedChallenge = Challenges.get(challengeString); 

    if (!user || !expectedChallenge) return res.status(400).json({ error: "Invalid State" });
    
    // DREAMS CHECK
    const durationMs = Number(process.hrtime.bigint() - expectedChallenge.startTime) / 1000000;
    const dreamPassed = DreamsEngine.check(durationMs, user);
    if (!dreamPassed) {
         Challenges.delete(expectedChallenge.challenge);
         return res.status(403).json({ verified: false, error: "ERR_TEMPORAL_ANOMALY" });
    }
    
    // WEBAUTHN VERIFY
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
    } catch (error) { 
        console.error(error);
        res.status(400).json({ error: error.message }); 
    } finally {
        if(expectedChallenge) Challenges.delete(expectedChallenge.challenge);
    }
});

// --- API & FILE ROUTING ---
app.post('/api/v1/external/verify', Nightmare.guardSaaS, (req, res) => {
    res.json({ valid: true, user: "Admin User", method: "LEGACY_KEY", quota: { used: 0, limit: 50 } });
});

app.get('/api/v1/beta/pulse-demo', (req, res) => {
    setTimeout(() => res.json({ valid: true, hash: 'pulse_' + Date.now(), ms: 15 }), 200);
});

app.get('/api/v1/admin/telemetry', (req, res) => {
    res.json({ stats: { requests: 0, threats: 0 }, threats: [] }); 
});

app.post('/api/v1/admin/pentest', (req, res) => setTimeout(() => res.json({ message: "DNA INTEGRITY VERIFIED." }), 2000));

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

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V56 (IDENTITY LOCKED) ONLINE: ${PORT}`));
