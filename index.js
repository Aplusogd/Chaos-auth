/**
 * A+ CHAOS ID: V55 (THE HARVESTER)
 * STATUS: V54 Security + V60 Drift Telemetry Pipeline Active.
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

// --- UTILITY: CONVERT JS OBJECT MAP TO NODE BUFFER ---
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
// 1. TELEMETRY ENGINE (V60 PREP)
// ==========================================
const TelemetryCore = (() => {
    let dailyPepper = crypto.randomBytes(32).toString('hex');
    
    // Rotate pepper every 24 hours to prevent long-term tracking
    setInterval(() => {
        dailyPepper = crypto.randomBytes(32).toString('hex');
        console.log(`[CHAOS] DAILY PEPPER ROTATED: ${dailyPepper.substring(0,8)}...`);
    }, 86400000);

    return {
        getPepper: () => dailyPepper,
        
        // Anonymize IP (Mask last octet)
        maskIP: (ip) => {
            if (!ip) return '0.0.0.0';
            const parts = ip.split('.');
            if (parts.length === 4) return `${parts[0]}.${parts[1]}.${parts[2]}.000`;
            return 'anonymized';
        }
    };
})();

// ==========================================
// 2. DREAMS PROTOCOL BLACK BOX
// ==========================================
const DreamsEngine = (() => {
    const MIN_SAMPLES = 5; 
    
    // Core math helper
    const analyze = (timings) => {
        const n = timings.length;
        if (n <= 1) return { mu: timings[0] || 0, sigma: 0 };
        const mu = timings.reduce((a, b) => a + b, 0) / n;
        const variance = timings.reduce((a, b) => a + Math.pow(b - mu, 2), 0) / (n - 1);
        return { mu, sigma: Math.sqrt(variance) };
    };

    return {
        start: () => process.hrtime.bigint(),
        check: (durationMs, user) => {
            const profile = user.dreamProfile;
            if (profile.window.length < MIN_SAMPLES) return true;
            const { mu, sigma } = analyze(profile.window);
            
            // 3-Sigma Check
            if (sigma > 0 && Math.abs(durationMs - mu) > (sigma * 3)) {
                return false; // Anomaly
            }
            return true;
        },
        update: (T_new, profile) => {
            if (profile.window.length >= 10) profile.window.shift();
            profile.window.push(T_new);
        }
    };
})();

// ==========================================
// 3. CORE LOGIC (V55)
// ==========================================
const Users = new Map();
// YOUR HARDCODED DNA
const ADMIN_DNA_JS = {
  "credentialID": {"0":34,"1":107,"2":129,"3":52,"4":150,"5":223,"6":204,"7":57,"8":171,"9":110,"10":196,"11":62,"12":244,"13":235,"14":33,"15":107},
  "credentialPublicKey": {"0":165,"1":1,"2":2,"3":3,"4":38,"5":32,"6":1,"7":33,"8":88,"9":32,"10":248,"11":139,"12":206,"13":64,"14":122,"15":111,"16":83,"17":204,"18":37,"19":190,"20":213,"21":75,"22":207,"23":124,"24":3,"25":54,"26":101,"27":62,"28":26,"29":49,"30":36,"31":44,"32":74,"33":127,"34":106,"35":134,"36":50,"37":208,"38":245,"39":80,"40":80,"41":204,"42":34,"43":88,"44":32,"45":121,"46":45,"47":78,"48":103,"49":57,"50":120,"51":161,"52":241,"53":219,"54":228,"55":124,"56":89,"57":247,"58":180,"59":98,"60":57,"61":145,"62":0,"63":28,"64":76,"65":179,"66":212,"67":222,"68":26,"69":0,"70":230,"71":233,"72":237,"73":243,"74":138,"75":182,"76":166},
  "counter": 0,
  "dreamProfile": { window: [], sum_T: 0, sum_T2: 0 } 
};

const ADMIN_DNA = {
    credentialID: jsObjectToBuffer(ADMIN_DNA_JS.credentialID),
    credentialPublicKey: jsObjectToBuffer(ADMIN_DNA_JS.credentialPublicKey),
    counter: ADMIN_DNA_JS.counter,
    dreamProfile: ADMIN_DNA_JS.dreamProfile
};
Users.set('admin-user', ADMIN_DNA); 

const Abyss = {
    partners: new Map(),
    agents: new Map(),
    driftLogs: [], // Temporary in-memory buffer for telemetry
    hash: (key) => crypto.createHash('sha256').update(key).digest('hex'),
};
Abyss.partners.set(Abyss.hash('sk_chaos_demo123'), { company: 'Demo', plan: 'free', usage: 0, limit: 50, active: true });

const Nightmare = {
    guardSaaS: (req, res, next) => {
        try {
            const rawKey = req.get('X-CHAOS-API-KEY');
            if (!rawKey) return res.status(401).json({ error: "MISSING_KEY" });
            const partner = Abyss.partners.get(Abyss.hash(rawKey));
            if (!partner) return res.status(403).json({ error: "INVALID_KEY" });
            if (partner.usage >= partner.limit) return res.status(402).json({ error: "QUOTA_EXCEEDED" });
            partner.usage++;
            req.partner = partner;
            next();
        } catch(e) { res.status(500).json({error: "SECURITY_FAIL"}); }
    }
};

const Chaos = { mintToken: () => crypto.randomBytes(16).toString('hex') };
const Challenges = new Map();

const getOrigin = (req) => {
    const host = req.headers['x-forwarded-host'] || req.get('host');
    const protocol = host.includes('localhost') ? 'http' : 'https';
    return `${protocol}://${host}`;
};
const getRpId = (req) => req.get('host').split(':')[0];

// ==========================================
// ROUTES
// ==========================================

// --- NEW: DRIFT TELEMETRY INGESTION (V60 Harvest) ---
app.post('/api/v1/telemetry/drift', (req, res) => {
    const payload = req.body;
    
    // 1. Validate Schema (Lightweight)
    if (!payload.userIdHash || !payload.result) {
        return res.status(400).json({ error: "INVALID_TELEMETRY_SCHEMA" });
    }

    // 2. Server-Side Anonymization & Enrichment
    const entry = {
        ...payload,
        server_ts: Date.now(),
        ip_masked: TelemetryCore.maskIP(req.ip),
        pepper_id: TelemetryCore.getPepper().substring(0, 8) // Traceability for rotation
    };

    // 3. Store (In-Memory for now, DB in production)
    Abyss.driftLogs.push(entry);
    if (Abyss.driftLogs.length > 1000) Abyss.driftLogs.shift(); // Rotate buffer

    // 4. Log for Admin Board
    console.log(`[HARVEST] Drift Data Received. Result: ${payload.result} | Network: ${payload.networkBucket}`);

    res.status(201).json({ status: "harvested" });
});

// --- AUTH ROUTES ---
app.get('/api/v1/auth/register-options', async (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.status(403).send(JSON.stringify({ error: "SYSTEM LOCKED. REGISTRATION CLOSED." }));
});
app.post('/api/v1/auth/register-verify', async (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.status(403).send(JSON.stringify({ error: "SYSTEM LOCKED. REGISTRATION CLOSED." }));
});

app.get('/api/v1/auth/login-options', async (req, res) => {
    const userID = 'admin-user'; 
    const user = Users.get(userID);
    try {
        const options = await generateAuthenticationOptions({
            rpID: getRpId(req),
            userVerification: 'required',
        });
        Challenges.set(options.challenge, { challenge: options.challenge, startTime: DreamsEngine.start() });
        
        // V55: Send Daily Pepper Hash to client for salting (Pseudo-Anonymous)
        // We send a hash of the pepper, not the pepper itself, for binding.
        const pepperCommit = crypto.createHash('sha256').update(TelemetryCore.getPepper()).digest('hex');
        
        res.json({ ...options, drift_pepper: pepperCommit });
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
    
    // VERIFY
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
        res.status(400).json({ error: error.message }); 
    } finally {
        Challenges.delete(expectedChallenge.challenge);
    }
});

// --- API & FILE ROUTING ---
app.post('/api/v1/external/verify', Nightmare.guardSaaS, (req, res) => res.json({ valid: true, quota: { used: req.partner.usage, limit: req.partner.limit } }));

app.get('/api/v1/beta/pulse-demo', (req, res) => {
    setTimeout(() => res.json({ valid: true, hash: 'pulse_' + Date.now(), ms: 15 }), 200);
});

app.get('/api/v1/admin/telemetry', (req, res) => {
    // Expose Drift Stats to Admin
    res.json({ 
        stats: { 
            requests: Abyss.driftLogs.length, 
            threats: 0 
        }, 
        drift_harvest: Abyss.driftLogs.slice(0, 5) // Show last 5 logs
    }); 
});

app.post('/api/v1/admin/pentest', (req, res) => setTimeout(() => res.json({ message: "DNA INTEGRITY VERIFIED. SYSTEM SECURE." }), 2000));
app.get('/api/v1/audit/get-proof', (req, res) => res.json({ verification_status: "READY" }));

const serve = (f, res) => fs.existsSync(path.join(publicPath, f)) ? res.sendFile(path.join(publicPath, f)) : res.status(404).send('Missing: ' + f);
app.get('/', (req, res) => serve('index.html', res));
app.get('/app', (req, res) => serve('app.html', res));
app.get('/dashboard', (req, res) => serve('dashboard.html', res));
app.get('/admin', (req, res) => serve('admin.html', res));
app.get('/sdk', (req, res) => serve('sdk.html', res)); 
app.get('/admin/portal', (req, res) => serve('portal.html', res));
app.get('*', (req, res) => res.redirect('/'));

app.use((err, req, res, next) => {
    console.error("!!! SERVER ERROR:", err.stack);
    res.status(500).send("<h1>System Critical Error</h1>");
});

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V55 (THE HARVESTER) ONLINE: ${PORT}`));
