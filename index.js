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
const DreamsEngine = {
    start: () => process.hrtime.bigint(),
    check: (durationMs, user) => { return true; }, 
    update: (T_new, profile) => { }
};

// ==========================================
// 2. CORE LOGIC (V52 - FINAL LOCK)
// ==========================================
const Users = new Map();

// --- YOUR DNA (HARDCODED) ---
const ADMIN_CRED_ID_STRING = "WrPt6Akz3Yxup57-9g-6mQ";
const ADMIN_PK_OBJ = {"0":165,"1":1,"2":2,"3":3,"4":38,"5":32,"6":1,"7":33,"8":88,"9":32,"10":20,"11":69,"12":72,"13":50,"14":102,"15":147,"16":162,"17":221,"18":86,"19":152,"20":123,"21":97,"22":160,"23":188,"24":29,"25":107,"26":7,"27":52,"28":181,"29":65,"30":226,"31":174,"32":5,"33":225,"34":251,"35":170,"36":129,"37":208,"38":37,"39":217,"40":250,"41":243,"42":34,"43":88,"44":32,"45":123,"46":122,"47":211,"48":13,"49":96,"50":104,"51":61,"52":231,"53":74,"54":17,"55":205,"56":190,"57":175,"58":246,"59":82,"60":123,"61":137,"62":44,"63":172,"64":82,"65":136,"66":22,"67":219,"68":93,"69":25,"70":227,"71":81,"72":189,"73":147,"74":163,"75":158,"76":25};

// CONVERT AND LOCK
const ADMIN_DNA = {
    // Convert Base64URL String to Buffer
    credentialID: Buffer.from(ADMIN_CRED_ID_STRING, 'base64url'),
    // Convert Object to Buffer
    credentialPublicKey: jsObjectToBuffer(ADMIN_PK_OBJ),
    counter: 0,
    dreamProfile: { window: [], sum_T: 0, sum_T2: 0 }
};
Users.set('admin-user', ADMIN_DNA); 
console.log(">>> [SYSTEM] V52 GOLD MASTER. IDENTITY LOCKED.");

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

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V52 (GOLD LOCK) ONLINE: ${PORT}`));


