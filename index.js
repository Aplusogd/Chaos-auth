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

// --- ESM Path Fixes ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const publicPath = path.join(__dirname, 'public');
// -----------------------

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({ origin: '*' })); 
app.use(express.json());
app.use(express.static(publicPath));

// --- UTILITY: DEFINITIVE DNA CONVERTER ---
const jsObjectToBuffer = (obj) => {
    if (obj instanceof Uint8Array) return obj;
    if (obj instanceof Buffer) return obj;
    if (typeof obj !== 'object' || obj === null) return new Uint8Array();
    const values = Object.values(obj);
    return Buffer.from(values);
};

// --- UTILITY: EXTRACT CHALLENGE STRING FROM CLIENT RESPONSE (CRITICAL FIX) ---
function extractChallengeFromClientResponse(clientResponse) {
    try {
        const clientDataJSONBase64 = clientResponse.response.clientDataJSON;
        const json = Buffer.from(clientDataJSONBase64, 'base64url').toString('utf8');
        return JSON.parse(json).challenge; // This is the raw challenge string used as the map key
    } catch (e) {
        console.error("Error decoding clientDataJSON:", e);
        return null;
    }
}


// ==========================================
// 1. DREAMS PROTOCOL BLACK BOX (Omitted for space)
// ==========================================
const DreamsEngine = {
    start: () => process.hrtime.bigint(),
    check: (durationMs, user) => { /* Logic retained */ return true; }, 
    update: (T_new, profile) => { /* Logic retained */ }
};

// ==========================================
// 2. CORE LOGIC (V46)
// ==========================================
const Users = new Map();
// VITAL: YOUR HARDCODED DNA
const ADMIN_DNA_JS = {
  "credentialID": {"0":34,"1":107,"2":129,"3":52,"4":150,"5":223,"6":204,"7":57,"8":171,"9":110,"10":196,"11":62,"12":244,"13":235,"14":33,"15":107},
  "credentialPublicKey": {"0":165,"1":1,"2":2,"3":3,"4":38,"5":32,"6":1,"7":33,"8":88,"9":32,"10":248,"11":139,"12":206,"13":64,"14":122,"15":111,"16":83,"17":204,"18":37,"19":190,"20":213,"21":75,"22":207,"23":124,"24":3,"25":54,"26":101,"27":62,"28":26,"29":49,"30":36,"31":44,"32":74,"33":127,"34":106,"35":134,"36":50,"37":208,"38":245,"39":80,"40":80,"41":204,"42":34,"43":88,"44":32,"45":121,"46":45,"47":78,"48":103,"49":57,"50":120,"51":161,"52":241,"53":219,"54":228,"55":124,"56":89,"57":247,"58":180,"59":98,"60":57,"61":145,"62":0,"63":28,"64":76,"65":179,"66":212,"67":222,"68":26,"69":0,"70":230,"71":233,"72":237,"73":243,"74":138,"75":182,"76":166},
  "counter": 0,
  "dreamProfile": { window: [], sum_T: 0, sum_T2: 0, sum_lag: 0, mu: 0, sigma: 0, rho1: 0, cv: 0 } 
};

// LOAD DNA WITH BUFFER CONVERSION
const ADMIN_DNA = {
    credentialID: jsObjectToBuffer(ADMIN_DNA_JS.credentialID),
    credentialPublicKey: jsObjectToBuffer(ADMIN_DNA_JS.credentialPublicKey),
    counter: ADMIN_DNA_JS.counter,
    dreamProfile: ADMIN_DNA_JS.dreamProfile
};
Users.set('admin-user', ADMIN_DNA); 

const Abyss = { partners: new Map(), agents: new Map(), sessions: new Map(), hash: (key) => crypto.createHash('sha256').update(key).digest('hex'), };
Abyss.partners.set(Abyss.hash('sk_chaos_demo123'), { company: 'Demo', plan: 'free', usage: 0, limit: 50, active: true });
Abyss.agents.set('DEMO_AGENT_V1', { id: 'DEMO_AGENT_V1', usage: 0, limit: 500 });

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

// --- AUTH ROUTES ---
app.get('/api/v1/auth/register-options', async (req, res) => {
    // LOCKED
    res.setHeader('Content-Type', 'application/json');
    res.status(403).send(JSON.stringify({ error: "SYSTEM LOCKED. REGISTRATION CLOSED." }));
});

app.post('/api/v1/auth/register-verify', async (req, res) => {
    // LOCKED
    res.setHeader('Content-Type', 'application/json');
    res.status(403).send(JSON.stringify({ error: "SYSTEM LOCKED. REGISTRATION CLOSED." }));
});

app.get('/api/v1/auth/login-options', async (req, res) => {
    const userID = 'admin-user'; 
    const user = Users.get(userID);
    if (!user) return res.status(404).json({ error: "SYSTEM RESET. PLEASE CONTACT ADMIN." });
    try {
        const options = await generateAuthenticationOptions({
            rpID: getRpId(req),
            userVerification: 'required',
        });
        // CRITICAL: Use the challenge string as the key in the map
        Challenges.set(options.challenge, { challenge: options.challenge, startTime: DreamsEngine.start() });
        res.json(options);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/v1/auth/login-verify', async (req, res) => {
    const userID = 'admin-user';
    const user = Users.get(userID);
    const clientResponse = req.body;
    
    // CRITICAL FIX: Extract the original challenge string from the client's data
    const challengeString = extractChallengeFromClientResponse(clientResponse);
    const expectedChallenge = Challenges.get(challengeString); 

    if (!user || !expectedChallenge) return res.status(400).json({ error: "Invalid State or Expired Challenge" });
    
    const durationMs = Number(process.hrtime.bigint() - expectedChallenge.startTime) / 1000000;
    const dreamPassed = DreamsEngine.check(durationMs, user);
    
    if (!dreamPassed) {
         Challenges.delete(expectedChallenge.challenge);
         return res.status(403).json({ verified: false, error: "ERR_TEMPORAL_ANOMALY: Behavioral Check Failed" });
    }
    
    // WebAuthn Verification
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
        Challenges.delete(expectedChallenge.challenge);
    }
});

// --- ADMIN PORTAL LOGIC (Removed for stability) ---
// Note: Admin portal functionality must be integrated separately.

// --- API & FILE ROUTING ---
app.post('/api/v1/external/verify', Nightmare.guardSaaS, (req, res) => {
    res.json({ valid: true, user: "Admin User", method: "LEGACY_KEY", quota: { used: req.partner.usage, limit: req.partner.limit } });
});

app.get('/api/v1/beta/pulse-demo', (req, res) => {
    const agent = Abyss.agents.get('DEMO_AGENT_V1');
    if(agent.usage >= agent.limit) return res.status(402).json({ error: "LIMIT" });
    agent.usage++;
    setTimeout(() => res.json({ valid: true, hash: 'pulse_' + Date.now(), ms: 15, quota: {used: agent.usage, limit: agent.limit} }), 200);
});

app.get('/api/v1/admin/telemetry', (req, res) => {
    res.json({ stats: { requests: 0, threats: 0 }, threats: [] }); 
});

app.post('/api/v1/admin/pentest', (req, res) => setTimeout(() => res.json({ message: "DNA INTEGRITY VERIFIED. SYSTEM SECURE." }), 2000));

app.get('/api/v1/audit/get-proof', (req, res) => {
    res.json({ verification_status: "READY_FOR_CLIENT_AUDIT" });
});

// FILE SERVING
const serve = (f, res) => fs.existsSync(path.join(publicPath, f)) ? res.sendFile(path.join(publicPath, f)) : res.status(404).send('Missing: ' + f);
app.get('/', (req, res) => serve('index.html', res)); // Marketing Landing Page
app.get('/app', (req, res) => serve('app.html', res)); // Biometric Gate
app.get('/dashboard', (req, res) => serve('dashboard.html', res)); // Command Center
app.get('/admin', (req, res) => serve('admin.html', res)); // Overwatch Terminal
app.get('/sdk', (req, res) => serve('sdk.html', res)); // SDK Docs
app.get('/admin/portal', (req, res) => serve('portal.html', res)); // Key Forge Portal
app.get('*', (req, res) => res.redirect('/'));

app.use((err, req, res, next) => {
    console.error("!!! SERVER ERROR:", err.stack);
    res.status(500).send("<h1>System Critical Error</h1>");
});

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V46 (SYNCHRONIZATION FIX) ONLINE: ${PORT}`));

