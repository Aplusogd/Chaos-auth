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

// ==========================================
// HYDRA CONFIGURATION (V58)
// ==========================================
// 1. Go to /hydra (your-url/hydra)
// 2. Generate Shards
// 3. Copy the hash and replace the string below OR set HYDRA_HASH env var.
// Default Hash below is for password: "chaos"
const HYDRA_HASH = process.env.HYDRA_HASH || "d216f40445d47042079075775796c096417d472251d1152771d34c038c362d2d"; 

let REGISTRATION_UNLOCKED = false; // Default Locked

// ... (Utility functions retained) ...
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
    check: () => true, 
    update: () => {}
};

// ... (Core Logic & Hardcoded DNA retained from V56) ...
const Users = new Map();
// Note: Ensure your V56 Hardcoded DNA is pasted here if you want persistence
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

const Abyss = { partners: new Map(), hash: (k) => crypto.createHash('sha256').update(k).digest('hex') };
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
// ROUTES
// ==========================================

// --- HYDRA UNLOCK ENDPOINT ---
app.post('/api/v1/auth/hydra-unlock', (req, res) => {
    const { key } = req.body;
    
    // Hash the incoming key to compare with stored hash
    const attemptHash = crypto.createHash('sha256').update(key).digest('hex');
    
    if (attemptHash === HYDRA_HASH) {
        REGISTRATION_UNLOCKED = true;
        
        // Auto-lock after 5 minutes for security
        setTimeout(() => { REGISTRATION_UNLOCKED = false; }, 300000);
        
        console.log(">>> [HYDRA] SYSTEM UNLOCKED BY QUORUM.");
        res.json({ success: true });
    } else {
        console.log(">>> [HYDRA] FAILED UNLOCK ATTEMPT.");
        res.status(403).json({ success: false });
    }
});

// --- AUTH (GATED BY HYDRA) ---
app.get('/api/v1/auth/register-options', async (req, res) => {
    if (!REGISTRATION_UNLOCKED) {
        res.setHeader('Content-Type', 'application/json');
        return res.status(403).send(JSON.stringify({ error: "SYSTEM LOCKED. USE HYDRA TO UNLOCK." }));
    }
    
    // ... Registration logic ...
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
    if (!REGISTRATION_UNLOCKED) return res.status(403).json({ error: "LOCKED" });
    
    // ... Verification logic ...
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
            res.json({ verified: true, adminDNA: JSON.stringify(userData) });
        } else { res.status(400).json({ verified: false }); }
    } catch (e) { res.status(400).json({ error: e.message }); }
});

// LOGIN (Standard - Always Open for valid keys)
app.get('/api/v1/auth/login-options', async (req, res) => {
    const userID = 'admin-user'; 
    const user = Users.get(userID);
    if (!user) return res.status(404).json({ error: "SYSTEM RESET. PLEASE CONTACT ADMIN." });
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
            Challenges.delete(expectedChallenge.challenge);
            res.json({ verified: true, token: Chaos.mintToken() });
        } else { res.status(400).json({ verified: false }); }
    } catch (error) { res.status(400).json({ error: error.message }); } 
    finally { Challenges.delete(expectedChallenge.challenge); }
});

// API & FILE ROUTING
app.post('/api/v1/external/verify', Nightmare.guardSaaS, (req, res) => res.json({ valid: true }));
app.get('/api/v1/admin/telemetry', (req, res) => res.json({ stats: { requests: 0 }, threats: [] }));
const serve = (f, res) => fs.existsSync(path.join(publicPath, f)) ? res.sendFile(path.join(publicPath, f)) : res.status(404).send('Missing: ' + f);
app.get('/', (req, res) => serve('index.html', res));
app.get('/app', (req, res) => serve('app.html', res));
app.get('/dashboard', (req, res) => serve('dashboard.html', res));
app.get('/admin', (req, res) => serve('admin.html', res));
app.get('/sdk', (req, res) => serve('sdk.html', res)); 
app.get('/admin/portal', (req, res) => serve('portal.html', res)); 
app.get('/hydra', (req, res) => serve('hydra.html', res)); // HYDRA ROUTE
app.get('*', (req, res) => res.redirect('/'));

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V58 (HYDRA ENABLED) ONLINE: ${PORT}`));


