/**
 * A+ CHAOS ID: V71 (DEFIBRILLATOR EDITION)
 * STATUS: Identity Locked. Health Check Added. Transports loosened.
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

// --- UTILITY ---
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
        if (kinetic && kinetic.velocity > 5.0) return false;
        return true; 
    }, 
    update: (T_new, profile) => {}
};

// ==========================================
// 1. CORE IDENTITY (LOCKED)
// ==========================================
const Users = new Map();

// --- YOUR DNA (HARDCODED) ---
const ADMIN_CRED_ID_STRING = "oJ18aj5LzkkixMX1ILmv7Q";
const ADMIN_PK_OBJ = {
    "0":165,"1":1,"2":2,"3":3,"4":38,"5":32,"6":1,"7":33,"8":88,"9":32,"10":137,"11":38,"12":238,"13":41,"14":157,"15":79,"16":47,"17":9,"18":25,"19":26,"20":130,"21":177,"22":87,"23":221,"24":98,"25":125,"26":66,"27":164,"28":2,"29":228,"30":240,"31":117,"32":167,"33":185,"34":43,"35":144,"36":127,"37":209,"38":138,"39":91,"40":44,"41":233,"42":34,"43":88,"44":32,"45":253,"46":17,"47":38,"48":124,"49":173,"50":105,"51":52,"52":132,"53":241,"54":76,"55":22,"56":160,"57":57,"58":68,"59":34,"60":20,"61":4,"62":15,"63":27,"64":165,"65":192,"66":195,"67":125,"68":9,"69":145,"70":249,"71":105,"72":229,"73":118,"74":79,"75":241,"76":42
};

const ADMIN_DNA = {
    credentialID: Buffer.from(ADMIN_CRED_ID_STRING, 'base64url'),
    credentialPublicKey: jsObjectToBuffer(ADMIN_PK_OBJ),
    counter: 0,
    dreamProfile: { window: [], sum_T: 0, sum_T2: 0 }
};
Users.set('admin-user', ADMIN_DNA); 
console.log(">>> [SYSTEM] V71 DEFIBRILLATOR. IDENTITY LOCKED.");

const Abyss = { partners: new Map(), hash: (k) => crypto.createHash('sha256').update(k).digest('hex') };
const Nightmare = { guardSaaS: (req, res, next) => next() };
const Chaos = { mintToken: () => crypto.randomBytes(16).toString('hex') };
const Challenges = new Map();

const getOrigin = (req) => `https://${req.headers['x-forwarded-host'] || req.get('host')}`;
const getRpId = (req) => req.get('host').split(':')[0];

// ==========================================
// 2. AUTH ROUTES
// ==========================================

// NEW: LIGHTWEIGHT HEALTH CHECK (Wakes up Render)
app.get('/api/v1/health', (req, res) => {
    res.json({ status: "ALIVE", timestamp: Date.now() });
});

app.get('/api/v1/auth/register-options', (req, res) => res.status(403).json({ error: "LOCKED" }));
app.post('/api/v1/auth/register-verify', (req, res) => res.status(403).json({ error: "LOCKED" }));

// LOGIN: KINETIC
app.get('/api/v1/auth/login-options', async (req, res) => {
    const userID = 'admin-user'; 
    const user = Users.get(userID);
    try {
        const options = await generateAuthenticationOptions({
            rpID: getRpId(req),
            allowCredentials: [{
                id: user.credentialID,
                type: 'public-key'
                // REMOVED 'transports' to allow maximum compatibility
            }], 
            userVerification: 'required',
        });
        
        const friction = Math.random(); 
        Challenges.set(options.challenge, { 
            challenge: options.challenge, 
            startTime: DreamsEngine.start(),
            friction: friction
        });
        
        res.json({ ...options, kinetic_friction: friction });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/v1/auth/login-verify', async (req, res) => {
    const userID = 'admin-user';
    const user = Users.get(userID);
    const clientResponse = req.body;
    const challengeString = extractChallengeFromClientResponse(clientResponse);
    const expectedChallenge = Challenges.get(challengeString); 

    if (!user || !expectedChallenge) return res.status(400).json({ error: "Invalid State" });
    
    // KINETIC CHECK
    const durationMs = Number(process.hrtime.bigint() - expectedChallenge.startTime) / 1000000;
    const kineticData = clientResponse.kinetic_data; 
    
    if (!DreamsEngine.check(durationMs, user, kineticData)) {
         Challenges.delete(expectedChallenge.challenge);
         return res.status(403).json({ verified: false, error: "ERR_KINETIC_ANOMALY" });
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
app.get('/api/v1/admin/telemetry', (req, res) => res.json({ stats: { requests: 0 }, threats: [] }));
const serve = (f, res) => fs.existsSync(path.join(publicPath, f)) ? res.sendFile(path.join(publicPath, f)) : res.status(404).send('Missing: ' + f);
app.get('/', (req, res) => serve('index.html', res));
app.get('/app', (req, res) => serve('app.html', res));
app.get('/dashboard', (req, res) => serve('dashboard.html', res));
app.get('*', (req, res) => res.redirect('/'));

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V71 (DEFIBRILLATOR) ONLINE: ${PORT}`));


