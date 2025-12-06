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

// ==========================================
// 1. TOTEM ENGINE (The Inception Layer)
// ==========================================
// The Totem converts raw behavior into a "Zone Hash".
// The server stores the Zone, not the data.
const TotemEngine = (() => {
    // Define "Zones" of behavior (buckets) to allow natural variance
    const QUANTUM_SIZE = 50; // 50ms buckets

    return {
        start: () => process.hrtime.bigint(),

        // Calculate the "Vibration" (Zone Hash)
        spin: (durationMs) => {
            // Round behavior into a "Zone" (Fuzzy Hashing)
            const zone = Math.floor(durationMs / QUANTUM_SIZE);
            // Hash the zone so the raw time is destroyed
            return crypto.createHash('sha256').update(`ZONE_SIG_${zone}`).digest('hex');
        },

        // Verify the Totem matches the Abyss record
        validate: (currentTotem, storedTotem) => {
            // In a real ZKP, we would allow "neighboring" totems.
            // For now, we check direct harmonic alignment.
            return currentTotem === storedTotem;
        }
    };
})();


// ==========================================
// 2. CORE LOGIC (V53)
// ==========================================
const Users = new Map();
// VITAL: YOUR HARDCODED DNA
const ADMIN_DNA_JS = {
  "credentialID": {"0":34,"1":107,"2":129,"3":52,"4":150,"5":223,"6":204,"7":57,"8":171,"9":110,"10":196,"11":62,"12":244,"13":235,"14":33,"15":107},
  "credentialPublicKey": {"0":165,"1":1,"2":2,"3":3,"4":38,"5":32,"6":1,"7":33,"8":88,"9":32,"10":248,"11":139,"12":206,"13":64,"14":122,"15":111,"16":83,"17":204,"18":37,"19":190,"20":213,"21":75,"22":207,"23":124,"24":3,"25":54,"26":101,"27":62,"28":26,"29":49,"30":36,"31":44,"32":74,"33":127,"34":106,"35":134,"36":50,"37":208,"38":245,"39":80,"40":80,"41":204,"42":34,"43":88,"44":32,"45":121,"46":45,"47":78,"48":103,"49":57,"50":120,"51":161,"52":241,"53":219,"54":228,"55":124,"56":89,"57":247,"58":180,"59":98,"60":57,"61":145,"62":0,"63":28,"64":76,"65":179,"66":212,"67":222,"68":26,"69":0,"70":230,"71":233,"72":237,"73":243,"74":138,"75":182,"76":166},
  "counter": 0,
  // NEW: The Totem Slot (Initially null)
  "totem": null 
};

// LOAD DNA
const ADMIN_DNA = {
    credentialID: jsObjectToBuffer(ADMIN_DNA_JS.credentialID),
    credentialPublicKey: jsObjectToBuffer(ADMIN_DNA_JS.credentialPublicKey),
    counter: ADMIN_DNA_JS.counter,
    totem: null
};
Users.set('admin-user', ADMIN_DNA); 

const Abyss = { partners: new Map(), agents: new Map(), hash: (key) => crypto.createHash('sha256').update(key).digest('hex') };
Abyss.partners.set(Abyss.hash('sk_chaos_demo123'), { company: 'Demo', plan: 'free', usage: 0, limit: 50, active: true });

const Nightmare = { guardSaaS: (req, res, next) => { next(); } };
const Chaos = { mintToken: () => crypto.randomBytes(16).toString('hex') };
const Challenges = new Map();
const getOrigin = (req) => {
    const host = req.headers['x-forwarded-host'] || req.get('host');
    const protocol = host.includes('localhost') ? 'http' : 'https';
    return `${protocol}://${host}`;
};
const getRpId = (req) => req.get('host').split(':')[0];

// --- ROUTES ---
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
        const options = await generateAuthenticationOptions({ rpID: getRpId(req), allowCredentials: [], userVerification: 'required' });
        // START THE TOTEM SPIN (Timer)
        Challenges.set(options.challenge, { challenge: options.challenge, startTime: TotemEngine.start() });
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
    
    // 1. CALCULATE THE CURRENT TOTEM (The Spin)
    const durationMs = Number(process.hrtime.bigint() - expectedChallenge.startTime) / 1000000;
    const currentTotem = TotemEngine.spin(durationMs);

    // 2. CHECK THE TOTEM (If it exists)
    if (user.totem) {
        // If we have a stored totem, the spin must match the "vibe" (Zone)
        const isNatural = TotemEngine.validate(currentTotem, user.totem);
        if (!isNatural) {
            // In V53, we log it but don't block yet, to let you calibrate the "Dream"
            console.log(`[TOTEM] WOBBLE DETECTED. Expected: ${user.totem.substring(0,6)}... Got: ${currentTotem.substring(0,6)}...`);
        }
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
            // 3. UPDATE THE TOTEM (The Anchor)
            // Every successful login refines the Totem in the Abyss
            user.totem = currentTotem; 
            user.counter = verification.authenticationInfo.newCounter;
            Users.set(userID, user); 
            Challenges.delete(expectedChallenge.challenge);
            
            res.json({ verified: true, token: Chaos.mintToken() });
        } else { res.status(400).json({ verified: false }); }
    } catch (error) { 
        console.error(error); res.status(400).json({ error: error.message }); 
    } finally {
        Challenges.delete(expectedChallenge.challenge);
    }
});

// --- API ROUTES ---
app.post('/api/v1/external/verify', Nightmare.guardSaaS, (req, res) => res.json({ valid: true }));
app.get('/api/v1/beta/pulse-demo', (req, res) => setTimeout(() => res.json({ valid: true }), 200));
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

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V53 (TOTEM ACTIVE) ONLINE: ${PORT}`));
