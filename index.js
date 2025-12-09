/**
 * A+ CHAOS ID: V143.6 (IMMORTAL GATEKEEPER)
 * STATUS: PRODUCTION
 * FEATURES: Hardcoded Identity + Registration Lock + Anti-Amnesia
 */
import express from 'express';
import path from 'path';
import cors from 'cors';
import fs from 'fs';
import crypto from 'crypto';
import helmet from 'helmet';
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

// --- UTILS ---
const toBuffer = (base64) => Buffer.from(base64, 'base64url');
const toBase64 = (buffer) => Buffer.from(buffer).toString('base64url');

// --- 1. THE IMMORTAL IDENTITY ---
// Your Phone's credentials, hardcoded to survive server restarts.
const PERMANENT_ID = "cWtBQ3Buc1ZnN2g2QlNGRlRjVGV6QQ";
const PERMANENT_KEY = "pQECAyYgASFYIHB_wbSVKRbTQgp7v4MEHhUa-GsFUzMQV49jJ1w8OvsqIlggFwXFALOUUKlfasQOhh3rSNG3zT3jVjiJA4ITr7u5uv0";

// --- STATE MANAGEMENT ---
const Users = new Map();
const ADMIN_USER_ID = 'admin-user';
const Challenges = new Map();
const Sessions = new Map();

// INITIALIZE USER WITH HARDCODED KEY
const adminData = {
    id: ADMIN_USER_ID,
    credentials: [{
        credentialID: toBuffer(PERMANENT_ID),
        credentialPublicKey: toBuffer(PERMANENT_KEY),
        counter: 0 // Reset to 0 allows any valid future login
    }]
};
Users.set(ADMIN_USER_ID, adminData);

// SECURITY STATE
let REGISTRATION_LOCKED = true; // STARTS LOCKED because you are already added!
let GATE_UNLOCK_TIMER = null;

// --- LIVE WIRE (SSE) ---
let connectedClients = [];
const LiveWire = {
    broadcast: (event, data) => {
        try { connectedClients.forEach(c => c.res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)); } catch(e){}
    },
    addClient: (req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive' });
        connectedClients.push({ id: Date.now(), res });
    }
};

const Telemetry = {
    logs: [],
    log: (type, msg) => {
        const entry = `[${type}] ${msg}`;
        console.log(entry);
        Telemetry.logs.unshift(entry);
        if (Telemetry.logs.length > 50) Telemetry.logs.pop();
        LiveWire.broadcast('log', { entry });
    }
};

// --- MIDDLEWARE ---
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*' })); 
app.use(express.json());
app.use(express.static(publicPath)); 

const DreamsEngine = {
    start: () => process.hrtime.bigint(),
    check: (durationMs, kinetic) => {
        // Relaxed velocity check
        if (kinetic && kinetic.velocity > 60.0) return false;
        return true; 
    }
};

const getOrigin = (req) => `https://${req.headers['x-forwarded-host'] || req.get('host')}`;
const getRpId = (req) => (req.headers['x-forwarded-host'] || req.get('host')).split(':')[0];

// ==========================================
// 2. GATEKEEPER ROUTE (UNLOCK)
// ==========================================
app.post('/api/v1/auth/unlock-gate', (req, res) => {
    const token = req.headers['x-chaos-token'];
    
    // VERIFY SESSION (You must be logged in to unlock)
    if (!Sessions.has(token)) {
        return res.status(401).json({ error: "ACCESS DENIED. LOGIN FIRST." });
    }

    REGISTRATION_LOCKED = false;
    Telemetry.log('SECURITY', 'GATE UNLOCKED FOR 30s');
    
    if (GATE_UNLOCK_TIMER) clearTimeout(GATE_UNLOCK_TIMER);
    GATE_UNLOCK_TIMER = setTimeout(() => {
        REGISTRATION_LOCKED = true;
        Telemetry.log('SECURITY', 'GATE LOCKED');
    }, 30000);

    res.json({ success: true, message: "GATE OPEN: 30s" });
});

// ==========================================
// 3. AUTH ROUTES
// ==========================================

app.get('/api/v1/auth/register-options', async (req, res) => {
    // BLOCK IF LOCKED
    if (REGISTRATION_LOCKED) {
        Telemetry.log('BLOCK', 'Registration Attempted (LOCKED)');
        return res.status(403).json({ error: "SYSTEM LOCKED. ASK ADMIN TO UNLOCK." });
    }

    try {
        const options = await generateRegistrationOptions({
            rpName: 'A+ Chaos ID', rpID: getRpId(req), userID: new Uint8Array(Buffer.from(ADMIN_USER_ID)), userName: 'admin@aplus.com',
            attestationType: 'none', authenticatorSelection: { residentKey: 'required', userVerification: 'preferred', authenticatorAttachment: 'platform' },
        });
        Challenges.set(ADMIN_USER_ID, options.challenge);
        res.json(options);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/v1/auth/register-verify', async (req, res) => {
    if (REGISTRATION_LOCKED) return res.status(403).json({ error: "LOCKED" });

    const expectedChallenge = Challenges.get(ADMIN_USER_ID);
    if (!expectedChallenge) return res.status(400).json({ error: "Expired" });

    try {
        const verification = await verifyRegistrationResponse({ 
            response: req.body, expectedChallenge, expectedOrigin: getOrigin(req), expectedRPID: getRpId(req) 
        });
        
        if (verification.verified) {
            const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
            const user = Users.get(ADMIN_USER_ID);
            
            // Check Duplicates
            const targetIdStr = toBase64(credentialID);
            const exists = user.credentials.find(c => toBase64(c.credentialID) === targetIdStr);

            if (!exists) {
                user.credentials.push({ credentialID, credentialPublicKey, counter });
                Users.set(ADMIN_USER_ID, user);
                Telemetry.log('AUTH', `New Device Added. Total: ${user.credentials.length}`);
                
                // AUTO-LOCK
                REGISTRATION_LOCKED = true;
                Telemetry.log('SECURITY', 'SYSTEM LOCKED.');
            }
            Challenges.delete(ADMIN_USER_ID);
            res.json({ verified: true });
        } else { res.status(400).json({ verified: false }); }
    } catch (e) { res.status(400).json({ error: e.message }); }
});

app.get('/api/v1/auth/login-options', async (req, res) => {
    const user = Users.get(ADMIN_USER_ID);
    if (!user || user.credentials.length === 0) return res.status(404).json({ error: "NO IDENTITY" });
    try {
        const allowed = user.credentials.map(c => ({ id: c.credentialID, type: 'public-key' }));
        const options = await generateAuthenticationOptions({ rpID: getRpId(req), allowCredentials: allowed, userVerification: 'preferred' });
        Challenges.set(options.challenge, { challenge: options.challenge, startTime: DreamsEngine.start() });
        res.json(options);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/v1/auth/login-verify', async (req, res) => {
    try {
        const json = Buffer.from(req.body.response.clientDataJSON, 'base64url').toString('utf8');
        const challengeString = JSON.parse(json).challenge;
        const challengeData = Challenges.get(challengeString);
        if (!challengeData) return res.status(400).json({ error: "Invalid Challenge" });

        const user = Users.get(ADMIN_USER_ID);
        // Robust ID Matching (Buffer vs String)
        const targetIdStr = req.body.id; 
        const match = user.credentials.find(c => toBase64(c.credentialID) === targetIdStr);
        
        if (!match) {
            Telemetry.log('FAIL', 'Device Not Found');
            return res.status(400).json({ error: "Device Not Found" });
        }

        const verification = await verifyAuthenticationResponse({
            response: req.body, expectedChallenge: challengeString, expectedOrigin: getOrigin(req), expectedRPID: getRpId(req),
            authenticator: { credentialID: match.credentialID, credentialPublicKey: match.credentialPublicKey, counter: match.counter },
            requireUserVerification: false,
        });

        if (verification.verified) {
            match.counter = verification.authenticationInfo.newCounter;
            Users.set(ADMIN_USER_ID, user);
            Challenges.delete(challengeString);
            
            const token = crypto.randomBytes(32).toString('hex');
            Sessions.set(token, { loginTime: Date.now() });
            
            Telemetry.log('AUTH', 'Login Successful');
            res.json({ verified: true, token });
        } else { res.status(400).json({ verified: false }); }
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Demo Routes
app.get('/api/v1/beta/pulse-demo', (req, res) => { res.json({ valid: true, hash: 'demo', ms: 10 }); });
app.post('/api/v1/public/signup', (req, res) => res.json({ success: true }));
app.post('/api/v1/external/verify', (req, res) => res.json({ valid: true }));
app.get('/api/v1/health', (req, res) => res.json({ status: "ALIVE" }));
app.get('/api/v1/stream', (req, res) => LiveWire.addClient(req, res));

// Files
const serve = (f, res) => fs.existsSync(path.join(publicPath, f)) ? res.sendFile(path.join(publicPath, f)) : res.status(404).send('Missing: ' + f);
app.get('/', (req, res) => serve('index.html', res));
app.get('/app', (req, res) => serve('app.html', res));
app.get('/dashboard', (req, res) => serve('dashboard.html', res));
app.get('*', (req, res) => res.redirect('/'));

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V143.6 ONLINE (IMMORTAL)`));
