/**
 * A+ CHAOS ID: V143.2 (NIGHT SHIFT STABILIZER)
 * STATUS: LIVE & DEBUGGING
 * FIXES: Restored Public Demo Routes + Simplified Registration for Recovery
 */
import express from 'express';
import path from 'path';
import cors from 'cors';
import fs from 'fs';
import crypto from 'crypto';
import helmet from 'helmet';
import { fileURLToPath } from 'url';
import { dirname } from 'path';     
import bcrypt from 'bcrypt';
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

// --- 1. LIVE WIRE ENGINE (SSE) ---
let connectedClients = [];
const LiveWire = {
    broadcast: (event, data) => {
        // Safe broadcast that handles circular references or connection drops
        try {
            const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
            connectedClients.forEach(client => client.res.write(payload));
        } catch (e) { console.error("Broadcast Error", e); }
    },
    addClient: (req, res) => {
        res.writeHead(200, {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive'
        });
        const clientId = Date.now();
        connectedClients.push({ id: clientId, res });
        req.on('close', () => connectedClients = connectedClients.filter(c => c.id !== clientId));
    }
};

// --- TELEMETRY ---
const Telemetry = {
    requests: 0,
    blocked: 0,
    logs: [],
    log: (type, msg) => {
        const entry = `[${type}] ${msg}`;
        console.log(entry); // Print to Render Console for debugging
        Telemetry.logs.unshift(entry);
        if (Telemetry.logs.length > 50) Telemetry.logs.pop();
        if (type === 'BLOCK') Telemetry.blocked++;
        LiveWire.broadcast('log', { entry, stats: { requests: Telemetry.requests, threats: Telemetry.blocked } });
    }
};

// --- MIDDLEWARE ---
app.use((req, res, next) => {
    if (!req.path.includes('/stream') && !req.path.includes('/health')) {
        Telemetry.requests++;
    }
    next();
});

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            // Relaxed for development stability
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdn.tailwindcss.com", "https://unpkg.com", "https://cdnjs.cloudflare.com"],
            scriptSrcAttr: ["'self'", "'unsafe-inline'"], 
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https://placehold.co"],
            connectSrc: ["'self'", "https://overthere.ai", "https://chaos-auth-iff2.onrender.com", "wss://chaos-auth-iff2.onrender.com"],
            upgradeInsecureRequests: [],
        },
    },
}));

app.use(cors({ origin: '*' })); 
app.use(express.json());
app.use(express.static(publicPath)); 

// --- UTILITIES ---
const toBuffer = (base64) => Buffer.from(base64, 'base64url');
const toBase64 = (buffer) => Buffer.from(buffer).toString('base64url');

const DreamsEngine = {
    start: () => process.hrtime.bigint(),
    check: (durationMs, kinetic) => {
        // Relaxed Bot Detection for Testing
        if (kinetic && kinetic.velocity > 50.0) {
            Telemetry.log('BLOCK', `Bot Detected (Extreme Vel: ${kinetic.velocity})`);
            return false;
        }
        return true; 
    }
};

// --- IDENTITY STORE (VOLATILE RAM) ---
// Note: This resets on server restart. You must re-register after deployment.
const Users = new Map();
const ADMIN_USER_ID = 'admin-user';
const Challenges = new Map();

// Initialize Admin
let adminData = { id: ADMIN_USER_ID, credentials: [] };
Users.set(ADMIN_USER_ID, adminData);

const getOrigin = (req) => `https://${req.headers['x-forwarded-host'] || req.get('host')}`;
const getRpId = (req) => (req.headers['x-forwarded-host'] || req.get('host')).split(':')[0];

// ==========================================
// 1. PUBLIC DEMO ROUTES (RESTORED)
// ==========================================

// Fixes "Unexpected Token <" on Benchmark Click
app.get('/api/v1/beta/pulse-demo', (req, res) => {
    const hash = crypto.createHash('sha256').update(Date.now().toString()).digest('hex');
    // Simulate processing time
    res.json({ valid: true, hash: hash, ms: Math.floor(Math.random() * 20) + 5 });
});

// Fixes "Join Beta" Form
app.post('/api/v1/public/signup', (req, res) => {
    const { firstName } = req.body;
    Telemetry.log('SIGNUP', `Interest Registered: ${firstName || 'Anonymous'}`);
    res.json({ success: true, key: "sk_chaos_demo_" + Date.now().toString().slice(-6) });
});

// Fixes "Partner Verification" Simulation
app.post('/api/v1/external/verify', (req, res) => {
    res.json({ valid: true, quota: { used: 120, limit: 500 } });
});

app.get('/api/v1/health', (req, res) => res.json({ status: "ALIVE", users: Users.get(ADMIN_USER_ID).credentials.length }));

// ==========================================
// 2. AUTHENTICATION ROUTES
// ==========================================

app.get('/api/v1/stream', (req, res) => {
    LiveWire.addClient(req, res);
    Telemetry.log('SYSTEM', 'Admin Connected to War Room');
});

// REGISTER (OPTIONS)
app.get('/api/v1/auth/register-options', async (req, res) => {
    // SECURITY RELAXED: No Master Key Check for tonight's recovery
    try {
        const options = await generateRegistrationOptions({
            rpName: 'A+ Chaos ID', 
            rpID: getRpId(req), 
            userID: new Uint8Array(Buffer.from(ADMIN_USER_ID)), 
            userName: 'admin@aplus.com',
            attestationType: 'none', 
            authenticatorSelection: { residentKey: 'required', userVerification: 'preferred', authenticatorAttachment: 'platform' },
        });
        Challenges.set(ADMIN_USER_ID, options.challenge);
        res.json(options);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// REGISTER (VERIFY)
app.post('/api/v1/auth/register-verify', async (req, res) => {
    const expectedChallenge = Challenges.get(ADMIN_USER_ID);
    if (!expectedChallenge) return res.status(400).json({ error: "Challenge Expired" });

    try {
        const verification = await verifyRegistrationResponse({ 
            response: req.body, expectedChallenge, expectedOrigin: getOrigin(req), expectedRPID: getRpId(req) 
        });
        
        if (verification.verified) {
            const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
            const user = Users.get(ADMIN_USER_ID);
            
            // Avoid duplicates in RAM
            const exists = user.credentials.find(c => Buffer.compare(c.credentialID, credentialID) === 0);
            if (!exists) {
                user.credentials.push({ credentialID, credentialPublicKey, counter });
                Users.set(ADMIN_USER_ID, user);
                Telemetry.log('AUTH', `Device Registered. Total Keys: ${user.credentials.length}`);
            }
            Challenges.delete(ADMIN_USER_ID);
            res.json({ verified: true });
        } else { res.status(400).json({ verified: false }); }
    } catch (e) { 
        Telemetry.log('ERROR', `Reg Failed: ${e.message}`);
        res.status(400).json({ error: e.message }); 
    }
});

// LOGIN (OPTIONS)
app.get('/api/v1/auth/login-options', async (req, res) => {
    const user = Users.get(ADMIN_USER_ID);
    
    // IF SERVER FORGOT YOU, TELL CLIENT TO RE-REGISTER
    if (!user || user.credentials.length === 0) {
        Telemetry.log('AUTH', 'RAM Empty. Requesting Registration.');
        return res.status(404).json({ error: "NO IDENTITY" });
    }
    
    try {
        const allowed = user.credentials.map(c => ({ id: c.credentialID, type: 'public-key' }));
        const options = await generateAuthenticationOptions({ rpID: getRpId(req), allowCredentials: allowed, userVerification: 'preferred' });
        Challenges.set(options.challenge, { challenge: options.challenge, startTime: DreamsEngine.start() });
        res.json(options);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// LOGIN (VERIFY)
app.post('/api/v1/auth/login-verify', async (req, res) => {
    try {
        const json = Buffer.from(req.body.response.clientDataJSON, 'base64url').toString('utf8');
        const challengeString = JSON.parse(json).challenge;
        const challengeData = Challenges.get(challengeString);
        
        if (!challengeData) return res.status(400).json({ error: "Invalid Challenge" });

        const user = Users.get(ADMIN_USER_ID);
        const targetId = toBuffer(req.body.id);
        const match = user.credentials.find(c => Buffer.compare(c.credentialID, targetId) === 0);
        
        if (!match) {
            Telemetry.log('FAIL', 'Device Not Found in RAM');
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
            Telemetry.log('AUTH', 'Login Successful');
            res.json({ verified: true, token });
        } else { res.status(400).json({ verified: false }); }
    } catch (e) { 
        Telemetry.log('ERROR', `Login Crash: ${e.message}`);
        res.status(500).json({ error: e.message }); 
    }
});

// ==========================================
// 3. STATIC FILE SERVER
// ==========================================
const serve = (f, res) => fs.existsSync(path.join(publicPath, f)) ? res.sendFile(path.join(publicPath, f)) : res.status(404).send('Missing: ' + f);

app.get('/', (req, res) => serve('index.html', res));
app.get('/app', (req, res) => serve('app.html', res));
app.get('/dashboard', (req, res) => serve('dashboard.html', res));
app.get('/admin', (req, res) => serve('admin.html', res));
app.get('/sdk', (req, res) => serve('sdk.html', res));
app.get('*', (req, res) => res.redirect('/'));

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V143.2 ONLINE (Restored)`));
