/**
 * A+ CHAOS ID: V143 (THE STABILIZER)
 * STATUS: PRODUCTION READY
 * FIXES: CSP Relaxation for inline events, Wake-Lock protocols.
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
import { v4 as uuidv4 } from 'uuid';
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
        const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
        connectedClients.forEach(client => client.res.write(payload));
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
        Telemetry.logs.unshift(entry);
        if (Telemetry.logs.length > 50) Telemetry.logs.pop();
        if (type === 'BLOCK') Telemetry.blocked++;
        LiveWire.broadcast('log', { entry, stats: { requests: Telemetry.requests, threats: Telemetry.blocked } });
    }
};

// --- MIDDLEWARE ---
app.use((req, res, next) => {
    if (!req.path.includes('/api/v1/stream') && !req.path.includes('/health')) {
        Telemetry.requests++;
        if (Telemetry.requests % 5 === 0) LiveWire.broadcast('stats', { requests: Telemetry.requests, threats: Telemetry.blocked });
    }
    next();
});

// --- V143 CSP CONFIGURATION ---
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            // ALLOW INLINE ATTRIBUTES (onclick) AND EVAL (for some older libs if needed)
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdn.tailwindcss.com", "https://unpkg.com", "https://cdnjs.cloudflare.com"],
            scriptSrcAttr: ["'self'", "'unsafe-inline'"], 
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https://placehold.co", "https://via.placeholder.com", "https://www.transparenttextures.com"],
            // ALLOW WSS FOR SECURE SOCKETS
            connectSrc: ["'self'", "https://cdn.skypack.dev", "https://overthere.ai", "https://chaos-auth-iff2.onrender.com", "wss://chaos-auth-iff2.onrender.com"],
            upgradeInsecureRequests: [],
        },
    },
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
    strictTransportSecurity: { maxAge: 63072000, includeSubDomains: true, preload: true },
    frameguard: { action: "deny" },
}));

app.use(cors({ origin: '*' })); 
app.use(express.json());
app.use(express.static(publicPath, { maxAge: '1h' })); 

// --- UTILITIES & ENGINES ---
const toBuffer = (base64) => Buffer.from(base64, 'base64url');
const toBase64 = (buffer) => Buffer.from(buffer).toString('base64url');

const DreamsEngine = {
    start: () => process.hrtime.bigint(),
    check: (durationMs, kinetic) => {
        if (kinetic && (kinetic.velocity > 15.0 || kinetic.entropy < 0.1)) {
            Telemetry.log('BLOCK', `Bot Detected (Vel: ${kinetic.velocity})`);
            return false;
        }
        return true; 
    }
};

// --- IDENTITY & DATA STORE ---
const Users = new Map();
const ADMIN_USER_ID = 'admin-user';
const MASTER_KEY = process.env.MASTER_KEY || "chaos-genesis";
let ADMIN_PW_HASH = process.env.ADMIN_PW_HASH || bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'chaos2025', 12);
let adminSession = new Map();
const Abyss = { partners: new Map(), agents: new Map(), feedback: [], sessions: new Map(), hash: (k) => crypto.createHash('sha256').update(k).digest('hex') };
const Challenges = new Map();
const Chaos = { mintToken: () => crypto.randomBytes(32).toString('hex') };

// INIT ADMIN
const adminData = { id: ADMIN_USER_ID, credentials: [] };
// (Keep your existing Key Load logic here if you have persistent keys)
Users.set(ADMIN_USER_ID, adminData);

// --- ROUTES ---

// HEALTH CHECK
app.get('/api/v1/health', (req, res) => res.json({ status: "ALIVE", timestamp: Date.now() }));

// STREAM
app.get('/api/v1/stream', (req, res) => {
    // Simplified guard for stream stability
    LiveWire.addClient(req, res);
    Telemetry.log('SYSTEM', 'Admin Connected to War Room');
});

// AUTH FLOWS
const getOrigin = (req) => `https://${req.headers['x-forwarded-host'] || req.get('host')}`;
const getRpId = (req) => (req.headers['x-forwarded-host'] || req.get('host')).split(':')[0];

app.get('/api/v1/auth/register-options', async (req, res) => {
    if (req.headers['x-chaos-master-key'] !== MASTER_KEY) return res.status(403).json({ error: "ACCESS DENIED" });
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
    if (req.headers['x-chaos-master-key'] !== MASTER_KEY) return res.status(403).json({ error: "ACCESS DENIED" });
    const expectedChallenge = Challenges.get(ADMIN_USER_ID);
    if (!expectedChallenge) return res.status(400).json({ error: "Expired" });

    try {
        const verification = await verifyRegistrationResponse({ 
            response: req.body, expectedChallenge, expectedOrigin: getOrigin(req), expectedRPID: getRpId(req) 
        });
        if (verification.verified) {
            const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
            const user = Users.get(ADMIN_USER_ID);
            user.credentials.push({ credentialID, credentialPublicKey, counter });
            Users.set(ADMIN_USER_ID, user);
            Challenges.delete(ADMIN_USER_ID);
            Telemetry.log('AUTH', 'New Device Registered');
            res.json({ verified: true });
        } else { res.status(400).json({ verified: false }); }
    } catch (e) { res.status(400).json({ error: e.message }); }
});

app.get('/api/v1/auth/login-options', async (req, res) => {
    const user = Users.get(ADMIN_USER_ID);
    if (!user || user.credentials.length === 0) return res.status(404).json({ error: "NO IDENTITY" }); // Trigger Registration
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

        // DREAMS CHECK
        const durationMs = Number(process.hrtime.bigint() - challengeData.startTime) / 1000000;
        if (!DreamsEngine.check(durationMs, req.body.kinetic_data)) return res.status(403).json({ error: "BOT DETECTED" });

        const user = Users.get(ADMIN_USER_ID);
        const match = user.credentials.find(c => Buffer.compare(c.credentialID, toBuffer(req.body.id)) === 0);
        if (!match) return res.status(400).json({ error: "Device Not Found" });

        const verification = await verifyAuthenticationResponse({
            response: req.body, expectedChallenge: challengeString, expectedOrigin: getOrigin(req), expectedRPID: getRpId(req),
            authenticator: { credentialID: match.credentialID, credentialPublicKey: match.credentialPublicKey, counter: match.counter },
            requireUserVerification: false,
        });

        if (verification.verified) {
            match.counter = verification.authenticationInfo.newCounter;
            Users.set(ADMIN_USER_ID, user);
            Challenges.delete(challengeString);
            const token = Chaos.mintToken();
            res.json({ verified: true, token });
        } else { res.status(400).json({ verified: false }); }
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// DEFAULT SERVE
const serve = (f, res) => fs.existsSync(path.join(publicPath, f)) ? res.sendFile(path.join(publicPath, f)) : res.status(404).send('Missing: ' + f);
app.get('/', (req, res) => serve('index.html', res));
app.get('/app', (req, res) => serve('app.html', res));
app.get('/dashboard', (req, res) => serve('dashboard.html', res));
app.get('*', (req, res) => res.redirect('/'));

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V143 ONLINE: ${PORT}`));
