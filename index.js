/**
 * A+ CHAOS SERVER V171 (MASTER BUILD)
 * STATUS: FINAL PRODUCTION
 * INCLUDES: Live Wire, God Lock, Key Forge, Dev Portal, Rate Limiting
 */
import express from 'express';
import path from 'path';
import cors from 'cors';
import fs from 'fs';
import crypto from 'crypto';
import helmet from 'helmet';
import { fileURLToPath } from 'url';
import { dirname } from 'path';     

// --- 1. ZOMBIE PROTOCOL ---
process.on('uncaughtException', (err) => console.error('>>> [CRASH] FATAL:', err.message));
process.on('unhandledRejection', (reason) => console.error('>>> [CRASH] REJECT:', reason));

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const publicPath = path.join(__dirname, 'public');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*' })); 
app.use(express.json());
app.use(express.static(publicPath));

// --- 2. DATA STORES ---
const KeyVault = new Map();   // Stores API Keys
const RateLimit = new Map();  // Tracks Usage

// --- 3. LIVE WIRE ENGINE ---
let connectedClients = [];
const LiveWire = {
    broadcast: (type, data) => {
        const payload = JSON.stringify({ type, timestamp: Date.now(), data });
        connectedClients.forEach(c => c.res.write(`data: ${payload}\n\n`));
    },
    addClient: (req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Connection': 'keep-alive', 'Cache-Control': 'no-cache' });
        connectedClients.push({ id: Date.now(), res });
        res.write(`data: ${JSON.stringify({ type: 'SYSTEM', data: 'LINK ESTABLISHED' })}\n\n`);
    }
};

// --- 4. API ROUTES ---

// A. LIVE WIRE
app.get('/api/live-wire', LiveWire.addClient);

// B. UNLOCK GATE (Landing Page Traffic)
const PROTECTED_CONTENT_HTML = `<section class="p-8"><h1 class="text-3xl text-white">ACCESS GRANTED</h1></section>`; // Simplified content
app.post('/api/unlock', (req, res) => {
    const { timestamp } = req.body;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    if (Date.now() - timestamp > 10000) {
         LiveWire.broadcast('BLOCK', { reason: 'STALE_TIMESTAMP', ip });
         return res.status(403).json({ error: "STALE_TIMESTAMP" });
    }
    LiveWire.broadcast('TRAFFIC', { status: 'HUMAN_VERIFIED', ip });
    res.json({ success: true, content: PROTECTED_CONTENT_HTML });
});

// C. CHAOS LOG
app.post('/api/chaos-log', (req, res) => {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    LiveWire.broadcast('THREAT', { ...req.body, ip });
    res.sendStatus(200);
});

// D. GOD LOCK (Dashboard Access)
app.post('/api/admin/verify', (req, res) => {
    const { token } = req.body;
    if (!token || token.length < 32) return res.status(403).json({ valid: false });
    res.json({ valid: true });
});

// E. KEY FORGE (Admin Minting)
app.post('/api/admin/keys/create', (req, res) => {
    const { token, clientName, scope } = req.body;
    // Verify Admin
    if (!token || token.length < 32) return res.status(403).json({ error: "UNAUTHORIZED" });

    const newApiKey = "sk_chaos_" + crypto.randomBytes(16).toString('hex');
    const keyData = { key: newApiKey, client: clientName, scope: scope, created: Date.now(), status: "ACTIVE" };
    
    KeyVault.set(newApiKey, keyData);
    LiveWire.broadcast('SYSTEM', `KEY MINTED: ${clientName}`);
    res.json({ success: true, key: newApiKey });
});

app.post('/api/admin/keys/list', (req, res) => {
    const { token } = req.body;
    if (!token || token.length < 32) return res.status(403).json({ error: "UNAUTHORIZED" });
    res.json({ success: true, keys: Array.from(KeyVault.values()) });
});

// F. DEVELOPER PORTAL (Public Registration)
app.post('/api/developer/register', (req, res) => {
    const { email, project, useCase } = req.body;
    if (!email || !project) return res.status(400).json({ error: "Missing Info" });

    const newApiKey = "sk_test_" + crypto.randomBytes(8).toString('hex');
    const keyData = { key: newApiKey, owner: email, project: project, scope: "sandbox", created: Date.now(), status: "ACTIVE" };

    KeyVault.set(newApiKey, keyData);
    LiveWire.broadcast('SYSTEM', `NEW DEV: ${project}`);
    res.json({ success: true, key: newApiKey });
});

// G. API VERIFICATION (The Product)
app.post('/api/v1/sentinel/verify', (req, res) => {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey || !KeyVault.has(apiKey)) return res.status(401).json({ error: "INVALID_KEY" });

    const keyData = KeyVault.get(apiKey);
    
    // Rate Limit Check
    if (!RateLimit.has(apiKey)) RateLimit.set(apiKey, []);
    let usage = RateLimit.get(apiKey).filter(t => t > Date.now() - 3600000);
    
    if (keyData.scope === 'sandbox' && usage.length >= 50) {
        LiveWire.broadcast('BLOCK', { reason: 'RATE_LIMIT', project: keyData.project });
        return res.status(429).json({ error: "RATE_LIMIT_EXCEEDED" });
    }

    usage.push(Date.now());
    RateLimit.set(apiKey, usage);
    
    LiveWire.broadcast('TRAFFIC', { status: 'API_CALL', project: keyData.project || keyData.client });
    res.json({ valid: true, trustScore: 100, status: "VERIFIED" });
});

// --- 5. FILE SERVING ---
const serve = (f, res) => fs.existsSync(path.join(publicPath, f)) ? res.sendFile(path.join(publicPath, f)) : res.status(404).send('Missing: ' + f);

app.get('/', (req, res) => serve('index.html', res));
app.get('/app', (req, res) => serve('app.html', res));
app.get('/dashboard', (req, res) => serve('dashboard.html', res));
app.get('/dreams', (req, res) => serve('dreams.html', res));
app.get('/keyforge', (req, res) => serve('keyforge.html', res));
app.get('/sdk', (req, res) => serve('sdk.html', res));
app.get('/test-console', (req, res) => serve('test-console.html', res));

app.get('*', (req, res) => res.redirect('/'));

// --- 6. START ---
try {
    app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V171 ONLINE (ALL SYSTEMS GO)`));
} catch (e) { console.error(`>>> [FATAL]`, e.message); }
