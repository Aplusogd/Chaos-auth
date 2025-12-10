/**
 * A+ CHAOS ID: V170 (DEVELOPER ECOSYSTEM)
 * STATUS: PRODUCTION
 * NEW: Developer Registration, Sandbox Keys, and Rate Limiting.
 */
import express from 'express';
import path from 'path';
import cors from 'cors';
import fs from 'fs';
import crypto from 'crypto';
import helmet from 'helmet';
import { fileURLToPath } from 'url';
import { dirname } from 'path';     

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

// --- DATA STORES ---
const KeyVault = new Map(); // Stores API Keys
const RateLimit = new Map(); // Tracks Usage

// --- LIVE WIRE ---
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

// --- API ROUTES ---

// 1. DEVELOPER REGISTRATION (Sign-In Logic)
app.post('/api/developer/register', (req, res) => {
    const { email, project, useCase } = req.body;
    
    if (!email || !project) return res.status(400).json({ error: "Missing Info" });

    // Mint Sandbox Key
    const newApiKey = "sk_test_" + crypto.randomBytes(8).toString('hex');
    const keyData = {
        key: newApiKey,
        owner: email,
        project: project,
        useCase: useCase,
        scope: "sandbox", // Limited access
        created: Date.now(),
        status: "ACTIVE"
    };

    KeyVault.set(newApiKey, keyData);
    
    // Notify Admin Dashboard
    console.log(`>>> [DEV PORTAL] New Project: ${project} (${email})`);
    LiveWire.broadcast('SYSTEM', `NEW DEVELOPER: ${project}`);
    
    res.json({ success: true, key: newApiKey, limit: "50 req/hour" });
});

// 2. VERIFY API KEY (The Endpoint Developers Call)
app.post('/api/v1/sentinel/verify', (req, res) => {
    const apiKey = req.headers['x-api-key'];
    
    // Check Key Existence
    if (!apiKey || !KeyVault.has(apiKey)) {
        return res.status(401).json({ error: "INVALID_API_KEY" });
    }

    const keyData = KeyVault.get(apiKey);

    // RATE LIMITING CHECK
    const now = Date.now();
    const windowStart = now - 3600000; // 1 hour ago
    
    // Initialize usage array if missing
    if (!RateLimit.has(apiKey)) RateLimit.set(apiKey, []);
    let usage = RateLimit.get(apiKey);
    
    // Filter old requests
    usage = usage.filter(t => t > windowStart);
    
    // Check Limit (Sandbox = 50 per hour)
    if (keyData.scope === 'sandbox' && usage.length >= 50) {
        LiveWire.broadcast('BLOCK', { reason: 'RATE_LIMIT_EXCEEDED', project: keyData.project });
        return res.status(429).json({ error: "RATE_LIMIT_EXCEEDED" });
    }

    // Log Request
    usage.push(now);
    RateLimit.set(apiKey, usage);
    
    // Mock Verification Logic (Developers would send entropy here)
    LiveWire.broadcast('TRAFFIC', { status: 'API_CALL', project: keyData.project });
    res.json({ valid: true, trustScore: 100, status: "VERIFIED" });
});

// ... (Existing Routes: /api/live-wire, /api/unlock, /api/chaos-log, etc.)
app.get('/api/live-wire', LiveWire.addClient);
app.post('/api/unlock', (req, res) => { res.json({ success: true, content: "<h1>Protected Content</h1>" }); }); // Simplified for brevity
app.post('/api/chaos-log', (req, res) => { LiveWire.broadcast('THREAT', req.body); res.sendStatus(200); });
app.post('/api/admin/verify', (req, res) => { 
    if(req.body.token && req.body.token.length > 30) res.json({valid:true}); else res.status(403).json({valid:false}); 
});
// ... (Auth/Demo Routes)

// --- FILE SERVING ---
const serve = (f, res) => fs.existsSync(path.join(publicPath, f)) ? res.sendFile(path.join(publicPath, f)) : res.status(404).send('Missing: ' + f);

app.get('/', (req, res) => serve('index.html', res));
app.get('/app', (req, res) => serve('app.html', res));
app.get('/dashboard', (req, res) => serve('dashboard.html', res));
app.get('/dreams', (req, res) => serve('dreams.html', res));
app.get('/keyforge', (req, res) => serve('keyforge.html', res));
app.get('/sdk', (req, res) => serve('sdk.html', res)); // THE NEW PORTAL

app.get('*', (req, res) => res.redirect('/'));

try {
    app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V170 ONLINE (DEV PORTAL ACTIVE)`));
} catch (e) { console.error(`>>> [FATAL]`, e.message); }
