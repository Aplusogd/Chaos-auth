import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';

// --- CONFIGURATION ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();

// CRITICAL: Render sets this env variable. We MUST use it.
// If it's undefined, we fallback to 3000 for local testing.
const PORT = process.env.PORT || 3000;

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());
app.use(express.static('public')); // Serves your HTML files

// --- HEALTH CHECK (For Render) ---
// This tells Render "I am alive" immediately.
app.get('/health', (req, res) => {
    res.status(200).send('OK');
});

// --- IN-MEMORY DATABASES ---
const KeyVault = new Map();
const RateLimit = new Map();
const Clients = new Set(); 

// --- SEED ADMIN KEY ---
const ADMIN_KEY = "sk_chaos_ee3aeaaaa3d193cee40bf7b2bc2e2432";
KeyVault.set(ADMIN_KEY, { 
    key: ADMIN_KEY, 
    client: "ADMIN_OVERRIDE", 
    scope: "full-access", 
    created: Date.now() 
});

// --- LIVE WIRE ---
const LiveWire = {
    broadcast: (type, data) => {
        const payload = `data: ${JSON.stringify({ type, data, time: Date.now() })}\n\n`;
        Clients.forEach(res => res.write(payload));
    }
};

// ==================================================================
// API ROUTES
// ==================================================================

app.get('/api/live-wire', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();
    Clients.add(res);
    req.on('close', () => Clients.delete(res));
    res.write(`data: ${JSON.stringify({ type: 'SYSTEM', data: 'CONNECTED' })}\n\n`);
});

app.post('/api/admin/verify', (req, res) => {
    const { token } = req.body;
    if (KeyVault.has(token)) res.json({ valid: true });
    else res.status(401).json({ valid: false });
});

app.post('/api/admin/keys/create', (req, res) => {
    const { token, clientName, scope } = req.body;
    if (token !== ADMIN_KEY) return res.status(403).json({ error: "FORBIDDEN" });

    const newKey = "sk_" + scope.split('-')[0] + "_" + crypto.randomBytes(8).toString('hex');
    KeyVault.set(newKey, { key: newKey, client: clientName, scope: scope, created: Date.now() });
    res.json({ success: true, key: newKey });
});

app.post('/api/auth/ghost-register', (req, res) => {
    const { alias, chaos_metric, provided_key } = req.body;
    if (!chaos_metric || chaos_metric === 0) {
        LiveWire.broadcast('THREAT', { status: 'BOT_BLOCKED', target: alias });
        return res.status(403).json({ error: "BIOMETRIC_FAIL" });
    }
    const ghostKey = provided_key || ("sk_guest_" + crypto.randomBytes(12).toString('hex'));
    KeyVault.set(ghostKey, { key: ghostKey, client: alias || "Anonymous", scope: "guest", created: Date.now(), trustScore: 50 });
    LiveWire.broadcast('SYSTEM', `GHOST IDENTITY ESTABLISHED: ${alias}`);
    res.json({ success: true, key: ghostKey });
});

app.post('/api/v1/sentinel/verify', (req, res) => {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey || !KeyVault.has(apiKey)) return res.status(401).json({ error: "INVALID_KEY", status: "DENIED" });

    const keyData = KeyVault.get(apiKey);
    const now = Date.now();
    const ageDays = (now - keyData.created) / (1000 * 60 * 60 * 24);
    
    let rank = "NEWBORN";
    let limit = 10; 
    if (keyData.scope === 'full-access') { rank = "GOD_MODE"; limit = 999999; }
    else {
        if (ageDays >= 30) { rank = "IMMORTAL"; limit = 9999; }
        else if (ageDays >= 14) { rank = "VETERAN"; limit = 300; }
        else if (ageDays >= 3) { rank = "SURVIVOR"; limit = 60; }
    }

    if (!RateLimit.has(apiKey)) RateLimit.set(apiKey, []);
    let usage = RateLimit.get(apiKey).filter(t => t > now - 60000); 
    if (usage.length >= limit) {
        LiveWire.broadcast('BLOCK', { reason: 'RATE_LIMIT', rank: rank, client: keyData.client });
        return res.status(429).json({ error: "RATE_LIMIT_EXCEEDED", rank, retryAfter: "60s" });
    }
    usage.push(now);
    RateLimit.set(apiKey, usage);
    
    const trustScore = Math.min(100, 50 + (ageDays * 2));
    LiveWire.broadcast('TRAFFIC', { status: 'VERIFIED', project: keyData.client, rank: rank, score: trustScore.toFixed(0) });
    
    res.json({ valid: true, status: "VERIFIED", trustScore: trustScore.toFixed(0), rank: rank, limit: limit + "/min", daysAlive: ageDays.toFixed(2), project: keyData.client });
});

app.post('/api/chaos-log', (req, res) => {
    const apiKey = req.headers['x-api-key'];
    if (!KeyVault.has(apiKey)) return res.status(401).json({ error: "UNAUTHORIZED" });
    LiveWire.broadcast('SYSTEM', `ARCHIVE: ${req.body.type || "DATA"} SAVED`);
    res.json({ success: true });
});

// --- ROUTING ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public/index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public/app.html')));
app.get('/abyss.html', (req, res) => res.sendFile(path.join(__dirname, 'public/abyss.html')));
app.get('/abyss-forge.html', (req, res) => res.sendFile(path.join(__dirname, 'public/abyss-forge.html')));
app.get('/check.html', (req, res) => res.sendFile(path.join(__dirname, 'public/check.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public/dashboard.html')));
app.get('/keyforge', (req, res) => res.sendFile(path.join(__dirname, 'public/keyforge.html')));
app.get('/tech-hub', (req, res) => res.sendFile(path.join(__dirname, 'public/tech-hub.html')));
app.get('/overwatch', (req, res) => res.sendFile(path.join(__dirname, 'public/overwatch.html')));
app.get('/sdk', (req, res) => res.sendFile(path.join(__dirname, 'public/sdk.html')));
app.get('/hydra', (req, res) => res.sendFile(path.join(__dirname, 'public/hydra.html')));
app.get('/dreams', (req, res) => res.sendFile(path.join(__dirname, 'public/dreams.html')));
app.get('/test-console', (req, res) => res.sendFile(path.join(__dirname, 'public/test-console.html')));

// --- START SERVER ---
// 0.0.0.0 is crucial for Render to route external traffic to your app
app.listen(PORT, '0.0.0.0', () => {
    console.log(`⚡ A+ CHAOS CORE V200 ONLINE`);
    console.log(`📡 LISTENING ON PORT ${PORT} (0.0.0.0)`);
    console.log(`🔒 ADMIN KEY LOADED`);
});
