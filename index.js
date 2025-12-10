import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';

// --- CONFIGURATION ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = process.env.PORT || 3000;

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());
app.use(express.static('public')); // Serves your HTML files

// --- IN-MEMORY DATABASES (The Vault) ---
const KeyVault = new Map();
const RateLimit = new Map();
const Clients = new Set(); // For LiveWire dashboard connections

// --- SEED ADMIN KEY (God Mode) ---
const ADMIN_KEY = "sk_chaos_ee3aeaaaa3d193cee40bf7b2bc2e2432";
KeyVault.set(ADMIN_KEY, { 
    key: ADMIN_KEY, 
    client: "ADMIN_OVERRIDE", 
    scope: "full-access", 
    created: Date.now() 
});

// --- LIVE WIRE (Real-Time Dashboard Stream) ---
const LiveWire = {
    broadcast: (type, data) => {
        const payload = `data: ${JSON.stringify({ type, data, time: Date.now() })}\n\n`;
        Clients.forEach(res => res.write(payload));
    }
};

// ==================================================================
// API ROUTES
// ==================================================================

// 1. LIVE WIRE ENDPOINT (Dashboard listens here)
app.get('/api/live-wire', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    Clients.add(res);
    req.on('close', () => Clients.delete(res));
    res.write(`data: ${JSON.stringify({ type: 'SYSTEM', data: 'CONNECTED' })}\n\n`);
});

// 2. ADMIN VERIFICATION (Login Screen Logic)
app.post('/api/admin/verify', (req, res) => {
    const { token } = req.body;
    if (KeyVault.has(token)) {
        res.json({ valid: true });
    } else {
        res.status(401).json({ valid: false });
    }
});

// 3. KEY MINTING (Key Forge Logic)
app.post('/api/admin/keys/create', (req, res) => {
    const { token, clientName, scope } = req.body;
    if (token !== ADMIN_KEY) return res.status(403).json({ error: "FORBIDDEN" });

    const newKey = "sk_" + scope.split('-')[0] + "_" + crypto.randomBytes(8).toString('hex');
    
    KeyVault.set(newKey, {
        key: newKey,
        client: clientName,
        scope: scope,
        created: Date.now()
    });

    res.json({ success: true, key: newKey });
});

// 4. GHOST REGISTER (Anonymous Identity - SELF-HEALING)
app.post('/api/auth/ghost-register', (req, res) => {
    const { alias, chaos_metric, provided_key } = req.body;

    // A. Silent Bot Check
    if (!chaos_metric || chaos_metric === 0) {
        LiveWire.broadcast('THREAT', { status: 'BOT_BLOCKED', target: alias });
        return res.status(403).json({ error: "BIOMETRIC_FAIL" });
    }

    // B. Key Logic (The Fix)
    // We accept the key calculated by the client (from words/trace) or mint a new one.
    const ghostKey = provided_key || ("sk_guest_" + crypto.randomBytes(12).toString('hex'));

    // C. Store in Vault
    KeyVault.set(ghostKey, { 
        key: ghostKey, 
        client: alias || "Anonymous", 
        scope: "guest", 
        created: Date.now(),
        trustScore: 50
    });
    
    LiveWire.broadcast('SYSTEM', `GHOST IDENTITY ESTABLISHED: ${alias}`);
    res.json({ success: true, key: ghostKey });
});

// 5. SENTINEL VERIFY (Trust Engine & Reputation Ramp)
app.post('/api/v1/sentinel/verify', (req, res) => {
    const apiKey = req.headers['x-api-key'];
    
    if (!apiKey || !KeyVault.has(apiKey)) {
        return res.status(401).json({ error: "INVALID_KEY", status: "DENIED" });
    }

    const keyData = KeyVault.get(apiKey);
    
    // Reputation Logic
    const now = Date.now();
    const ageDays = (now - keyData.created) / (1000 * 60 * 60 * 24);
    
    let rank = "NEWBORN";
    let limit = 10; 

    if (keyData.scope === 'full-access') {
        rank = "GOD_MODE";
        limit = 999999;
    } else {
        if (ageDays >= 30) { rank = "IMMORTAL"; limit = 9999; }
        else if (ageDays >= 14) { rank = "VETERAN"; limit = 300; }
        else if (ageDays >= 3) { rank = "SURVIVOR"; limit = 60; }
    }

    // Rate Limiting
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
    
    res.json({ 
        valid: true, 
        status: "VERIFIED",
        trustScore: trustScore.toFixed(0), 
        rank: rank, 
        limit: limit + "/min"
    });
});

// 6. CHAOS LOG (Secure Archive)
app.post('/api/chaos-log', (req, res) => {
    const apiKey = req.headers['x-api-key'];
    if (!KeyVault.has(apiKey)) return res.status(401).json({ error: "UNAUTHORIZED" });

    const payload = req.body;
    LiveWire.broadcast('SYSTEM', `ARCHIVE: ${payload.type || "DATA"} SAVED`);
    res.json({ success: true, timestamp: Date.now() });
});

// --- PAGE ROUTING ---
// These match your file structure:
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public/index.html')));          // Landing Page
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public/login.html')));     // Admin Login (Make sure this file exists!)
app.get('/abyss.html', (req, res) => res.sendFile(path.join(__dirname, 'public/abyss.html'))); // Biometric Gate
app.get('/check.html', (req, res) => res.sendFile(path.join(__dirname, 'public/check.html'))); // Status Dashboard
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public/dashboard.html'))); // Admin Dash
app.get('/keyforge', (req, res) => res.sendFile(path.join(__dirname, 'public/keyforge.html')));   // Key Minting

// --- START SERVER ---
app.listen(PORT, () => {
    console.log(`⚡ A+ CHAOS CORE V188 ONLINE: PORT ${PORT}`);
    console.log(`🔒 GOD KEY ACTIVE: ${ADMIN_KEY.substring(0, 10)}...`);
});
