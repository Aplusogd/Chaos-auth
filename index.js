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
app.use(express.static('public')); 

// --- HEALTH CHECK (For Render) ---
app.get('/health', (req, res) => {
    res.status(200).send('OK');
});

// --- IN-MEMORY DATABASES (Phase 9 - Live Wire) ---
const KeyVault = new Map();
const RateLimit = new Map();
const Clients = new Set(); 

// --- SEED ADMIN KEY (God Mode) ---
const ADMIN_KEY = "sk_chaos_ee3aeaaaa3d193cee40bf7b2bc2e2432";
KeyVault.set(ADMIN_KEY, { 
    key: ADMIN_KEY, 
    client: "ADMIN_OVERRIDE", 
    scope: "full-access", 
    created: Date.now() 
});

// --- LIVE WIRE (Simplified) ---
const LiveWire = {
    broadcast: (type, data) => {
        const payload = `data: ${JSON.stringify({ type, data, time: Date.now() })}\n\n`;
        Clients.forEach(res => res.write(payload));
    }
};

// ==================================================================
// API ROUTES
// ==================================================================

app.post('/api/admin/verify', (req, res) => {
    const { token } = req.body;
    if (KeyVault.has(token)) res.json({ valid: true });
    else res.status(401).json({ valid: false });
});

app.post('/api/auth/ghost-register', (req, res) => {
    const { alias, chaos_metric, provided_key } = req.body;
    if (!chaos_metric || chaos_metric === 0) {
        LiveWire.broadcast('THREAT', { status: 'BOT_BLOCKED', target: alias });
        return res.status(403).json({ error: "BIOMETRIC_FAIL" });
    }
    const ghostKey = provided_key || ("sk_guest_" + crypto.randomBytes(12).toString('hex'));
    KeyVault.set(ghostKey, { key: ghostKey, client: alias || "Anonymous", scope: "guest", created: Date.now(), trustScore: 50 });
    res.json({ success: true, key: ghostKey });
});

app.post('/api/v1/sentinel/verify', (req, res) => {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey || !KeyVault.has(apiKey)) return res.status(401).json({ error: "INVALID_KEY", status: "DENIED" });

    const keyData = KeyVault.get(apiKey);
    const now = Date.now();
    const ageDays = (now - keyData.created) / (1000 * 60 * 60 * 24);
    
    // Simplified Rank/Limit calculation for stability
    let rank = "NEWBORN";
    let limit = 10; 
    if (keyData.scope === 'full-access') { rank = "GOD_MODE"; limit = 999999; }
    else if (ageDays >= 30) { rank = "IMMORTAL"; limit = 9999; }
    else if (ageDays >= 3) { rank = "SURVIVOR"; limit = 60; }

    const trustScore = Math.min(100, 50 + (ageDays * 2));
    
    // Mock the response data needed by check.html
    res.json({ valid: true, status: "VERIFIED", trustScore: trustScore.toFixed(0), rank: rank, limit: limit + "/min", project: keyData.client });
});

// ==================================================================
// ROUTING (All files wired)
// ==================================================================
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public/index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public/app.html')));
app.get('/abyss.html', (req, res) => res.sendFile(path.join(__dirname, 'public/abyss.html')));
app.get('/abyss-forge.html', (req, res) => res.sendFile(path.join(__dirname, 'public/abyss-forge.html')));

// --- CORE PAGES ---
app.get('/abyss-search.html', (req, res) => res.sendFile(path.join(__dirname, 'public/abyss-search.html'))); 
app.get('/check.html', (req, res) => res.sendFile(path.join(__dirname, 'public/check.html')));

// --- OTHER TOOLS (For Dashboard links) ---
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public/dashboard.html')));
app.get('/keyforge', (req, res) => res.sendFile(path.join(__dirname, 'public/keyforge.html')));
app.get('/tech-hub', (req, res) => res.sendFile(path.join(__dirname, 'public/tech-hub.html')));
app.get('/overwatch', (req, res) => res.sendFile(path.join(__dirname, 'public/overwatch.html')));
app.get('/sdk', (req, res) => res.sendFile(path.join(__dirname, 'public/sdk.html')));
app.get('/hydra', (req, res) => res.sendFile(path.join(__dirname, 'public/hydra.html')));


app.listen(PORT, '0.0.0.0', () => {
    console.log(`⚡ A+ CHAOS CORE V211 (FINAL PHASE 9) ONLINE`);
    console.log(`📡 LISTENING ON PORT ${PORT}`);
});
