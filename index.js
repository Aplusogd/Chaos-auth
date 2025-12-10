import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';

// --- CONFIGURATION ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
// CRITICAL: Use the port assigned by the host (Render) or default to 3000
const PORT = process.env.PORT || 3000; 

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());
// Serves all your HTML, CSS, JS files from the 'public' folder
app.use(express.static('public')); 

// --- HEALTH CHECK (For Render Stability) ---
app.get('/health', (req, res) => {
    // Responds 200 OK immediately to satisfy cloud host uptime checks
    res.status(200).send('OK');
});

// --- IN-MEMORY DATABASES (Phase 9 - Live Wire) ---
const KeyVault = new Map();
const RateLimit = new Map();
const Clients = new Set(); 

// --- SEED ADMIN KEY (Security Priority: Ensures YOU are never locked out) ---
const ADMIN_KEY = "sk_chaos_ee3aeaaaa3d193cee40bf7b2bc2e2432";
KeyVault.set(ADMIN_KEY, { 
    key: ADMIN_KEY, 
    client: "ADMIN_OVERRIDE", 
    scope: "full-access", 
    created: Date.now() 
});

// --- LIVE WIRE (Simplified event broadcast) ---
const LiveWire = {
    broadcast: (type, data) => {
        const payload = `data: ${JSON.stringify({ type, data, time: Date.now() })}\n\n`;
        Clients.forEach(res => res.write(payload));
    }
};

// ==================================================================
// API ROUTES (Self-Healing / Verification)
// ==================================================================

// 1. ADMIN VERIFY (Used for auto-login/session check)
app.post('/api/admin/verify', (req, res) => {
    const { token } = req.body;
    if (KeyVault.has(token)) res.json({ valid: true });
    else res.status(401).json({ valid: false });
});

// 2. GHOST REGISTER (Used for Callsign creation AND Self-Healing Login)
app.post('/api/auth/ghost-register', (req, res) => {
    const { alias, chaos_metric, provided_key } = req.body;
    
    // Minimal anti-bot check
    if (!chaos_metric || chaos_metric === 0) {
        return res.status(403).json({ error: "BIOMETRIC_FAIL" });
    }
    
    const ghostKey = provided_key || ("sk_guest_" + crypto.randomBytes(12).toString('hex'));
    KeyVault.set(ghostKey, { key: ghostKey, client: alias || "Anonymous", scope: "guest", created: Date.now(), trustScore: 50 });
    
    res.json({ success: true, key: ghostKey });
});

// 3. SENTINEL VERIFY (Used by check.html to pull rank/trust score)
app.post('/api/v1/sentinel/verify', (req, res) => {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey || !KeyVault.has(apiKey)) return res.status(401).json({ error: "INVALID_KEY", status: "DENIED" });

    const keyData = KeyVault.get(apiKey);
    const now = Date.now();
    const ageDays = (now - keyData.created) / (1000 * 60 * 60 * 24);
    
    // Security and Trust Logic
    let rank = "NEWBORN";
    let limit = 10; 
    if (keyData.scope === 'full-access') { rank = "GOD_MODE"; limit = 999999; }
    else if (ageDays >= 30) { rank = "IMMORTAL"; limit = 9999; }
    else if (ageDays >= 3) { rank = "SURVIVOR"; limit = 60; }

    const trustScore = Math.min(100, 50 + (ageDays * 2));
    
    res.json({ valid: true, status: "VERIFIED", trustScore: trustScore.toFixed(0), rank: rank, limit: limit + "/min", project: keyData.client });
});

// ==================================================================
// ROUTING (Deep Think: Mapping the 3 Files)
// ==================================================================

// 1. LANDING PAGE
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public/index.html')));

// 2. CREATION PAGE (Chaos Forge)
app.get('/abyss.html', (req, res) => res.sendFile(path.join(__dirname, 'public/abyss.html')));

// 3. LOGIN PAGE (Biometric Trace Login)
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public/app.html')));


// --- POST-LOGIN PAGES ---
app.get('/abyss-forge.html', (req, res) => res.sendFile(path.join(__dirname, 'public/abyss-forge.html'))); // Sigil Calibration/Training
app.get('/abyss-search.html', (req, res) => res.sendFile(path.join(__dirname, 'public/abyss-search.html'))); // Loading Screen
app.get('/check.html', (req, res) => res.sendFile(path.join(__dirname, 'public/check.html'))); // Sanctuary Dashboard
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public/dashboard.html'))); // Admin Dashboard (Original name)


// --- START SERVER ---
// Binding to 0.0.0.0 is crucial for external cloud access
app.listen(PORT, '0.0.0.0', () => {
    console.log(`⚡ A+ CHAOS CORE V218 ONLINE`);
    console.log(`📡 LISTENING ON PORT ${PORT} (Admin Key Secure)`);
});
