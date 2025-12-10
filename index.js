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
    res.status(200).send('OK');
});

// --- IN-MEMORY DATABASES (The Vault) ---
const KeyVault = new Map();
const RateLimit = new Map();
const Clients = new Set(); 

// --- SEED ADMIN KEY (Security Priority) ---
const ADMIN_KEY = "sk_chaos_ee3aeaaaa3d193cee40bf7b2bc2e2432";
KeyVault.set(ADMIN_KEY, { 
    key: ADMIN_KEY, 
    client: "ADMIN_OVERRIDE", 
    scope: "full-access", 
    created: Date.now() 
});

// --- API ROUTES (Functional Core) ---
app.post('/api/admin/verify', (req, res) => {
    const { token } = req.body;
    if (KeyVault.has(token)) res.json({ valid: true });
    else res.status(401).json({ valid: false });
});

app.post('/api/auth/ghost-register', (req, res) => {
    const { alias, chaos_metric, provided_key } = req.body;
    const ghostKey = provided_key || ("sk_guest_" + crypto.randomBytes(12).toString('hex'));
    KeyVault.set(ghostKey, { key: ghostKey, client: alias || "Anonymous", scope: "guest", created: Date.now(), trustScore: 50 });
    res.json({ success: true, key: ghostKey });
});

app.post('/api/v1/sentinel/verify', (req, res) => {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey || !KeyVault.has(apiKey)) return res.status(401).json({ error: "INVALID_KEY", status: "DENIED" });
    
    const keyData = KeyVault.get(apiKey);
    const ageDays = (Date.now() - keyData.created) / (1000 * 60 * 60 * 24);
    
    let rank = "NEWBORN";
    if (keyData.scope === 'full-access') rank = "GOD_MODE";
    else if (ageDays >= 30) rank = "IMMORTAL";

    const trustScore = Math.min(100, 50 + (ageDays * 2));
    
    res.json({ valid: true, status: "VERIFIED", trustScore: trustScore.toFixed(0), rank: rank, project: keyData.client });
});

// ==================================================================
// ROUTING (Definitive Mapping)
// ==================================================================

// 1. LANDING PAGE
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public/index.html')));

// 2. FORGE (Callsign Creation)
app.get('/forge', (req, res) => res.sendFile(path.join(__dirname, 'public/abyss.html')));

// 3. LOGIN PAGE (Biometric Trace Login) - FIX IS HERE
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public/app.html'))); 

// 4. SANCTUARY (User Dashboard)
app.get('/sanctuary', (req, res) => res.sendFile(path.join(__dirname, 'public/check.html')));

// 5. PROFILE/CALIBRATE (Advanced Training)
app.get('/profile/calibrate', (req, res) => res.sendFile(path.join(__dirname, 'public/abyss-forge.html')));

// --- UTILITY PAGES ---
app.get('/logout', (req, res) => res.sendFile(path.join(__dirname, 'public/logout.html')));
app.get('/error', (req, res) => res.sendFile(path.join(__dirname, 'public/error.html')));

// --- Fallback Routing (Ensures old links redirect to clean ones) ---
app.get('/abyss.html', (req, res) => res.redirect(301, '/forge'));
app.get('/app.html', (req, res) => res.redirect(301, '/login')); 
app.get('/check.html', (req, res) => res.redirect(301, '/sanctuary'));


// --- START SERVER ---
app.listen(PORT, '0.0.0.0', () => {
    console.log(`⚡ A+ CHAOS CORE V227 ONLINE`);
    console.log(`📡 LISTENING ON PORT ${PORT}`);
});
