/**
 * A+ CHAOS ID: V169 (KEY FORGE ENABLED)
 * STATUS: PRODUCTION
 * NEW: Adds /api/admin/keys endpoints to mint and manage API keys.
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

// --- MOCK DATABASE (In-Memory for now) ---
// In a real app, this would be a MongoDB or SQL database.
const KeyVault = new Map(); 

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

// --- CONTENT ---
const PROTECTED_CONTENT_HTML = ``;

// --- API ROUTES ---

// 1. LIVE WIRE
app.get('/api/live-wire', LiveWire.addClient);

// 2. UNLOCK GATE
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

// 3. CHAOS LOG
app.post('/api/chaos-log', (req, res) => {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    LiveWire.broadcast('THREAT', { ...req.body, ip });
    res.sendStatus(200);
});

// 4. GOD LOCK (Admin Verify)
app.post('/api/admin/verify', (req, res) => {
    const { token } = req.body;
    if (!token || token.length < 32) return res.status(403).json({ valid: false });
    res.json({ valid: true });
});

// 5. KEY FORGE (New API Key Management)
app.post('/api/admin/keys/create', (req, res) => {
    // 1. Verify Admin Token First (God Lock)
    const { token, clientName, scope } = req.body;
    if (!token || token.length < 32) return res.status(403).json({ error: "UNAUTHORIZED" });

    // 2. Mint New Key
    const newApiKey = "sk_chaos_" + crypto.randomBytes(16).toString('hex');
    const keyData = {
        key: newApiKey,
        client: clientName || "Unknown Client",
        scope: scope || "read-only",
        created: Date.now(),
        status: "ACTIVE"
    };

    // 3. Store (In-Memory for demo)
    KeyVault.set(newApiKey, keyData);
    
    // 4. Log
    console.log(`>>> [KEY FORGE] Minted key for ${clientName}`);
    LiveWire.broadcast('SYSTEM', `NEW KEY MINTED: ${clientName}`);
    
    res.json({ success: true, key: newApiKey });
});

app.post('/api/admin/keys/list', (req, res) => {
    const { token } = req.body;
    if (!token || token.length < 32) return res.status(403).json({ error: "UNAUTHORIZED" });
    
    // Convert Map to Array for frontend
    const keys = Array.from(KeyVault.values());
    res.json({ success: true, keys });
});


// --- FILE SERVING ---
const serve = (f, res) => fs.existsSync(path.join(publicPath, f)) ? res.sendFile(path.join(publicPath, f)) : res.status(404).send('Missing: ' + f);

// Client Injection Logic
const SENTINEL_SDK_CODE = `/* Code Omitted */`; 
app.get('/', (req, res) => serve('index.html', res));

app.get('/app', (req, res) => serve('app.html', res));
app.get('/dashboard', (req, res) => serve('dashboard.html', res));
app.get('/dreams', (req, res) => serve('dreams.html', res));
app.get('/keyforge', (req, res) => serve('keyforge.html', res)); // THE NEW PAGE

app.get('*', (req, res) => res.redirect('/'));

// --- START ---
try {
    app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V169 ONLINE (KEY FORGE ACTIVE)`));
} catch (e) { console.error(`>>> [FATAL]`, e.message); }
