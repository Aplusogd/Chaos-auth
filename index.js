/**
 * A+ CHAOS ID: V167 (LIVE WIRE SERVER)
 * STATUS: PRODUCTION
 * NEW: Adds Server-Sent Events (SSE) to pipe real-time logs to the Dashboard.
 */
import express from 'express';
import path from 'path';
import cors from 'cors';
import fs from 'fs';
import crypto from 'crypto';
import helmet from 'helmet';
import { fileURLToPath } from 'url';
import { dirname } from 'path';     

// --- ZOMBIE PROTOCOL ---
process.on('uncaughtException', (err) => console.error('>>> [CRASH] FATAL:', err.message));
process.on('unhandledRejection', (reason) => console.error('>>> [CRASH] REJECT:', reason));

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const publicPath = path.join(__dirname, 'public');

const app = express();
const PORT = process.env.PORT || 3000;

// --- MIDDLEWARE ---
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*' })); 
app.use(express.json());
app.use(express.static(publicPath));

// --- LIVE WIRE ENGINE (Real-Time Feed) ---
let connectedClients = [];

const LiveWire = {
    // Send data to all connected dashboards
    broadcast: (type, data) => {
        const payload = JSON.stringify({ type, timestamp: Date.now(), data });
        connectedClients.forEach(client => {
            try {
                client.res.write(`data: ${payload}\n\n`);
            } catch(e) { /* Client disconnected */ }
        });
    },
    // Handle new dashboard connection
    addClient: (req, res) => {
        const headers = {
            'Content-Type': 'text/event-stream',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache'
        };
        res.writeHead(200, headers);
        const clientId = Date.now();
        const newClient = { id: clientId, res };
        connectedClients.push(newClient);
        
        // Send initial handshake
        res.write(`data: ${JSON.stringify({ type: 'SYSTEM', data: 'LINK ESTABLISHED' })}\n\n`);

        req.on('close', () => {
            connectedClients = connectedClients.filter(c => c.id !== clientId);
        });
    }
};

// --- DATA & CONTENT ---
const PROTECTED_CONTENT_HTML = `
    <section class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-32">
        <div class="p-8 rounded bg-black/40 backdrop-blur card-hover group border-t-2 border-t-red-500/50">
            <div class="w-12 h-12 bg-red-900/20 rounded flex items-center justify-center mb-6"><i class="fas fa-robot text-2xl text-red-500"></i></div>
            <h3 class="text-xl font-bold text-white mb-3">Invisible Wall</h3>
            <p class="text-gray-400 text-sm">Server-side content hydration active.</p>
        </div>
        <div class="p-8 rounded bg-black/40 backdrop-blur card-hover group">
            <div class="w-12 h-12 bg-green-900/20 rounded flex items-center justify-center mb-6"><i class="fas fa-fingerprint text-2xl text-green-500"></i></div>
            <h3 class="text-xl font-bold text-white mb-3">Kinetic Entropy</h3>
            <p class="text-gray-400 text-sm">Proof of Life verified.</p>
        </div>
        <a href="/dreams" class="p-8 rounded bg-black/40 backdrop-blur card-hover group block cursor-pointer border-t-2 border-t-blue-500/50">
            <div class="w-12 h-12 bg-blue-900/20 rounded flex items-center justify-center mb-6"><i class="fas fa-wave-square text-2xl text-blue-500"></i></div>
            <h3 class="text-xl font-bold text-white mb-3">Dreams V6</h3>
            <p class="text-gray-400 text-sm">Predictive Maintenance Engine.</p>
        </a>
    </section>
`;

// --- API ROUTES ---

// 1. THE LIVE WIRE ENDPOINT (Dashboard connects here)
app.get('/api/live-wire', LiveWire.addClient);

// 2. UNLOCK GATE (Traffic Entry)
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

// 3. CHAOS LOG (Sentinel Reports)
app.post('/api/chaos-log', (req, res) => {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    // Broadcast the threat report to the dashboard
    LiveWire.broadcast('THREAT', { ...req.body, ip });
    console.log(">>> [THREAT REPORT]", req.body);
    res.sendStatus(200);
});

// 4. AUTH & DEMO (Placeholders)
app.get('/api/v1/auth/login-options', (req, res) => res.status(404).json({ error: "No Identity" }));
app.post('/api/v1/auth/login-verify', (req, res) => res.status(400).json({ verified: false }));
app.get('/api/v1/beta/pulse-demo', (req, res) => res.json({ valid: true, hash: crypto.randomBytes(32).toString('hex') }));

// --- FILE SERVING ---
const serve = (f, res) => fs.existsSync(path.join(publicPath, f)) ? res.sendFile(path.join(publicPath, f)) : res.status(404).send('Missing: ' + f);

// Injection Handler for Landing Page
const SENTINEL_SDK_CODE = `/* Client Code Injected Here in Memory */`; 
// Note: We keep the simplified serve for index.html as the client V176 is self-contained now.
app.get('/', (req, res) => serve('index.html', res));

app.get('/app', (req, res) => serve('app.html', res));
app.get('/dashboard', (req, res) => serve('dashboard.html', res));
app.get('/dreams', (req, res) => serve('dreams.html', res));
app.get('*', (req, res) => res.redirect('/'));

// --- START ---
try {
    app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V167 ONLINE (LIVE WIRE ACTIVE)`));
} catch (e) {
    console.error(`>>> [FATAL] PORT ERROR:`, e.message);
}
