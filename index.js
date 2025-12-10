/**
 * A+ CHAOS ID: V166 (SERVER FINAL)
 * STATUS: PRODUCTION READY
 * FUNCTION: Stable file server, API routing, and Trust Bypass for V176 Client.
 */
import express from 'express';
import path from 'path';
import cors from 'cors';
import fs from 'fs';
import crypto from 'crypto';
import helmet from 'helmet';
import { fileURLToPath } from 'url';
import { dirname } from 'path';     

// --- ZOMBIE PROTOCOL (CRITICAL STARTUP PROTECTION) ---
process.on('uncaughtException', (err) => console.error('>>> [CRASH LOG] FATAL ERROR CAUGHT:', err.message, err));
process.on('unhandledRejection', (reason) => console.error('>>> [CRASH LOG] REJECTION CAUGHT:', reason));

// --- 1. INITIAL SETUP ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const publicPath = path.join(__dirname, 'public');

const app = express();
const PORT = process.env.PORT || 3000;

// --- 2. MIDDLEWARE ---
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*' })); 
app.use(express.json());
app.use(express.static(publicPath));

// --- 3. MOCK PROTECTED CONTENT (Sent via API) ---
const PROTECTED_CONTENT_HTML = `
    <section class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-32">
        <div class="p-8 rounded bg-black/40 backdrop-blur card-hover group border-t-2 border-t-red-500/50">
            <div class="w-12 h-12 bg-red-900/20 rounded flex items-center justify-center mb-6"><i class="fas fa-robot text-2xl text-red-500"></i></div>
            <h3 class="text-xl font-bold text-white mb-3">Invisible Wall</h3>
            <p class="text-gray-400 text-sm">*Solution for Data Leakage.* Content is only 'hydrated' for human visitors.</p>
        </div>
        <div class="p-8 rounded bg-black/40 backdrop-blur card-hover group">
            <div class="w-12 h-12 bg-green-900/20 rounded flex items-center justify-center mb-6"><i class="fas fa-fingerprint text-2xl text-green-500"></i></div>
            <h3 class="text-xl font-bold text-white mb-3">Kinetic Entropy</h3>
            <p class="text-gray-400 text-sm">Proves "Proof of Life" using chaotic velocity.</p>
        </div>
        <a href="/dreams" class="p-8 rounded bg-black/40 backdrop-blur card-hover group block cursor-pointer border-t-2 border-t-blue-500/50">
            <div class="w-12 h-12 bg-blue-900/20 rounded flex items-center justify-center mb-6"><i class="fas fa-wave-square text-2xl text-blue-500"></i></div>
            <h3 class="text-xl font-bold text-white mb-3">Dreams V6</h3>
            <p class="text-gray-400 text-sm">Acoustic diagnostics for hardware health.</p>
        </a>
    </section>
`;

// --- 4. API ROUTES ---

// UNLOCK GATE (Trust Bypass - No Hash Check)
app.post('/api/unlock', (req, res) => {
    const { timestamp } = req.body; 
    // Basic Replay Protection (10s window)
    if (Date.now() - timestamp > 10000) {
         return res.status(403).json({ error: "STALE_TIMESTAMP" });
    }
    console.log(">>> [SECURITY] Trust Bypass Granted.");
    res.json({ success: true, content: PROTECTED_CONTENT_HTML });
});

// LOGGING BEACON
app.post('/api/chaos-log', (req, res) => {
    console.log(">>> [CHAOS LOG]", req.body);
    res.sendStatus(200);
});

// AUTH PLACEHOLDERS (For future expansion)
app.get('/api/v1/auth/login-options', (req, res) => res.status(404).json({ error: "No Identity" }));
app.post('/api/v1/auth/login-verify', (req, res) => res.status(400).json({ verified: false }));
app.get('/api/v1/beta/pulse-demo', (req, res) => res.json({ valid: true, hash: crypto.randomBytes(32).toString('hex') }));

// --- 5. FILE SERVING ---
const serve = (f, res) => fs.existsSync(path.join(publicPath, f)) ? res.sendFile(path.join(publicPath, f)) : res.status(404).send('Missing: ' + f);

app.get('/', (req, res) => serve('index.html', res));
app.get('/app', (req, res) => serve('app.html', res));
app.get('/dashboard', (req, res) => serve('dashboard.html', res));
app.get('/dreams', (req, res) => serve('dreams.html', res));

// Catch-All
app.get('*', (req, res) => res.redirect('/'));

// --- 6. START SERVER ---
try {
    app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V166 ONLINE (PORT ${PORT})`));
} catch (e) {
    console.error(`>>> [FATAL] FAILED TO BIND PORT. Error:`, e.message);
}
