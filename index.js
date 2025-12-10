// index.js — V240 — FINAL STABLE BUILD

import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import compression from 'compression';
import helmet from 'helmet';
import crypto from 'crypto'; 

// Fix __dirname and __filename in ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Placeholder for your callsign generation function
function generateInfiniteChaosCode(seed, count) {
    const words = ['CRIMSON','RAZOR','THUNDER','VOID','NOVA','ABYSS'];
    const randIndex = crypto.createHash('sha256').update(seed).digest('hex').charCodeAt(0);
    return `${words[randIndex % words.length]}-${words[(randIndex % 10) % words.length]}-${words[(randIndex + 2) % words.length]}`;
}

// Security + Speed Middleware
// Custom CSP to allow client-side inline scripts (CRITICAL FIX)
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

app.use((req, res, next) => {
    res.setHeader(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; connect-src 'self';"
    );
    next();
});

app.use(compression());
app.use(express.json());

// Serve all static files from /public
app.use(express.static(path.join(__dirname, 'public')));

// === API STUBS & CORE ROUTING (V240) ===
app.post('/api/auth/ghost-register', (req, res) => res.json({ success: true }));
app.post('/api/v1/sentinel/verify', (req, res) => res.json({ valid: true, trustScore: 90, rank: "IMMORTAL", project: "A+ Core User" }));

// Session Guard Middleware (Placeholder)
function verifySession(req, res, next) { next(); }

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/forge', (req, res) => res.sendFile(path.join(__dirname, 'public', 'abyss.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));
app.get('/dashboard', verifySession, (req, res) => res.sendFile(path.join(__dirname, 'public', 'check.html')));
app.get('/admin', verifySession, (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/sdk', (req, res) => res.sendFile(path.join(__dirname, 'public', 'sdk.html')));
app.get('/error', (req, res) => res.sendFile(path.join(__dirname, 'public', 'error.html')));
app.get('/logout', (req, res) => res.sendFile(path.join(__dirname, 'public', 'logout.html')));
app.get('/pair', verifySession, (req, res) => res.sendFile(path.join(__dirname, 'public', 'pair.html'))); 

// Redundancy Redirects (for brevity, listing only the most critical ones here)
app.get('/abyss-forge', (req, res) => res.redirect(301, '/forge'));
app.get('/keyforge', (req, res) => res.redirect(301, '/forge'));
app.get('/portal', (req, res) => res.redirect(301, '/login'));
app.get('/hydra', (req, res) => res.redirect(301, '/dashboard'));

// Final Endpoints
app.get('/search', (req, res) => res.sendFile(path.join(__dirname, 'public', 'abyss-search.html')));
app.get('/chaos', (req, res) => {
    const callsign = generateInfiniteChaosCode('seed' + Date.now(), 3);
    res.json({ callsign, message: "The Abyss speaks." });
});

// 404 → Error Page
app.use((req, res) => res.redirect('/error?code=404'));

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🌑 CHAOS SERVER V240 ALIVE — PORT ${PORT}`);
});
