// index.js — V245 — FINAL STABLE BUILD WITH CSP FIX

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

// Placeholder for callsign generation
function generateInfiniteChaosCode(seed, count) {
    const words = ['CRIMSON','RAZOR','THUNDER','VOID','NOVA','ABYSS'];
    const randIndex = crypto.createHash('sha256').update(seed).digest('hex').charCodeAt(0);
    return `${words[randIndex % words.length]}-${words[(randIndex % 10) % words.length]}-${words[(randIndex + 2) % words.length]}`;
}

// --- SECURITY & PERFORMANCE MIDDLEWARE ---

// 1. Disable Helmet defaults for manual control
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

// 2. CRITICAL FIX: Custom Content Security Policy (CSP)
// This explicitly allows the necessary CDNs and inline scripts/styles for the A+ Chaos front-end.
app.use((req, res, next) => {
    res.setHeader(
        "Content-Security-Policy",
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; " + // Allows CryptoJS/JQuery/etc.
        "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://fonts.googleapis.com; " + // Allows Tailwind CSS
        "font-src 'self' https://fonts.gstatic.com; " + // Allows Google Fonts
        "connect-src 'self';" // Allows internal API calls
    );
    next();
});

// Other Middleware
app.use(compression());
app.use(express.json());

// Serve all static files from /public
app.use(express.static(path.join(__dirname, 'public')));

// === API STUBS & SESSION CONTROL ===
app.post('/api/auth/ghost-register', (req, res) => res.json({ success: true }));
app.post('/api/v1/sentinel/verify', (req, res) => res.json({ valid: true, trustScore: 90, rank: "IMMORTAL", project: "A+ Core User" }));

function verifySession(req, res, next) { next(); }

// === CORE CHAOS ROUTES (V245) ===
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/forge', (req, res) => res.sendFile(path.join(__dirname, 'public', 'abyss.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));
app.get('/dashboard', verifySession, (req, res) => res.sendFile(path.join(__dirname, 'public', 'check.html')));
app.get('/admin', verifySession, (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/sdk', (req, res) => res.sendFile(path.join(__dirname, 'public', 'sdk.html')));
app.get('/error', (req, res) => res.sendFile(path.join(__dirname, 'public', 'error.html')));
app.get('/logout', (req, res) => res.sendFile(path.join(__dirname, 'public', 'logout.html')));
app.get('/pair', verifySession, (req, res) => res.sendFile(path.join(__dirname, 'public', 'pair.html'))); 

// === REDUNDANCY REDIRECTS (Consolidated) ===
const redirects = {
    '/abyss-forge': '/forge',
    '/keyforge': '/forge',
    '/portal': '/login',
    '/hydra': '/dashboard',
    '/overwatch': '/admin',
    '/test-console': '/admin',
    '/dreams': '/sdk'
};

Object.entries(redirects).forEach(([from, to]) => {
    app.get(from, (req, res) => res.redirect(301, to));
});

// === UTILITY ENDPOINTS ===
app.get('/search', (req, res) => res.sendFile(path.join(__dirname, 'public', 'abyss-search.html')));

app.get('/chaos', (req, res) => {
    const callsign = generateInfiniteChaosCode('seed' + Date.now(), 3);
    res.json({ callsign, message: "The Abyss speaks." });
});

// 404 → Error Page
app.use((req, res) => res.redirect('/error?code=404'));

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🌑 CHAOS SERVER V245 ALIVE — PORT ${PORT}`);
});
