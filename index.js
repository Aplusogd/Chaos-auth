// index.js — V241 — RENDER/VERCEL FINAL STABLE BUILD

import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import compression from 'compression';
import helmet from 'helmet';
import crypto from 'crypto'; // Needed for callsign generation stub

// Fix __dirname and __filename in ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Placeholder for your callsign generation function
function generateInfiniteChaosCode(seed, count) {
    const words = ['CRIMSON','RAZOR','THUNDER','VOID','NOVA','ABYSS'];
    const randIndex = crypto.createHash('sha256').update(seed).digest('hex').charCodeAt(0);
    return `${words[randIndex % words.length]}-${words[(randIndex + 1) % words.length]}-${words[(randIndex + 2) % words.length]}`;
}

// Security + Speed Middleware
// 1. CRITICAL FIX: Custom CSP to allow client-side inline scripts (Tailwind/CryptoJS)
app.use(helmet({
    contentSecurityPolicy: false, // Disable default so we can set manually
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

// Session Guard Middleware (Placeholder)
function verifySession(req, res, next) {
    next(); 
}

// === CORE CHAOS ROUTES (Clean URLs) ===
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/forge', (req, res) => res.sendFile(path.join(__dirname, 'public', 'abyss.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));
app.get('/dashboard', verifySession, (req, res) => res.sendFile(path.join(__dirname, 'public', 'check.html')));
app.get('/admin', verifySession, (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/sdk', (req, res) => res.sendFile(path.join(__dirname, 'public', 'sdk.html')));
app.get('/error', (req, res) => res.sendFile(path.join(__dirname, 'public', 'error.html')));
app.get('/logout', (req, res) => res.sendFile(path.join(__dirname, 'public', 'logout.html')));
app.get('/pair', verifySession, (req, res) => res.sendFile(path.join(__dirname, 'public', 'pair.html'))); 

// === REDUNDANCY REDIRECTS ===
const redirects = {
    '/abyss-forge': '/forge',
    '/keyforge': '/forge',
    '/abyss.html': '/forge',
    '/hydra': '/dashboard',
    '/portal': '/login',
    '/overwatch': '/admin',
    '/test-console': '/admin',
    '/dreams': '/sdk',
    '/check.html': '/dashboard',
    '/app.html': '/login',
    '/index.html': '/',
    // Redirects for specific static files that might be requested directly
    '/abyss-search.html': '/search',
    '/chaos-sdk.js': '/sdk', 
    '/dashboard.html': '/dashboard',
    '/overwatch.html': '/admin',
    '/keyforge.html': '/forge'
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
    console.log(`🌑 CHAOS SERVER V241 ALIVE — PORT ${PORT}`);
});
