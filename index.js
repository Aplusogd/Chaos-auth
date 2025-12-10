// index.js — V239 — ES MODULE FIX FOR RENDER/VERCEL

import express from 'express';
import path from 'path';
import compression from 'compression';
import helmet from 'helmet';
import { fileURLToPath } from 'url';
import crypto from 'crypto'; // Needed for callsign generation

// Fix __dirname and __filename in ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Placeholder for your callsign generation function
function generateInfiniteChaosCode(seed, count) {
    const words = ['CRIMSON','RAZOR','THUNDER','VOID','NOVA','ABYSS'];
    return `${words[Math.floor(Math.random()*words.length)]}-${words[Math.floor(Math.random()*words.length)]}-${words[Math.floor(Math.random()*words.length)]}`;
}

// Security + Speed Middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            connectSrc: ["'self'"],
        },
    },
}));
app.use(compression());
app.use(express.json()); // For handling API POST requests

// Serve all static files from /public
app.use(express.static(path.join(__dirname, 'public')));

// === API STUBS (Required by Client-Side Scripts) ===
app.post('/api/auth/ghost-register', (req, res) => res.json({ success: true }));
app.post('/api/v1/sentinel/verify', (req, res) => res.json({ valid: true, trustScore: 90, rank: "IMMORTAL", project: "A+ Core User" }));

// Session Guard Middleware (Placeholder)
function verifySession(req, res, next) {
    next(); 
}

// === CLEAN CHAOS ROUTES (Mapping 18 files) ===
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/forge', (req, res) => res.sendFile(path.join(__dirname, 'public', 'abyss.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));
app.get('/dashboard', verifySession, (req, res) => res.sendFile(path.join(__dirname, 'public', 'check.html')));
app.get('/admin', verifySession, (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/sdk', (req, res) => res.sendFile(path.join(__dirname, 'public', 'sdk.html')));
app.get('/search', (req, res) => res.sendFile(path.join(__dirname, 'public', 'abyss-search.html')));
app.get('/error', (req, res) => res.sendFile(path.join(__dirname, 'public', 'error.html')));
app.get('/logout', (req, res) => res.sendFile(path.join(__dirname, 'public', 'logout.html')));
app.get('/pair', verifySession, (req, res) => res.sendFile(path.join(__dirname, 'public', 'pair.html'))); // New pairing route

// === REDUNDANT → CLEAN REDIRECTS (301) ===
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
    // Include direct file name redirects for the remaining static files that don't need a route alias
    '/chaos-sdk.js': '/chaos-sdk.js',
    '/dashboard.html': '/dashboard',
    '/abyss-search.html': '/search',
    '/overwatch.html': '/admin',
    '/keyforge.html': '/forge',
    '/sdk.html': '/sdk'
};

Object.entries(redirects).forEach(([from, to]) => {
    // Only redirect if the destination is a clean URL, otherwise serve the file directly.
    if (to.startsWith('/')) {
        app.get(from, (req, res) => res.redirect(301, to));
    }
});


// === CHAOS ENDPOINT (Alive & Breathing) ===
app.get('/chaos', (req, res) => {
    const callsign = generateInfiniteChaosCode('seed' + Date.now(), 3);
    res.json({ callsign, message: "The Abyss speaks." });
});

// 404 → Error Page
app.use((req, res) => res.redirect('/error?code=404'));

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🌑 CHAOS SERVER V239 ALIVE — PORT ${PORT}`);
    console.log(`   Core: http://localhost:${PORT}`);
});
