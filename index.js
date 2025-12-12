// index.js — V256 — PRODUCTION MASTER
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import compression from 'compression';
import helmet from 'helmet';
import crypto from 'crypto';

// 1. ES Module Fix for __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// 2. SECURITY MIDDLEWARE
// We disable default Helmet CSP to allow our CDNs (Tailwind, etc.)
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

// Custom Content Security Policy (CSP)
// Explicitly whitelists the external tools we use (Tailwind, FontAwesome, CryptoJS)
app.use((req, res, next) => {
    res.setHeader(
        "Content-Security-Policy",
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.tailwindcss.com; " +
        "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com https://fonts.googleapis.com; " +
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; " +
        "img-src 'self' data:; " +
        "connect-src 'self';"
    );
    next();
});

// 3. PERFORMANCE & PARSING
app.use(compression());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// 4. API STUBS (For future expansion)
app.post('/api/auth/ghost-register', (req, res) => res.json({ success: true }));
app.post('/api/v1/sentinel/verify', (req, res) => res.json({ valid: true, trustScore: 90, rank: "IMMORTAL" }));
app.get('/chaos', (req, res) => {
    const callsign = `CHAOS-${Date.now().toString(36).toUpperCase()}`;
    res.json({ callsign, status: "OPERATIONAL" });
});

// 5. CORE ROUTING
// Landing & Auth
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));
app.get('/logout', (req, res) => res.sendFile(path.join(__dirname, 'public', 'logout.html')));

// The Forge (Identity Creation)
app.get('/forge', (req, res) => res.sendFile(path.join(__dirname, 'public', 'abyss.html'))); // Step 1: Pick Name
app.get('/abyss-forge', (req, res) => res.sendFile(path.join(__dirname, 'public', 'abyss-forge.html'))); // Step 2: Calibrate Bio
app.get('/abyss.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'abyss.html'))); // Direct link support

// The System (Logged In)
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'check.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/pair', (req, res) => res.sendFile(path.join(__dirname, 'public', 'pair.html')));
app.get('/search', (req, res) => res.sendFile(path.join(__dirname, 'public', 'search.html')));

// Developer Resources
app.get('/sdk', (req, res) => res.sendFile(path.join(__dirname, 'public', 'sdk.html')));
app.get('/examples.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'examples.html')));

// Error Handling
app.get('/error', (req, res) => res.sendFile(path.join(__dirname, 'public', 'error.html')));
app.get('/portal', (req, res) => res.sendFile(path.join(__dirname, 'public', 'portal.html')));

// 6. REDIRECTS (Legacy Support)
const redirects = {
    '/keyforge': '/forge',
    '/hydra': '/dashboard',
    '/overwatch': '/admin',
    '/docs': '/sdk'
};

Object.entries(redirects).forEach(([from, to]) => {
    app.get(from, (req, res) => res.redirect(301, to));
});

// 404 Catch-All -> Redirect to Error Oracle
app.use((req, res) => res.redirect('/error?code=404'));

// 7. START SERVER
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🌑 CHAOS SERVER V256 LIVE — PORT ${PORT}`);
});
