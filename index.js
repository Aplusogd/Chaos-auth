// index.js - V245 - FINAL STABLE
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import compression from 'compression';
import helmet from 'helmet';
import crypto from 'crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Security Middleware: Allow Inline Scripts (Fixes "Bad Look" / Unclickable buttons)
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

app.use((req, res, next) => {
    res.setHeader(
        "Content-Security-Policy",
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; " +
        "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://fonts.googleapis.com; " +
        "font-src 'self' https://fonts.gstatic.com; " +
        "connect-src 'self';"
    );
    next();
});

app.use(compression());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// === API STUBS ===
app.post('/api/auth/ghost-register', (req, res) => res.json({ success: true }));
app.post('/api/v1/sentinel/verify', (req, res) => res.json({ valid: true, trustScore: 90, rank: "IMMORTAL" }));

// === ROUTES ===
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/forge', (req, res) => res.sendFile(path.join(__dirname, 'public', 'abyss.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'check.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/sdk', (req, res) => res.sendFile(path.join(__dirname, 'public', 'sdk.html')));
app.get('/error', (req, res) => res.sendFile(path.join(__dirname, 'public', 'error.html')));
app.get('/logout', (req, res) => res.sendFile(path.join(__dirname, 'public', 'logout.html')));
app.get('/pair', (req, res) => res.sendFile(path.join(__dirname, 'public', 'pair.html')));

// === REDIRECTS ===
const redirects = {
    '/abyss-forge': '/forge',
    '/keyforge': '/forge',
    '/portal': '/login',
    '/hydra': '/dashboard',
    '/overwatch': '/admin',
    '/test-console': '/admin'
};
Object.entries(redirects).forEach(([from, to]) => {
    app.get(from, (req, res) => res.redirect(301, to));
});

// === CHAOS ENDPOINT ===
app.get('/chaos', (req, res) => {
    const callsign = `CHAOS-${Date.now()}`;
    res.json({ callsign, message: "The Abyss speaks." });
});

// 404
app.use((req, res) => res.redirect('/error?code=404'));

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🌑 CHAOS SERVER V245 ALIVE — PORT ${PORT}`);
});
