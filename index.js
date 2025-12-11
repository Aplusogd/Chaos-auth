// index.js — V251 — ROUTE FIX
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

// Security & CSP
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use((req, res, next) => {
    res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; connect-src 'self';");
    next();
});

app.use(compression());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// === ROUTES ===
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'check.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/pair', (req, res) => res.sendFile(path.join(__dirname, 'public', 'pair.html')));
app.get('/sdk', (req, res) => res.sendFile(path.join(__dirname, 'public', 'sdk.html')));
app.get('/logout', (req, res) => res.sendFile(path.join(__dirname, 'public', 'logout.html')));
app.get('/forge', (req, res) => res.sendFile(path.join(__dirname, 'public', 'abyss.html')));
app.get('/abyss-forge', (req, res) => res.sendFile(path.join(__dirname, 'public', 'abyss-forge.html')));

// *** FIXED ROUTE ***
app.get('/search', (req, res) => res.sendFile(path.join(__dirname, 'public', 'search.html')));

// Chaos API
app.get('/chaos', (req, res) => {
    res.json({ callsign: `CHAOS-${Date.now()}`, message: "The Abyss speaks." });
});

app.use((req, res) => res.redirect('/'));

app.listen(PORT, '0.0.0.0', () => console.log(`🌑 CHAOS V251 ONLINE`));
