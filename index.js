// index.js — V240 — Render.com Guaranteed

import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import compression from 'compression';
import helmet from 'helmet';

// Fix __dirname and __filename in ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Security Middleware (Helmet + Custom CSP Fix)
// 1. Disable default CSP so we can set it manually
app.use(helmet({
  contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

// 2. Manual CSP — CRITICAL FIX: Allows client-side inline scripts to run
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:;"
  );
  next();
});

// Compression and Static Serving
app.use(compression());
app.use(express.static(path.join(__dirname, 'public')));

// === CORE CHAOS ROUTES (Clean URLs) ===
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/forge', (req, res) => res.sendFile(path.join(__dirname, 'public', 'abyss.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'check.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/sdk', (req, res) => res.sendFile(path.join(__dirname, 'public', 'sdk.html')));
app.get('/search', (req, res) => res.sendFile(path.join(__dirname, 'public', 'abyss-search.html')));
app.get('/error', (req, res) => res.sendFile(path.join(__dirname, 'public', 'error.html')));
app.get('/logout', (req, res) => res.sendFile(path.join(__dirname, 'public', 'logout.html')));

// === REDUNDANT → CLEAN REDIRECTS (301) ===
const redirects = {
  '/abyss-forge': '/forge',
  '/keyforge': '/forge',
  '/abyss': '/forge',
  '/hydra': '/dashboard',
  '/portal': '/login',
  '/overwatch': '/admin',
  '/test-console': '/admin',
  '/dreams': '/sdk',
  // Redirect static file names to their clean aliases
  '/check.html': '/dashboard',
  '/app.html': '/login'
};

Object.entries(redirects).forEach(([from, to]) => {
  app.get(from, (req, res) => res.redirect(301, to));
});

// Chaos endpoint (Alive & Breathing)
app.get('/chaos', (req, res) => {
  const words = ["CRIMSON","VOID","RAZOR","THUNDER","ABYSS","NOVA","GHOST","PLASMA","ONYX","ECLIPSE"];
  const callsign = `${words[Math.floor(Math.random()*10)]}-${words[Math.floor(Math.random()*10)]}-${words[Math.floor(Math.random()*10)]}`;
  res.json({ callsign, message: "The Abyss breathes." });
});

// 404 → Error Page
app.use((req, res) => res.redirect('/error?code=404'));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🌑 CHAOS SERVER V240 ALIVE — PORT ${PORT}`);
});
