// index.js — V275 — ABSOLUTE PATH FIX
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import compression from 'compression';
import helmet from 'helmet';
import cors from 'cors';

// 1. Setup
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// 2. SECURITY & CORS (MUST BE FIRST)
app.use(cors({ origin: '*' })); 
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(compression());
app.use(express.json());

// 3. API & SDK ROUTING (Solve 404 & CORS for external files)

// FIX 1: SDK FILE (Solve the 404)
app.get('/chaos-sdk.js', (req, res) => {
    // Uses path.resolve to guarantee finding the file regardless of deploy path
    res.sendFile(path.resolve(__dirname, 'public', 'chaos-sdk.js'));
});

// FIX 2: API ENDPOINT (Solve CORS check for /chaos)
app.get('/chaos', (req, res) => {
    res.json({ callsign: `CHAOS-${Date.now().toString(36).toUpperCase()}`, status: "OPERATIONAL", timestamp: Date.now() });
});

// 4. CORE ROUTING (Standard HTML files)
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'check.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/forge', (req, res) => res.sendFile(path.join(__dirname, 'public', 'abyss.html')));
app.get('/examples.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'examples.html')));
// ... (Include other core routes like /pair, /search, /sdk)

// 5. STATIC FILES (Everything else like CSS, images, etc.)
app.use(express.static(path.join(__dirname, 'public')));


// 6. LAUNCH
app.use((req, res) => res.redirect('/'));

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🌑 CHAOS SERVER V275 LIVE — PORT ${PORT}`);
});
