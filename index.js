// index.js — V274 — STABLE STATIC CORE
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import compression from 'compression';
import helmet from 'helmet';
import cors from 'cors'; // Necessary for external SDK/API use

// 1. Setup
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// 2. Security & CORS (Essential for API)
app.use(cors({ origin: '*' }));
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
// CSP simplified for robustness
app.use((req, res, next) => {
    res.setHeader(
        "Content-Security-Policy",
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.tailwindcss.com; " +
        "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://fonts.googleapis.com; " +
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; " +
        "img-src 'self' data:; " +
        "connect-src *;"
    );
    next();
});

// 3. Performance & Static Files (Serves ALL files from /public)
app.use(compression());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// 4. API ENDPOINT (HARDCODED)
// This will now work because static file serving is done first, 
// and this is a simple route.
app.get('/chaos', (req, res) => {
    // This route should now respond correctly
    res.json({ callsign: `CHAOS-${Date.now().toString(36).toUpperCase()}`, status: "OPERATIONAL", timestamp: Date.now() });
});


// 5. REDIRECTS (Handles custom paths like /dashboard, /login)
// We rely on the client-side router.js to handle the .html file serving

app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'check.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/sdk', (req, res) => res.sendFile(path.join(__dirname, 'public', 'sdk.html')));
app.get('/forge', (req, res) => res.sendFile(path.join(__dirname, 'public', 'abyss.html')));

// Fallback to serve index.html for the root
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// 6. LAUNCH
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🌑 CHAOS SERVER V274 LIVE — PORT ${PORT}`);
});
