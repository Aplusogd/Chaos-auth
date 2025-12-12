// index.js — V273 — FINAL STABILITY FIX
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import compression from 'compression';
import helmet from 'helmet';
import cors from 'cors'; 

// 1. ES Module Fix
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// 2. MIDDLEWARE
app.use(cors({ origin: '*' })); 
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
// Custom CSP
app.use((req, res, next) => {
    res.setHeader(
        "Content-Security-Policy",
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.tailwindcss.com; " +
        "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com https://fonts.googleapis.com; " +
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; " +
        "img-src 'self' data:; " +
        "connect-src *;"
    );
    next();
});

app.use(compression());
app.use(express.json());

// **CRITICAL FIX: SERVE STATIC FILES LAST, NOT FIRST**
// We will serve the core files via routes first, then static files.

// 3. API ENDPOINTS (Now Accessible Externally)
app.get('/chaos', (req, res) => {
    // This route should now work
    res.json({ callsign: `CHAOS-${Date.now().toString(36).toUpperCase()}`, status: "OPERATIONAL", timestamp: Date.now() });
});

// **CRITICAL FIX: EXPLICIT SDK ROUTE**
app.get('/chaos-sdk.js', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'chaos-sdk.js'));
});

// 4. CORE ROUTING (Keep these standard)
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'check.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/forge', (req, res) => res.sendFile(path.join(__dirname, 'public', 'abyss.html')));
app.get('/abyss-forge', (req, res) => res.sendFile(path.join(__dirname, 'public', 'abyss-forge.html')));
app.get('/examples.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'examples.html')));
// ... (Include other routes: /pair, /search, /sdk, /logout)

// Serve all other static assets (like images, CSS, non-routed JS)
app.use(express.static(path.join(__dirname, 'public')));


// 5. LAUNCH
app.use((req, res) => res.redirect('/')); // Catch-all

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🌑 CHAOS SERVER V273 LIVE — PORT ${PORT}`);
});
