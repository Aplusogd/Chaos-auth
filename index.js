// index.js — V272 — API UNLOCKED (CORS FIX)
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import compression from 'compression';
import helmet from 'helmet';
import cors from 'cors'; // <--- NEW IMPORT

// 1. ES Module Fix
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// 2. SECURITY MIDDLEWARE
// A. Enable CORS (Allows your API/SDK to be used by other websites)
app.use(cors({ origin: '*' })); 

// B. Disable default Helmet CSP (We manage it manually)
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

// C. Custom CSP (Whitelists Tailwind, Fonts, and allows API connections)
app.use((req, res, next) => {
    res.setHeader(
        "Content-Security-Policy",
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.tailwindcss.com; " +
        "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com https://fonts.googleapis.com; " +
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; " +
        "img-src 'self' data:; " +
        "connect-src *;" // <--- Allows connecting to anywhere
    );
    next();
});

// 3. PERFORMANCE
app.use(compression());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// 4. API ENDPOINTS (Now Accessible Externally)
app.get('/chaos', (req, res) => {
    const callsign = `CHAOS-${Date.now().toString(36).toUpperCase()}`;
    res.json({ callsign, status: "OPERATIONAL", timestamp: Date.now() });
});

// 5. CORE ROUTING
// Landing
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));
app.get('/logout', (req, res) => res.sendFile(path.join(__dirname, 'public', 'logout.html')));

// The Forge
app.get('/forge', (req, res) => res.sendFile(path.join(__dirname, 'public', 'abyss.html')));
app.get('/abyss-forge', (req, res) => res.sendFile(path.join(__dirname, 'public', 'abyss-forge.html')));
app.get('/abyss.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'abyss.html')));

// The System
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'check.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/pair', (req, res) => res.sendFile(path.join(__dirname, 'public', 'pair.html')));
app.get('/search', (req, res) => res.sendFile(path.join(__dirname, 'public', 'search.html')));

// Resources
app.get('/sdk', (req, res) => res.sendFile(path.join(__dirname, 'public', 'sdk.html')));
app.get('/examples.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'examples.html')));
// Direct access to the JS file for external loading
app.get('/chaos-sdk.js', (req, res) => res.sendFile(path.join(__dirname, 'public', 'chaos-sdk.js')));

// Redirects & Errors
const redirects = { '/portal': '/login', '/docs': '/sdk', '/hydra': '/dashboard' };
Object.entries(redirects).forEach(([from, to]) => app.get(from, (req, res) => res.redirect(301, to)));

app.use((req, res) => res.redirect('/')); // Catch-all

// 6. LAUNCH
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🌑 CHAOS SERVER V272 LIVE — PORT ${PORT}`);
});
