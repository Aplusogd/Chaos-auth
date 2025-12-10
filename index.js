// index.js - A+ CHAOS CORE SERVER (V237 - Production Master)

const express = require('express');
const path = require('path');
const compression = require('compression');
const helmet = require('helmet');
const crypto = require('crypto'); // Used for generating test callsigns

const app = express();
const PORT = process.env.PORT || 3000;

// Placeholder for your callsign generation function (for the /chaos endpoint)
function generateInfiniteChaosCode(seed, count) {
    const randomBytes = crypto.randomBytes(4).toString('hex').toUpperCase();
    return `FINAL-CHAOS-${randomBytes}`;
}

// --- MIDDLEWARE & API STUBS ---
// 1. SECURITY & PERFORMANCE
app.use(helmet({
    contentSecurityPolicy: false, // Relaxed temporarily for client-side frameworks
    crossOriginEmbedderPolicy: false
}));
app.use(compression());
app.use(express.json()); // Enable body parsing for API stubs

// 2. STATIC SERVING
app.use(express.static(path.join(__dirname, 'public')));

// 3. API STUBS (To satisfy client-side verification attempts)
app.post('/api/auth/ghost-register', (req, res) => res.json({ success: true }));
app.post('/api/v1/sentinel/verify', (req, res) => res.json({ valid: true, trustScore: 90, rank: "IMMORTAL", project: "A+ Core User" }));

// 4. SESSION GUARD MIDDLEWARE (Placeholder)
function verifySession(req, res, next) {
    // In a final production environment, this function would verify a token or session cookie.
    // For now, it allows traffic, relying on client-side JS (router.js) for security UX.
    next(); 
}

// ==================================================================
// ROUTING (Definitive Mapping Accounting for All 18 Files)
// ==================================================================

// --- A. STABLE CORE USER FLOW (Serving the final file) ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.get('/forge', (req, res) => res.sendFile(path.join(__dirname, 'public', 'abyss.html'))); 

app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html'))); 

app.get('/dashboard', verifySession, (req, res) => res.sendFile(path.join(__dirname, 'public', 'check.html'))); 

// --- B. NEW FEATURE ROUTE ---
app.get('/pair', verifySession, (req, res) => res.sendFile(path.join(__dirname, 'public', 'pair.html'))); 

// --- C. UTILITY / ADMIN / DOCS ---
app.get('/admin', verifySession, (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html'))); 
app.get('/sdk', (req, res) => res.sendFile(path.join(__dirname, 'public', 'sdk.html'))); 
app.get('/logout', (req, res) => res.sendFile(path.join(__dirname, 'public', 'logout.html')));
app.get('/error', (req, res) => res.sendFile(path.join(__dirname, 'public', 'error.html')));


// --- D. REDUNDANCY REDIRECTS (Consolidating the 18 Files) ---
// Note: 301 redirects all traffic to the final, clean, consolidated file.

// Creation Consolidation (abyss.html)
app.get('/abyss-forge', (req, res) => res.redirect(301, '/forge'));
app.get('/keyforge', (req, res) => res.redirect(301, '/forge'));
app.get('/abyss.html', (req, res) => res.redirect(301, '/forge')); // Old file name

// Verification Consolidation (app.html)
app.get('/portal', (req, res) => res.redirect(301, '/login'));

// Dashboard Consolidation (check.html)
app.get('/hydra', (req, res) => res.redirect(301, '/dashboard'));
app.get('/check.html', (req, res) => res.redirect(301, '/dashboard'));
app.get('/dashboard.html', verifySession, (req, res) => res.redirect(301, '/dashboard')); 

// Admin/Tools Consolidation (admin.html)
app.get('/overwatch', (req, res) => res.redirect(301, '/admin'));
app.get('/test-console', (req, res) => res.redirect(301, '/admin'));

// SDK/Docs Consolidation (sdk.html)
app.get('/dreams', (req, res) => res.redirect(301, '/sdk'));

// Catching the miscellaneous file names that serve static content directly:
app.get('/abyss-search', (req, res) => res.sendFile(path.join(__dirname, 'public', 'abyss-search.html')));
app.get('/chaos-sdk.js', (req, res) => res.sendFile(path.join(__dirname, 'public', 'chaos-sdk.js')));


// --- E. UTILITY ENDPOINTS ---
app.get('/chaos', (req, res) => {
    const callsign = generateInfiniteChaosCode('seed' + Date.now(), 3); 
    res.json({ callsign, message: 'The Abyss breathes — verify to proceed.' });
});

// 5. 404 CATCH-ALL
app.use((req, res) => res.redirect('/error?code=404'));

// 6. START SERVER
app.listen(PORT, '0.0.0.0', () => console.log(`⚡ A+ CHAOS CORE V237 Live on port ${PORT} — All routes stable.`));
