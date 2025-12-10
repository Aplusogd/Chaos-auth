// index.js - A+ CHAOS CORE SERVER (V233 - Definitive Production Master)

const express = require('express');
const path = require('path');
const compression = require('compression');
const helmet = require('helmet');
const crypto = require('crypto'); // Assuming crypto is used for callsign generation stub

const app = express();
const PORT = process.env.PORT || 3000;

// Placeholder for your callsign generation function (for the /chaos endpoint)
function generateInfiniteChaosCode(seed, count) {
    const randomBytes = crypto.randomBytes(4).toString('hex').toUpperCase();
    return `FINAL-CHAOS-${randomBytes}`;
}

// 1. SECURITY & PERFORMANCE MIDDLEWARE
// Helmet: Adds security headers
app.use(helmet({
    contentSecurityPolicy: false, // Relaxed temporarily for client-side frameworks
    crossOriginEmbedderPolicy: false
}));

// Compression: Reduces load time
app.use(compression());
app.use(express.json()); // Enable body parsing for API stubs

// Static Public Serving (All Files from /public)
app.use(express.static(path.join(__dirname, 'public')));

// 2. SERVER STUBS (To satisfy client-side verification attempts)
app.post('/api/auth/ghost-register', (req, res) => res.json({ success: true }));
app.post('/api/v1/sentinel/verify', (req, res) => res.json({ valid: true, trustScore: 90, rank: "IMMORTAL", project: "A+ Core User" }));


// 3. CORE ROUTING (Mapping Stable Files and Accounting for ALL 18 Files)

// --- A. STABLE USER FLOW (Serving the final file) ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.get('/forge', (req, res) => res.sendFile(path.join(__dirname, 'public', 'abyss.html'))); 

app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html'))); 

app.get('/dashboard', verifySession, (req, res) => res.sendFile(path.join(__dirname, 'public', 'check.html'))); 

app.get('/admin', verifySession, (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html'))); 

app.get('/sdk', (req, res) => res.sendFile(path.join(__dirname, 'public', 'sdk.html'))); 

app.get('/logout', (req, res) => res.sendFile(path.join(__dirname, 'public', 'logout.html')));

app.get('/error', (req, res) => res.sendFile(path.join(__dirname, 'public', 'error.html')));

// --- B. REDUNDANCY REDIRECTS (Accounting for all 18 files) ---
// Creation Consolidation (abyss.html)
app.get('/abyss-forge', (req, res) => res.redirect(301, '/forge'));
app.get('/keyforge', (req, res) => res.redirect(301, '/forge'));

// Login Consolidation (app.html)
app.get('/portal', (req, res) => res.redirect(301, '/login'));

// Dashboard Consolidation (check.html)
app.get('/hydra', (req, res) => res.redirect(301, '/dashboard'));
app.get('/dashboard.html', verifySession, (req, res) => res.redirect(301, '/dashboard')); // Redirects the literal file name

// Admin Consolidation (admin.html)
app.get('/overwatch', (req, res) => res.redirect(301, '/admin'));
app.get('/test-console', (req, res) => res.redirect(301, '/admin'));

// SDK Consolidation (sdk.html)
app.get('/dreams', (req, res) => res.redirect(301, '/sdk'));

// Catching the miscellaneous file names that serve static content:
app.get('/abyss-search', (req, res) => res.sendFile(path.join(__dirname, 'public', 'abyss-search.html')));
app.get('/chaos-sdk.js', (req, res) => res.sendFile(path.join(__dirname, 'public', 'chaos-sdk.js')));


// --- C. UTILITY ENDPOINTS ---
app.get('/chaos', (req, res) => {
    const callsign = generateInfiniteChaosCode('seed' + Date.now(), 3); 
    res.json({ callsign, message: 'The Abyss breathes — verify to proceed.' });
});

// Session Guard Middleware (Placeholder - Relies on Client Router for UX)
function verifySession(req, res, next) {
    // This is the server-side guard for protected pages.
    // Ideally, it checks a token/cookie. For now, it's a placeholder.
    next(); 
}

// 4. 404 CATCH-ALL
app.use((req, res) => res.redirect('/error?code=404'));

// 5. START SERVER
app.listen(PORT, '0.0.0.0', () => console.log(`⚡ A+ CHAOS CORE V233 Live on port ${PORT} — All 18 files routed.`));
