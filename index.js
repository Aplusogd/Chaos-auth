// index.js - A+ CHAOS CORE SERVER (V230 - Definitive Production)

const express = require('express');
const path = require('path');
const compression = require('compression');
const helmet = require('helmet');

// --- SERVER SETUP ---
const app = express();
const PORT = process.env.PORT || 3000;

// Placeholder for your secure logic/API functions (assumed imported or internal)
function generateInfiniteChaosCode(seed, count) {
    // This function must be defined elsewhere or imported if used in a test endpoint
    // Placeholder implementation for testing:
    return `TEST-CODE-${Math.random().toFixed(4).substring(2)}`;
}

// 1. SECURITY & PERFORMANCE MIDDLEWARE
// Helmet: Adds security headers (Zero-Knowledge friendly)
app.use(helmet({
    contentSecurityPolicy: false, // Disabling CSP for easy testing of inline scripts
    crossOriginEmbedderPolicy: false
}));

// Compression: Reduces load time (fixes white screen factor)
app.use(compression());

// Static Serving from /public
app.use(express.static(path.join(__dirname, 'public')));

// Placeholder Middleware (Client-side logic now handles most verification)
function verifySession(req, res, next) {
    // NOTE: Client-side router.js handles the majority of redirect guards.
    // This is reserved for server-enforced API checks.
    next(); 
}

// 2. CUSTOM ROUTES (Mapping Corrected Files to Clean URLs)

// A. USER FLOW ROUTES
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// CRITICAL FIX: Callsign CREATION is in abyss.html
app.get('/forge', (req, res) => res.sendFile(path.join(__dirname, 'public', 'abyss.html'))); 

// LOGIN/VERIFICATION is in app.html
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html'))); 

// SANCTUARY (User Dashboard) is in check.html
app.get('/sanctuary', verifySession, (req, res) => res.sendFile(path.join(__dirname, 'public', 'check.html'))); 

// B. UTILITY ROUTES
app.get('/profile/calibrate', verifySession, (req, res) => res.sendFile(path.join(__dirname, 'public', 'abyss-forge.html')));

app.get('/admin', verifySession, (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html'))); // Placeholder

app.get('/error', (req, res) => res.sendFile(path.join(__dirname, 'public', 'error.html')));

app.get('/logout', (req, res) => res.sendFile(path.join(__dirname, 'public', 'logout.html')));

// C. TESTING/STUBS (Tie to your placeholder files)
app.get('/search', (req, res) => res.sendFile(path.join(__dirname, 'public', 'abyss-search.html')));
app.get('/sdk', (req, res) => res.sendFile(path.join(__dirname, 'public', 'sdk.html')));


// D. REDUNDANCY REDIRECTS (Enforce Clean URLs)
app.get('/abyss', (req, res) => res.redirect('/forge'));
app.get('/check.html', (req, res) => res.redirect('/sanctuary'));
app.get('/app.html', (req, res) => res.redirect('/login'));
app.get('/keyforge', (req, res) => res.redirect('/forge'));
app.get('/portal', (req, res) => res.redirect('/login'));

// E. CHAOS ENDPOINT (For Debug/Testing)
app.get('/chaos', (req, res) => {
    const callsign = generateInfiniteChaosCode('test' + Date.now(), 3);
    res.json({ callsign });
});

// 3. 404 CATCH-ALL
app.use((req, res) => res.redirect('/error?code=404'));

// 4. START SERVER
app.listen(PORT, '0.0.0.0', () => console.log(`⚡ Abyss Server Alive on port ${PORT}`));
