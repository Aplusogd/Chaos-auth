// index.js - A+ CHAOS CORE SERVER (V232 - Definitive Production Master)

const express = require('express');
const path = require('path');
const compression = require('compression');
const helmet = require('helmet');
// Assuming the use of the crypto module for your internal API logic
const crypto = require('crypto'); 

const app = express();
const PORT = process.env.PORT || 3000;

// Placeholder for generating a random code (needed for the /chaos test endpoint)
function generateInfiniteChaosCode(seed, count) {
    const randomBytes = crypto.randomBytes(4).toString('hex').toUpperCase();
    return `TEST-CHAOS-${randomBytes}`;
}

// 1. SECURITY & PERFORMANCE MIDDLEWARE
// Helmet: Adds security headers
app.use(helmet({
    contentSecurityPolicy: false, // Temporarily disabled for ease of client-side testing
    crossOriginEmbedderPolicy: false
}));

// Compression: Reduces load time
app.use(compression());

// Static Public Serving (All Files from /public)
app.use(express.static(path.join(__dirname, 'public')));

// --- API STUBS (Required by Client-Side Scripts) ---
app.use(express.json()); // Enable body parsing for API stubs
app.post('/api/auth/ghost-register', (req, res) => {
    // Simplified stub to satisfy client-side registration/verification
    res.json({ success: true });
});
app.post('/api/v1/sentinel/verify', (req, res) => {
    // Simplified stub to satisfy client-side dashboard loading
    res.json({ valid: true, trustScore: 85, rank: "IMMORTAL", project: "A+ Core User" });
});

// 2. CUSTOM ROUTES (Mapping Corrected Files to Clean URLs)
// --- CORE USER FLOW ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// CRITICAL CORRECTION: Callsign Creation is in abyss.html
app.get('/forge', (req, res) => res.sendFile(path.join(__dirname, 'public', 'abyss.html'))); 

// Biometric Verification is in app.html
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html'))); 

// User Sanctuary/Dashboard is in check.html
app.get('/dashboard', verifySession, (req, res) => res.sendFile(path.join(__dirname, 'public', 'check.html'))); 

// --- UTILITY / ADMIN ---
app.get('/admin', verifySession, (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html'))); // Placeholder file
app.get('/error', (req, res) => res.sendFile(path.join(__dirname, 'public', 'error.html')));
app.get('/logout', (req, res) => res.sendFile(path.join(__dirname, 'public', 'logout.html')));

// --- REDUNDANCY/MERGE REDIRECTS (Enforce Clean URLs) ---
app.get('/abyss', (req, res) => res.redirect('/forge'));
app.get('/keyforge', (req, res) => res.redirect('/forge'));
app.get('/portal', (req, res) => res.redirect('/login'));
app.get('/check.html', (req, res) => res.redirect('/dashboard'));

// --- CHAOS ENDPOINT (Alive Feature) ---
app.get('/chaos', (req, res) => {
    const callsign = generateInfiniteChaosCode('seed' + Date.now(), 3); 
    res.json({ callsign, message: 'The Abyss breathes — use wisely.' });
});

// Session Guard Middleware (Placeholder - Rely on Client Router for immediate UX)
function verifySession(req, res, next) {
    // In this stateless setup, we primarily rely on client-side router.js guards, 
    // but a robust app would check an API token here.
    next(); 
}

// 3. 404 CATCH-ALL
app.use((req, res) => res.redirect('/error?code=404'));

// 4. START SERVER
app.listen(PORT, '0.0.0.0', () => console.log(`⚡ A+ CHAOS CORE V232 Online on port ${PORT}`));
