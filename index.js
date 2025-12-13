// index.js — Chaos Command Server V1.0
// 🚀 Powering the A+ Overhead Garage Doors Ecosystem

const express = require('express');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// --- 1. SECURITY & MIDDLEWARE ---

// Enable HELMET for header security (prevents basic attacks)
app.use(helmet({
    contentSecurityPolicy: false, // Disabled for dev simplicity, enable in Prod V2
}));

// Enable CORS (Allow the Shield to talk to us)
app.use(cors());

// Parse JSON payloads (Shield sends data in JSON)
app.use(express.json());

// RATE LIMITING (Prevent DDoS attacks on your API)
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: "⚠️ Chaos Shield Protection: Too many requests from this IP."
});
app.use('/api/', apiLimiter);

// --- 2. CHAOS SHIELD API ENDPOINTS ---

// A. Heartbeat Endpoint
// The Shield pings this to confirm it has internet access
app.get('/api/v1/status', (req, res) => {
    res.json({ 
        status: 'ONLINE', 
        system: 'Chaos Command Center', 
        time: Date.now() 
    });
});

// B. Ambient Learning Sync
// The Shield sends observed user interests (Keywords) here to train the Cloud Model
app.post('/api/v1/chaos/sync', (req, res) => {
    const { shield_id, keywords, trust_score } = req.body;
    
    // In the future, this will save to a database.
    // For now, we log it to the console to verify the Shield is working.
    console.log(`📡 [INCOMING TELEMETRY] Shield: ${shield_id} | Trust: ${trust_score}%`);
    console.log(`🧠 [AMBIENT LEARNING] New Interests: ${keywords}`);

    res.json({ success: true, message: "Telemetry Received. Model Updated." });
});

// C. Secure Token Verification
// Verifies if a Token sent by a user is valid
app.post('/api/v1/auth/verify', (req, res) => {
    const { token, callsign } = req.body;
    
    // Simulation: Check if token is valid (In V2 this checks signature)
    if(token && callsign === "APLUS-OGD-ADMIN") {
        res.json({ valid: true, clearance: "MAXIMUM" });
    } else {
        res.status(403).json({ valid: false, error: "Invalid Credentials" });
    }
});

// --- 3. SERVE FRONTEND (The App) ---

// Serve static files from the 'public' folder
app.use(express.static(path.join(__dirname, 'public')));

// Fallback: Send everything else to login/index
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- 4. START SERVER ---
app.listen(PORT, () => {
    console.log(`\n🌑 CHAOS COMMAND CENTER INITIALIZED`);
    console.log(`✅ Server running on port: ${PORT}`);
    console.log(`🛡️  Master Callsign: APLUS-OGD-ADMIN`);
});
