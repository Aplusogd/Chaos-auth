// index.js — Chaos Command Center V3.0 (Production)
// 🛡️ SECURITY LEVEL: CRIMSON (Master Lock Active)
// 👑 MASTER CALLSIGN: APLUS-OGD-ADMIN

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const MASTER_CALLSIGN = "APLUS-OGD-ADMIN";

// --- 1. FORTIFIED SECURITY MIDDLEWARE ---

// Security Note: Helmet's CSP is disabled to allow the Seraphim Web Serial integration,
// as the browser requires permissions for the navigator.serial object to be called directly.
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false, // May be needed for some browser-level features
})); 

app.use(cors());   // Open communication for the Shield Swarm
app.use(express.json()); // Parse JSON payloads

// Anti-DDoS: Strict limits on API usage
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 300, // Limit each IP to 300 requests per window
    message: "⚠️ Chaos Shield Defense: Traffic Limit Exceeded. Re-evaluating Trust Score."
});
app.use('/api/', apiLimiter);

// --- 2. API ENDPOINTS ---

// A. Heartbeat (System Status)
app.get('/api/v1/status', (req, res) => {
    res.json({ 
        system: 'Chaos Command Center', 
        status: 'ONLINE', 
        swarm_mode: 'ACTIVE',
        timestamp: Date.now()
    });
});

// B. Secure Admin Verification (The Master Lock)
app.post('/api/v1/auth/verify_admin', (req, res) => {
    // Requires physical access (Seraphim) and high Trust Score before calling this.
    const { callsign, trust_score } = req.body;

    console.log(`🔒 AUTH CHECK: ${callsign} | Trust: ${trust_score}%`);

    // Master Lock Condition: Admin callsign AND high trust level
    if (callsign === MASTER_CALLSIGN && trust_score >= 95) { // Increased minimum trust for Master Access
        res.json({ 
            access: "GRANTED", 
            role: "MASTER_OPERATOR",
            token: "CHAOS_ROOT_SIG_" + Date.now() 
        });
    } else if (callsign !== MASTER_CALLSIGN) {
        console.warn(`⛔ BLOCKED: Mismatching Master Callsign on attempt by ${callsign}`);
        res.status(403).json({ 
            access: "DENIED", 
            reason: "Master Identity Verification Failed" 
        });
    } else {
        console.warn(`⛔ BLOCKED: Trust Score too low (${trust_score}%). Access Denied.`);
        res.status(403).json({ 
            access: "DENIED", 
            reason: "Insufficient Trust Score (Requires 95%+)" 
        });
    }
});

// C. Federated Learning Sync (Receiving Intelligence)
app.post('/api/v1/chaos/federated_update', (req, res) => {
    const { shield_id, delta_weights, trust_score } = req.body;

    // Must be high-trust hardware communicating
    if (trust_score < 90) {
        console.warn(`🧠 [FEDERATED] Shield ${shield_id} rejected. Low Trust (${trust_score}%).`);
        return res.status(403).json({ error: "Low Trust. Model Update Rejected." });
    }

    // Future: Logic to sanitize delta_weights and apply to Overthere.ai model
    console.log(`🧠 [FEDERATED] Shield ${shield_id} sent model update. Status: Awaiting Aggregation.`);
    
    res.json({ success: true, message: "Model Delta Acknowledged." });
});

// D. Swarm Telemetry (Network Health)
app.post('/api/v1/chaos/swarm_health', (req, res) => {
    const { shield_id, active_peers, latency_avg } = req.body;
    console.log(`🐝 [SWARM] Shield ${shield_id}: Active Peers: ${active_peers} | Latency: ${latency_avg}ms`);
    // Future: Logic to update global latency map and trust scores
    res.json({ received: true });
});

// --- 3. SERVE FRONTEND ---

// Static files must be served from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// All non-API routes send the main entry point HTML
app.get('/dashboard.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Failsafe for other routes
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- 4. LAUNCH ---
app.listen(PORT, () => {
    console.log(`\n🌑 CHAOS COMMAND CENTER INITIALIZED`);
    console.log(`🛡️  Master Lock: ${MASTER_CALLSIGN}`);
    console.log(`✅ Listening on Port ${PORT}`);
    console.log(`\n--- Production Note ---`);
    console.log(`Ensure 'node_modules' is installed (npm install) and 'public' directory contains:`);
    console.log(`- index.html (Landing Page)`);
    console.log(`- dashboard.html (Command Center)`);
    console.log(`- js/bridge.js (Seraphim Serial Logic)`);
});
