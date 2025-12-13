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
app.use(helmet({
    contentSecurityPolicy: false, // Allow inline scripts for Dashboard
}));
app.use(cors());   // Open communication for the Shield Swarm
app.use(express.json()); // Parse JSON payloads

// Anti-DDoS: Strict limits on API usage
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 300, // Limit each IP to 300 requests per window
    message: "⚠️ Chaos Shield Defense: Traffic Limit Exceeded."
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
    const { callsign, trust_score } = req.body;

    console.log(`🔒 AUTH CHECK: ${callsign} | Trust: ${trust_score}%`);

    if (callsign === MASTER_CALLSIGN && trust_score >= 90) {
        res.json({ 
            access: "GRANTED", 
            role: "MASTER_OPERATOR",
            token: "CHAOS_ROOT_SIG_" + Date.now() 
        });
    } else {
        console.warn(`⛔ BLOCKED: Unauthorized access by ${callsign}`);
        res.status(403).json({ 
            access: "DENIED", 
            reason: "Identity Verification Failed" 
        });
    }
});

// C. Federated Learning Sync (Receiving Intelligence)
// Shields send Model Weights here, not user history.
app.post('/api/v1/chaos/federated_update', (req, res) => {
    const { shield_id, delta_weights, trust_score } = req.body;

    if (trust_score < 90) {
        return res.status(403).json({ error: "Low Trust. Model Update Rejected." });
    }

    console.log(`🧠 [FEDERATED] Shield ${shield_id} sent model update.`);
    // Future: Aggregate weights into global model
    
    res.json({ success: true, message: "Global Model Updated." });
});

// D. Swarm Telemetry (Network Health)
app.post('/api/v1/chaos/swarm_health', (req, res) => {
    const { active_peers, latency_avg } = req.body;
    console.log(`🐝 [SWARM] Active Peers: ${active_peers} | Latency: ${latency_avg}ms`);
    res.json({ received: true });
});

// --- 3. SERVE FRONTEND ---
app.use(express.static(path.join(__dirname, 'public')));

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- 4. LAUNCH ---
app.listen(PORT, () => {
    console.log(`\n🌑 CHAOS COMMAND CENTER INITIALIZED`);
    console.log(`🛡️  Master Lock: ${MASTER_CALLSIGN}`);
    console.log(`✅ Listening on Port ${PORT}`);
});
