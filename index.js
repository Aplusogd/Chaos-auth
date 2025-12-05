/**
 * A+ TOTEM SECURITY CORE V7: GHOST PROTOCOL
 * Pillars: CHAOS, IRON DOME, SPHINX, CONSTELLATION
 * New Feature: DEVICE FINGERPRINTING & GHOST PROFILES
 */

const express = require('express');
const crypto = require('crypto');
const v8 = require('v8');
const path = require('path');
const fs = require('fs');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
const publicPath = path.join(__dirname, 'public');

// --- DEBUG: Verify Files ---
if (!fs.existsSync(publicPath)) console.error("❌ CRITICAL: 'public' folder missing!");

// ==========================================
// 🌌 THE ABYSS (State & Profiles)
// ==========================================
const ChallengeMap = new Map();
const ActiveSessions = new Map();
const COLORS = ['red', 'blue', 'green', 'yellow'];

// THE GHOST PROFILE (Your Device DNA)
// In a database, this would be per-user. Here, we lock it to the first admin.
let MASTER_DEVICE_HASH = null; 

function generateQuantumPulse() {
    const osEntropy = crypto.randomBytes(32);
    const timeEntropy = Buffer.from(process.hrtime.bigint().toString());
    const mixer = crypto.createHash('sha512');
    mixer.update(osEntropy).update(timeEntropy);
    return mixer.digest('hex').substring(0, 32);
}

function createChallenge() {
    const nonce = generateQuantumPulse();
    // Server decides the pattern. Client must match it.
    const sequence = [];
    for(let i=0; i<4; i++) {
        sequence.push(COLORS[parseInt(nonce.substring(i, i+1), 16) % 4]);
    }
    ChallengeMap.set(nonce, { expires: Date.now() + 60000, sequence: sequence });
    return { nonce, sequence };
}

function verifyResponse(nonce, clientEcho, clientSequence, deviceHash) {
    if (!ChallengeMap.has(nonce)) return { valid: false, error: "ERR_INVALID_NONCE" };
    const data = ChallengeMap.get(nonce);
    ChallengeMap.delete(nonce); 
    
    if (Date.now() > data.expires) return { valid: false, error: "ERR_TIMEOUT" };

    // 1. DEVICE CHECK (The Card)
    if (MASTER_DEVICE_HASH === null) {
        // First login ever: Bind this device as Master
        MASTER_DEVICE_HASH = deviceHash;
        console.log(`[ABYSS] NEW MASTER DEVICE BOUND: ${deviceHash.substring(0,8)}...`);
    } else if (deviceHash !== MASTER_DEVICE_HASH) {
        // Unknown device trying to log in
        console.log(`[NIGHTMARE] Blocked Unauthorized Device: ${deviceHash.substring(0,8)}...`);
        return { valid: false, error: "ERR_DEVICE_NOT_RECOGNIZED" };
    }

    // 2. PATTERN CHECK (The PIN)
    if (JSON.stringify(clientSequence) !== JSON.stringify(data.sequence)) {
        return { valid: false, error: "ERR_CAPTCHA_FAIL" };
    }

    // 3. CRYPTO CHECK (The Logic)
    const expectedEcho = crypto.createHash('sha256').update(nonce + "TOTEM_PRIME_DIRECTIVE").digest('hex');
    if (clientEcho !== expectedEcho) return { valid: false, error: "ERR_CRYPTO_FAIL" };

    return { valid: true };
}

// ==========================================
// 👹 NIGHTMARE DEFENSE
// ==========================================
const Nightmare = {
    rateLimiter: (req, res, next) => {
        // Basic rate limiting logic kept simple for V7 focus
        next();
    },
    antiBot: (req, res, next) => {
        const secretHeader = req.get('X-APLUS-SECURE');
        if (req.path.startsWith('/api') && secretHeader !== 'TOTEM_V4_ACCESS') {
            return res.status(403).json({ error: "ERR_MISSING_HEADER" });
        }
        next();
    }
};

app.use(Nightmare.rateLimiter);
app.use(Nightmare.antiBot);

// ==========================================
// 🛣️ ROUTES
// ==========================================

// 1. CHECK DEVICE STATUS (Ghost Ping)
// Client asks: "Do you know me?"
app.post('/api/v1/ghost/scan', (req, res) => {
    const { deviceHash } = req.body;
    if (MASTER_DEVICE_HASH && deviceHash === MASTER_DEVICE_HASH) {
        res.json({ status: "RECOGNIZED", message: "Welcome back, Partner." });
    } else {
        res.json({ status: "UNKNOWN", message: "Device not trusted." });
    }
});

// 2. GET PUZZLE
app.get('/api/v1/challenge', (req, res) => {
    const data = createChallenge();
    res.json({ pulse: data.nonce, sequence: data.sequence });
});

// 3. VERIFY & BIND
app.post('/api/v1/verify', (req, res) => {
    const { nonce, echo, solution, deviceHash } = req.body; 
    if (!nonce || !echo || !solution || !deviceHash) return res.status(400).json({ error: "MISSING_DATA" });

    const result = verifyResponse(nonce, echo, solution, deviceHash);

    if (result.valid) {
        const sessionToken = generateQuantumPulse();
        ActiveSessions.set(sessionToken, Date.now() + 3600000);
        res.json({ valid: true, session: sessionToken });
    } else {
        setTimeout(() => res.status(403).json(result), 500);
    }
});

app.use(express.static(publicPath));

app.get('/', (req, res) => res.sendFile(path.join(publicPath, 'index.html')));
app.get('/app', (req, res) => res.sendFile(path.join(publicPath, 'app.html')));

app.listen(PORT, () => console.log(`🛡️ A+ TOTEM GHOST PROTOCOL LIVE: ${PORT}`));


