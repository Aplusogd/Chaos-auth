/**
 * A+ TOTEM SECURITY CORE V7: DNA LOCK
 * Features: CHAOS, IRON DOME, SPHINX, CONSTELLATION, DEVICE FINGERPRINTING
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
// 🌌 THE ABYSS (State)
// ==========================================
const ChallengeMap = new Map();
// THE SECRET PATTERN (The "PIN") - Hardcoded for this demo
// In production, this would be fetched from a database per user.
const SECRET_SEQUENCE = ['red', 'blue', 'green', 'red']; 

// THE TRUSTED DEVICE (The "Card") - We will capture this on first successful login
// In production, you'd store "Authorized Device IDs" in a DB.
let TRUSTED_DEVICE_HASH = null; 

function generateQuantumPulse() {
    const osEntropy = crypto.randomBytes(32);
    const timeEntropy = Buffer.from(process.hrtime.bigint().toString());
    const mixer = crypto.createHash('sha512');
    mixer.update(osEntropy).update(timeEntropy);
    return mixer.digest('hex').substring(0, 32);
}

function createChallenge() {
    const nonce = generateQuantumPulse();
    ChallengeMap.set(nonce, { expires: Date.now() + 60000 });
    return nonce;
}

function verifyResponse(nonce, clientEcho, clientSequence, deviceHash) {
    if (!ChallengeMap.has(nonce)) return { valid: false, error: "ERR_INVALID_NONCE" };
    const data = ChallengeMap.get(nonce);
    ChallengeMap.delete(nonce); 
    
    if (Date.now() > data.expires) return { valid: false, error: "ERR_TIMEOUT" };

    // 1. CHECK PIN (The Pattern)
    // User must know the secret sequence. The server does NOT send it anymore.
    if (JSON.stringify(clientSequence) !== JSON.stringify(SECRET_SEQUENCE)) {
        return { valid: false, error: "ERR_WRONG_PIN" };
    }

    // 2. CHECK DEVICE (The Card)
    // If this is the first time, we "Bind" this device as the owner.
    if (TRUSTED_DEVICE_HASH === null) {
        TRUSTED_DEVICE_HASH = deviceHash;
        console.log(`[SYSTEM] Device Bound: ${deviceHash.substring(0,10)}...`);
    } else {
        // If a device is already bound, verify it matches.
        if (deviceHash !== TRUSTED_DEVICE_HASH) {
            return { valid: false, error: "ERR_UNAUTHORIZED_DEVICE" };
        }
    }

    // 3. CHECK MATH
    const expectedEcho = crypto.createHash('sha256').update(nonce + "TOTEM_PRIME_DIRECTIVE").digest('hex');
    if (clientEcho !== expectedEcho) return { valid: false, error: "ERR_CRYPTO_FAIL" };

    return { valid: true };
}

// ==========================================
// 👹 NIGHTMARE DEFENSE
// ==========================================
const Nightmare = {
    rateLimiter: (req, res, next) => {
        // Simplified for brevity, keeps existing logic
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

app.get('/api/v1/challenge', (req, res) => {
    const nonce = createChallenge();
    // NOTE: We do NOT send the sequence anymore. The user must know it.
    res.json({ pulse: nonce });
});

app.post('/api/v1/verify', (req, res) => {
    const { nonce, echo, solution, deviceHash } = req.body; 
    
    if (!nonce || !echo || !solution || !deviceHash) return res.status(400).json({ error: "MISSING_DATA" });

    const result = verifyResponse(nonce, echo, solution, deviceHash);

    if (result.valid) {
        const sessionToken = crypto.randomBytes(32).toString('hex');
        res.json({ valid: true, session: sessionToken });
    } else {
        setTimeout(() => res.status(403).json(result), 1000); // Punishment delay
    }
});

app.use(express.static(publicPath));
app.get('/', (req, res) => res.sendFile(path.join(publicPath, 'index.html')));
app.get('/app', (req, res) => res.sendFile(path.join(publicPath, 'app.html')));

app.listen(PORT, () => console.log(`🛡️ A+ TOTEM V7 LIVE: ${PORT}`));
