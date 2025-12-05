/**
 * A+ TOTEM SECURITY CORE: ZERO-DATA PROFILE EDITION
 * Routing: '/' -> War Room (Verify First) | '/dashboard' -> Home Base
 * Security: CHAOS, NIGHTMARE, ABYSS, SPHINX, CONSTELLATION, DNA LOCK
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
// 🌌 THE ABYSS (Ephemeral Profile Storage)
// ==========================================
const ChallengeMap = new Map();
const COLORS = ['red', 'blue', 'green', 'yellow'];

// IN-MEMORY PROFILE STORE (The "Abyss")
// Stores ONLY hashes: { "device_hash": "hashed_pattern" }
// It remembers "This device knows this pattern", but doesn't know WHO it is.
const AbyssProfiles = new Map(); 

function generateQuantumPulse() {
    const osEntropy = crypto.randomBytes(32);
    const timeEntropy = Buffer.from(process.hrtime.bigint().toString());
    const heapEntropy = Buffer.from(JSON.stringify(v8.getHeapStatistics()));
    const mixer = crypto.createHash('sha512');
    mixer.update(osEntropy).update(timeEntropy).update(heapEntropy);
    return mixer.digest('hex').substring(0, 32);
}

function createChallenge() {
    const nonce = generateQuantumPulse();
    ChallengeMap.set(nonce, { expires: Date.now() + 60000 });
    return nonce;
}

function registerProfile(deviceHash, patternHash) {
    // The Abyss remembers this device + pattern combo
    AbyssProfiles.set(deviceHash, patternHash);
    console.log(`[ABYSS] New Anonymous Profile Created: ${deviceHash.substring(0,8)}...`);
    return true;
}

function verifyLogin(deviceHash, patternHash) {
    // 1. Check if device exists
    if (!AbyssProfiles.has(deviceHash)) {
        return { valid: false, error: "ERR_UNKNOWN_DEVICE" };
    }
    // 2. Check if pattern matches
    const storedPattern = AbyssProfiles.get(deviceHash);
    if (storedPattern !== patternHash) {
        return { valid: false, error: "ERR_WRONG_PATTERN" };
    }
    return { valid: true };
}

function verifyResponse(nonce, clientEcho, clientPattern, deviceHash, mode) {
    if (!ChallengeMap.has(nonce)) return { valid: false, error: "ERR_INVALID_NONCE" };
    const data = ChallengeMap.get(nonce);
    ChallengeMap.delete(nonce); // Burn nonce
    if (Date.now() > data.expires) return { valid: false, error: "ERR_TIMEOUT" };

    // HASH THE PATTERN (So we never store the raw sequence in memory)
    const patternHash = crypto.createHash('sha256').update(JSON.stringify(clientPattern)).digest('hex');

    if (mode === 'REGISTER') {
        // Create new anonymous profile
        registerProfile(deviceHash, patternHash);
        return { valid: true, message: "Profile Created in Abyss." };
    } else {
        // Verify existing profile
        return verifyLogin(deviceHash, patternHash);
    }
}

// ==========================================
// 👹 NIGHTMARE DEFENSE
// ==========================================
const Nightmare = {
    rateLimiter: (req, res, next) => {
        const ip = req.ip || req.connection.remoteAddress;
        if (!Nightmare._requests) Nightmare._requests = new Map();
        if (!Nightmare._requests.has(ip)) Nightmare._requests.set(ip, []);
        const now = Date.now();
        const timestamps = Nightmare._requests.get(ip).filter(time => now - time < 10000);
        timestamps.push(now);
        Nightmare._requests.set(ip, timestamps);
        if (timestamps.length > 50) return res.status(429).json({ error: "ERR_RATE_LIMIT" });
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
    res.json({ pulse: createChallenge() });
});

app.post('/api/v1/verify', (req, res) => {
    const { nonce, echo, solution, deviceHash, mode } = req.body; 
    // Mode: 'REGISTER' (New Profile) or 'LOGIN' (Verify)
    
    if (!nonce || !echo || !solution || !deviceHash || !mode) return res.status(400).json({ error: "MISSING_DATA" });

    const result = verifyResponse(nonce, echo, solution, deviceHash, mode);

    if (result.valid) {
        const sessionToken = crypto.randomBytes(32).toString('hex');
        res.json({ valid: true, session: sessionToken, message: result.message });
    } else {
        setTimeout(() => res.status(403).json(result), 1000);
    }
});

app.use(express.static(publicPath));

// ROUTING LOGIC - WAR ROOM FIRST
app.get('/', (req, res) => {
    // Default Route: Loads the Secure App (War Room)
    const appFile = path.join(publicPath, 'app.html');
    if (fs.existsSync(appFile)) {
        res.sendFile(appFile);
    } else {
        res.status(404).send("Error: public/app.html is missing.");
    }
});

app.get('/info', (req, res) => {
    // Info Route: Loads the Marketing Page
    const landingFile = path.join(publicPath, 'index.html');
    if (fs.existsSync(landingFile)) {
        res.sendFile(landingFile);
    } else {
        res.status(404).send("Error: public/index.html is missing.");
    }
});

app.get('/dashboard', (req, res) => {
    const dashFile = path.join(publicPath, 'dashboard.html');
    if (fs.existsSync(dashFile)) {
        res.sendFile(dashFile);
    } else {
        res.status(404).send("Error: public/dashboard.html is missing.");
    }
});

app.listen(PORT, () => console.log(`🛡️ A+ TOTEM ZERO-DATA CORE ONLINE: ${PORT}`));
