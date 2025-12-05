/**
 * A+ TOTEM SECURITY CORE: SAAS EDITION
 * FINAL FIX: Routing Update for app.html and index.html
 * Security: CHAOS, NIGHTMARE, ABYSS, SPHINX, CONSTELLATION
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

// --- DEBUG: Verify Files Exist on Startup ---
if (!fs.existsSync(publicPath)) {
    console.error("❌ CRITICAL ERROR: 'public' folder missing!");
} else {
    console.log("✅ 'public' folder found.");
    if (!fs.existsSync(path.join(publicPath, 'index.html'))) console.error("❌ MISSING: public/index.html (Storefront)");
    if (!fs.existsSync(path.join(publicPath, 'app.html'))) console.error("❌ MISSING: public/app.html (War Room)");
}

// ==========================================
// 🌌 THE ABYSS (State)
// ==========================================
const ChallengeMap = new Map();
const COLORS = ['red', 'blue', 'green', 'yellow'];

// SECRETS (In production, use ENV variables)
const SECRET_SEQUENCE = ['red', 'blue', 'green', 'red']; 
let TRUSTED_DEVICE_HASH = null; 

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

function verifyResponse(nonce, clientEcho, clientSequence, deviceHash) {
    if (!ChallengeMap.has(nonce)) return { valid: false, error: "ERR_INVALID_NONCE" };
    const data = ChallengeMap.get(nonce);
    ChallengeMap.delete(nonce); 
    
    if (Date.now() > data.expires) return { valid: false, error: "ERR_TIMEOUT" };

    // 1. CHECK PIN (The Pattern)
    if (JSON.stringify(clientSequence) !== JSON.stringify(SECRET_SEQUENCE)) {
        return { valid: false, error: "ERR_WRONG_PIN" };
    }

    // 2. CHECK DEVICE (The Card)
    if (TRUSTED_DEVICE_HASH === null) {
        TRUSTED_DEVICE_HASH = deviceHash;
        console.log(`[SYSTEM] Device Bound: ${deviceHash.substring(0,10)}...`);
    } else {
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
// 👹 NIGHTMARE DEFENSE (IRON DOME)
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
        
        const jitter = Math.floor(Math.random() * 50); 
        if (timestamps.length > 50) {
            setTimeout(() => res.status(429).json({ error: "ERR_RATE_LIMIT" }), jitter);
            return;
        }
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
        setTimeout(() => res.status(403).json(result), Math.floor(Math.random() * 50));
    }
});

app.use(express.static(publicPath));

// ROUTING LOGIC (Updated for new file names)
app.get('/', (req, res) => {
    // Load Storefront
    const landingFile = path.join(publicPath, 'index.html');
    res.sendFile(landingFile, (err) => {
        if (err) {
            console.error(`ERROR: Could not find ${landingFile}`);
            res.status(404).send("404 NOT FOUND: Storefront missing.");
        }
    });
});

app.get('/app', (req, res) => {
    // Load Secure App
    const appFile = path.join(publicPath, 'app.html');
    res.sendFile(appFile, (err) => {
        if (err) {
            console.error(`ERROR: Could not find ${appFile}`);
            res.status(404).send("404 NOT FOUND: War Room missing.");
        }
    });
});

app.listen(PORT, () => console.log(`🛡️ A+ TOTEM BUSINESS CORE ONLINE: ${PORT}`));
