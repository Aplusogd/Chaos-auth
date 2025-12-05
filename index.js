/**
 * A+ TOTEM SECURITY CORE: SAAS EDITION
 * FINAL FIX: Uses public/index.html for the Landing Page (Storefront).
 * Routing: '/' -> index.html (Storefront) | '/app' -> app.html (War Room)
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

// --- DEBUG: Verify Files Exist on Startup (for local development) ---
if (!fs.existsSync(publicPath)) {
    console.error("❌ CRITICAL ERROR: 'public' folder missing!");
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
    const sequence = [];
    for(let i=0; i<4; i++) {
        sequence.push(COLORS[parseInt(nonce.substring(i, i+1), 16) % 4]);
    }
    ChallengeMap.set(nonce, { expires: Date.now() + 60000 });
    return nonce;
}

function verifyResponse(nonce, clientEcho, clientSequence, deviceHash) {
    if (!ChallengeMap.has(nonce)) return { valid: false, error: "ERR_INVALID_NONCE" };
    const data = ChallengeMap.get(nonce);
    ChallengeMap.delete(nonce); 
    if (Date.now() > data.expires) return { valid: false, error: "ERR_TIMEOUT" };
    
    // 1. CHECK PIN
    if (JSON.stringify(clientSequence) !== JSON.stringify(SECRET_SEQUENCE)) return { valid: false, error: "ERR_WRONG_PIN" };
    
    // 2. CHECK DEVICE
    if (TRUSTED_DEVICE_HASH === null) { TRUSTED_DEVICE_HASH = deviceHash; console.log("Device Bound."); }
    else if (deviceHash !== TRUSTED_DEVICE_HASH) return { valid: false, error: "ERR_UNAUTHORIZED_DEVICE" };

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

    scanForPoison: (req, res, next) => {
        const payload = JSON.stringify(req.body || {}).toLowerCase();
        const sqlPattern = /(\b(select|update|delete|insert|drop|alter|truncate|union|exec)\b)|(')|(--)|(#)|(\sor\s)|(\sand\s)|(=)/i;
        const xssPattern = /(<|>|javascript:|vbscript:|onload|onerror|alert\()/i;

        if (req.path.includes('/verify') && req.body.solution) {
             if (xssPattern.test(payload)) return res.status(406).json({ error: "ERR_MALICIOUS_PAYLOAD" });
             return next();
        }
        if (sqlPattern.test(payload) || xssPattern.test(payload)) {
            return res.status(406).json({ error: "ERR_POISON_DETECTED" });
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
app.use(Nightmare.scanForPoison);
app.use(Nightmare.antiBot);

// ==========================================
// 🛣️ ROUTES
// ==========================================

app.get('/api/v1/challenge', (req, res) => {
    res.json({ pulse: createChallenge() });
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

// ROUTING LOGIC
app.get('/', (req, res) => {
    // This loads public/index.html (The Storefront)
    const landingFile = path.join(publicPath, 'index.html');
    if (fs.existsSync(landingFile)) {
        res.sendFile(landingFile);
    } else {
         res.status(404).send("Storefront Missing (public/index.html)");
    }
});

app.get('/app', (req, res) => {
    // This loads public/app.html (The Secure War Room)
    const appFile = path.join(publicPath, 'app.html');
    if (fs.existsSync(appFile)) {
        res.sendFile(appFile);
    } else {
        res.status(404).send("App Missing (public/app.html)");
    }
});

app.get('/dashboard', (req, res) => {
    const dashFile = path.join(publicPath, 'dashboard.html');
    if (fs.existsSync(dashFile)) {
        res.sendFile(dashFile);
    } else {
        res.status(404).send("Dashboard Missing (public/dashboard.html)");
    }
});

app.listen(PORT, () => console.log(`🛡️ A+ TOTEM BUSINESS CORE ONLINE: ${PORT}`));
