/**
 * A+ TOTEM SECURITY CORE: SAAS EDITION
 * Routing: Landing Page (Marketing) vs App (War Room)
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

// --- DEBUG: Verify Files Exist on Startup (for local development) ---
if (!fs.existsSync(publicPath)) {
    console.error("❌ CRITICAL ERROR: 'public' folder missing!");
}

// ==========================================
// 🌌 THE ABYSS (State)
// ==========================================
const ChallengeMap = new Map();
const COLORS = ['red', 'blue', 'green', 'yellow'];

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
    ChallengeMap.set(nonce, { expires: Date.now() + 60000, sequence: sequence });
    return { nonce, sequence };
}

function verifyResponse(nonce, clientEcho, clientSequence) {
    if (!ChallengeMap.has(nonce)) return { valid: false, error: "ERR_INVALID_NONCE" };
    const data = ChallengeMap.get(nonce);
    ChallengeMap.delete(nonce); 
    if (Date.now() > data.expires) return { valid: false, error: "ERR_TIMEOUT" };
    if (JSON.stringify(clientSequence) !== JSON.stringify(data.sequence)) return { valid: false, error: "ERR_CAPTCHA_FAIL" };
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

// API
app.get('/api/v1/challenge', (req, res) => {
    const data = createChallenge();
    res.json({ pulse: data.nonce, sequence: data.sequence });
});

app.post('/api/v1/verify', (req, res) => {
    const { nonce, echo, solution } = req.body; 
    if (!nonce || !echo || !solution) return res.status(400).json({ error: "MISSING_DATA" });
    const result = verifyResponse(nonce, echo, solution);
    if (result.valid) {
        const sessionToken = crypto.randomBytes(32).toString('hex');
        res.json({ valid: true, session: sessionToken });
    } else {
        setTimeout(() => res.status(403).json(result), Math.floor(Math.random() * 50));
    }
});

app.use(express.static(publicPath));

// ROUTING LOGIC (The crucial change is here)
app.get('/', (req, res) => {
    // 1. Check for landing.html (The Storefront)
    const landingFile = path.join(publicPath, 'landing.html');
    if (fs.existsSync(landingFile)) {
        res.sendFile(landingFile);
    } else {
        // 2. Fallback to index.html (The App) if landing is missing
        res.sendFile(path.join(publicPath, 'index.html'));
    }
});

app.get('/app', (req, res) => {
    // Explicitly serves the secure app file
    res.sendFile(path.join(publicPath, 'index.html'));
});

app.listen(PORT, () => console.log(`🛡️ A+ TOTEM BUSINESS CORE ONLINE: ${PORT}`));
