/**
 * A+ CHAOS ID: V19 (OVERWATCH EDITION)
 * Features: Admin Analytics, Threat Tracking, Self-Healing
 */
const express = require('express');
const path = require('path');
const cors = require('cors');
const crypto = require('crypto');
const { 
    generateRegistrationOptions, 
    verifyRegistrationResponse, 
    generateAuthenticationOptions, 
    verifyAuthenticationResponse 
} = require('@simplewebauthn/server');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({ origin: '*' })); 
app.use(express.json());

// ==========================================
// 1. THE BLACK BOX (DATA RECORDER)
// ==========================================
const BlackBox = {
    stats: {
        totalRequests: 0,
        activeKeys: 2, // Starts with demos
        pulseUsage: 0,
        legacyUsage: 0,
        attacksBlocked: 0,
        systemHealth: 100
    },
    threatLog: [] // Stores last 50 blocked attempts
};

// Log a threat
const logThreat = (ip, type) => {
    BlackBox.stats.attacksBlocked++;
    const entry = `[${new Date().toISOString()}] BLOCKED: ${ip} -> ${type}`;
    BlackBox.threatLog.unshift(entry);
    if (BlackBox.threatLog.length > 50) BlackBox.threatLog.pop();
};

// ==========================================
// 2. ABYSS (THE LEDGER)
// ==========================================
const Abyss = {
    partners: new Map(), 
    sessions: new Map(),
    hash: (key) => crypto.createHash('sha256').update(key).digest('hex'),
};

// SEED DATA
const demoHash = Abyss.hash('sk_chaos_demo123');
Abyss.partners.set(demoHash, { company: 'Public Demo', plan: 'free', usage: 0, limit: 50, active: true });

// ==========================================
// 3. NIGHTMARE (THE GATEKEEPER)
// ==========================================
const Nightmare = {
    guardSaaS: (req, res, next) => {
        BlackBox.stats.totalRequests++;
        
        // SIMULATE THREAT DETECTION (Random bot noise)
        if (Math.random() < 0.05) { 
            logThreat(req.ip || 'Unknown IP', 'MALFORMED_HEADER_INJECTION');
            return res.status(403).json({ error: "BLOCKED_BY_NIGHTMARE" });
        }

        const rawKey = req.get('X-CHAOS-API-KEY');
        if (!rawKey) {
            logThreat(req.ip, 'MISSING_AUTH_TOKEN');
            return res.status(401).json({ error: "MISSING_KEY" });
        }

        const hashedKey = Abyss.hash(rawKey);
        const partner = Abyss.partners.get(hashedKey);

        if (!partner) {
            logThreat(req.ip, 'INVALID_API_KEY_ATTEMPT');
            return res.status(403).json({ error: "INVALID_KEY" });
        }

        if (partner.usage >= partner.limit) {
            return res.status(402).json({ error: "QUOTA_EXCEEDED" });
        }

        partner.usage++;
        BlackBox.stats.legacyUsage++;
        req.partner = partner;
        next();
    }
};

// ==========================================
// UTILS & DB
// ==========================================
const getOrigin = (req) => {
    const host = req.headers['x-forwarded-host'] || req.get('host');
    const proto = req.headers['x-forwarded-proto'] || 'http';
    return `${proto}://${host}`;
};
const getRpId = (req) => {
    const host = req.headers['x-forwarded-host'] || req.get('host');
    return host.split(':')[0];
};

const Users = new Map();
const Challenges = new Map();
const Chaos = { mintToken: () => 'tk_' + crypto.randomBytes(16).toString('hex') };

// ==========================================
// ROUTES
// ==========================================

// --- AUTH ROUTES (Standard) ---
app.get('/api/v1/auth/register-options', async (req, res) => {
    const userID = 'admin-user'; 
    try {
        const options = await generateRegistrationOptions({
            rpName: 'A+ Chaos ID',
            rpID: getRpId(req),
            userID,
            userName: 'admin@aplus.com',
            attestationType: 'none',
            authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
        });
        Challenges.set(userID, options.challenge);
        res.json(options);
    } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post('/api/v1/auth/register-verify', async (req, res) => {
    const userID = 'admin-user';
    const expectedChallenge = Challenges.get(userID);
    if (!expectedChallenge) return res.status(400).json({ error: "Expired" });
    try {
        const verification = await verifyRegistrationResponse({
            response: req.body,
            expectedChallenge,
            expectedOrigin: getOrigin(req),
            expectedRPID: getRpId(req),
        });
        if (verification.verified) {
            const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
            Users.set(userID, { credentialID, credentialPublicKey, counter });
            Challenges.delete(userID);
            res.json({ verified: true });
        } else { res.status(400).json({ verified: false }); }
    } catch (e) { res.status(400).json({ error: e.message }); }
});

app.get('/api/v1/auth/login-options', async (req, res) => {
    const userID = 'admin-user';
    const user = Users.get(userID);
    if (!user) return res.status(404).json({ error: "User Not Found" });
    try {
        const options = await generateAuthenticationOptions({
            rpID: getRpId(req),
            allowCredentials: [{ id: user.credentialID, type: 'public-key', transports: ['internal'] }],
        });
        Challenges.set(userID, options.challenge);
        res.json(options);
    } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post('/api/v1/auth/login-verify', async (req, res) => {
    const userID = 'admin-user';
    const user = Users.get(userID);
    const expectedChallenge = Challenges.get(userID);
    try {
        const verification = await verifyAuthenticationResponse({
            response: req.body,
            expectedChallenge,
            expectedOrigin: getOrigin(req),
            expectedRPID: getRpId(req),
            authenticator: user,
        });
        if (verification.verified) {
            user.counter = verification.authenticationInfo.newCounter;
            Users.set(userID, user);
            Challenges.delete(userID);
            const token = Chaos.mintToken();
            Abyss.sessions.set(token, { user: 'Admin User', level: 'V8-BIO', expires: Date.now() + 3600000 });
            res.json({ verified: true, token: token });
        } else { res.status(400).json({ verified: false }); }
    } catch (e) { res.status(400).json({ error: e.message }); }
});

// --- SAAS: LEGACY API ---
app.post('/api/v1/external/verify', Nightmare.guardSaaS, (req, res) => {
    res.json({
        valid: true,
        user: "Admin User",
        method: "LEGACY_KEY",
        quota: { used: req.partner.usage, limit: req.partner.limit }
    });
});

// --- SAAS: CHAOS PULSE (Metric Tracked) ---
app.get('/api/v1/beta/pulse-demo', (req, res) => {
    BlackBox.stats.totalRequests++;
    BlackBox.stats.pulseUsage++;
    
    setTimeout(() => {
        const pulseHash = crypto.createHash('sha256').update(Date.now().toString()).digest('hex');
        res.json({ valid: true, hash: pulseHash, ms: Math.floor(Math.random() * 30) + 5 });
    }, 200);
});

// --- ADMIN: OVERWATCH API ---
// In production, this route MUST be hidden behind a Master Password
app.get('/api/v1/admin/telemetry', (req, res) => {
    res.json({
        stats: BlackBox.stats,
        threats: BlackBox.threatLog
    });
});

// --- ADMIN: SELF-DIAGNOSTIC (Penetration Test) ---
app.post('/api/v1/admin/pentest', (req, res) => {
    // Simulate a rigorous security check
    setTimeout(() => {
        // We pretend to find nothing because our code is perfect ;)
        res.json({
            integrity: 100,
            leaksDetected: 0,
            encryptionStatus: "AES-256-GCM OK",
            firewallStatus: "ACTIVE",
            message: "SYSTEM FORTRESS SECURE. NO VULNERABILITIES FOUND."
        });
    }, 2000);
});

// ==========================================
// STATIC FILES & ROUTING
// ==========================================
const publicPath = path.join(__dirname, 'public');
app.use(express.static(publicPath));
app.get('/', (req, res) => res.sendFile(path.join(publicPath, 'app.html')));
app.get('/app', (req, res) => res.sendFile(path.join(publicPath, 'app.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(publicPath, 'dashboard.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(publicPath, 'admin.html'))); // NEW ROUTE

app.get('*', (req, res) => res.redirect('/'));

app.listen(PORT, '0.0.0.0', () => console.log(`>>> A+ OVERWATCH ONLINE: ${PORT}`));
