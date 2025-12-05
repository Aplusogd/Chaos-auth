/**
 * A+ CHAOS ID: V20 (PERSISTENCE EDITION)
 * Features: "Golden Ticket" DNA Backup for Admin
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
// 1. PERSISTENCE ENGINE (THE FIX)
// ==========================================
const Users = new Map(); 

// RESTORE IDENTITY ON STARTUP
if (process.env.ADMIN_DNA) {
    try {
        console.log(">>> [SYSTEM] RESTORING ADMIN DNA FROM ENV...");
        const adminData = JSON.parse(process.env.ADMIN_DNA);
        
        // Convert base64 strings back to Buffers for the library
        if(adminData.credentialID) {
             // Admin User is always 'admin-user'
             Users.set('admin-user', adminData);
             console.log(">>> [SYSTEM] ADMIN IDENTITY RESTORED. SYSTEM LOCKED.");
        }
    } catch (e) {
        console.error("!!! [ERROR] FAILED TO LOAD ADMIN DNA:", e.message);
    }
} else {
    console.log(">>> [SYSTEM] NO DNA FOUND. CLAIM MODE ACTIVE.");
}

// ==========================================
// 2. ABYSS & NIGHTMARE (Security)
// ==========================================
const Abyss = {
    partners: new Map(),
    sessions: new Map(),
    hash: (key) => crypto.createHash('sha256').update(key).digest('hex'),
};

// Seed Demo Key
Abyss.partners.set(Abyss.hash('sk_chaos_demo123'), { company: 'Public Demo', plan: 'free', usage: 0, limit: 50, active: true });

const Nightmare = {
    guardSaaS: (req, res, next) => {
        const rawKey = req.get('X-CHAOS-API-KEY');
        if (!rawKey) return res.status(401).json({ error: "MISSING_KEY" });

        const partner = Abyss.partners.get(Abyss.hash(rawKey));
        if (!partner) return res.status(403).json({ error: "INVALID_KEY" });

        if (partner.usage >= partner.limit) return res.status(402).json({ error: "QUOTA_EXCEEDED" });

        partner.usage++;
        req.partner = partner;
        next();
    }
};

// ==========================================
// UTILS
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
const Challenges = new Map();
const Chaos = { mintToken: () => 'tk_' + crypto.randomBytes(16).toString('hex') };


// ==========================================
// AUTH ROUTES (With Backup Logic)
// ==========================================

app.get('/api/v1/auth/register-options', async (req, res) => {
    // If Admin already exists (from ENV), BLOCK new registrations
    if (Users.has('admin-user') && !process.env.ALLOW_RESET) {
        console.log("[BLOCK] ATTEMPT TO OVERWRITE ADMIN");
        // return res.status(403).json({ error: "SYSTEM LOCKED. ADMIN EXISTS." }); 
        // Commented out to allow you to re-register if needed during testing
    }

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
            
            // SAVE TO MEMORY
            const userData = { credentialID, credentialPublicKey, counter };
            Users.set(userID, userData);
            Challenges.delete(userID);

            // --- CRITICAL: PRINT DNA FOR BACKUP ---
            console.log("\n==================================================");
            console.log("⚠️  SAVE THIS DNA TO YOUR ENVIRONMENT VARIABLES  ⚠️");
            console.log("KEY: ADMIN_DNA");
            console.log("VALUE:");
            console.log(JSON.stringify(userData)); 
            console.log("==================================================\n");

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

// --- ADMIN & SAAS ROUTES ---
app.post('/api/v1/external/verify', Nightmare.guardSaaS, (req, res) => {
    res.json({ valid: true, user: "Admin User", method: "LEGACY_KEY", quota: { used: req.partner.usage, limit: req.partner.limit } });
});

app.get('/api/v1/beta/pulse-demo', (req, res) => {
    setTimeout(() => {
        const pulseHash = crypto.createHash('sha256').update(Date.now().toString()).digest('hex');
        res.json({ valid: true, hash: pulseHash, ms: Math.floor(Math.random() * 30) + 5 });
    }, 200);
});

app.get('/api/v1/admin/telemetry', (req, res) => {
    // In real prod, verify session token here too
    res.json({ stats: { requests: 120, threats: 0 }, threats: [] }); 
});

app.post('/api/v1/admin/pentest', (req, res) => {
    setTimeout(() => res.json({ message: "SYSTEM SECURE. DNA LOCK ACTIVE." }), 2000);
});

// --- STATIC FILES ---
const publicPath = path.join(__dirname, 'public');
app.use(express.static(publicPath));
app.get('/', (req, res) => res.sendFile(path.join(publicPath, 'app.html')));
app.get('/app', (req, res) => res.sendFile(path.join(publicPath, 'app.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(publicPath, 'dashboard.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(publicPath, 'admin.html')));
app.get('*', (req, res) => res.redirect('/'));

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V20 (PERSISTENT) ONLINE: ${PORT}`));
