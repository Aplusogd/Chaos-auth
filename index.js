/**
 * A+ CHAOS ID: V22 (STABLE)
 * STATUS: FIXED ORDER OF OPERATIONS
 */
const express = require('express'); // Line 1: Build Engine
const path = require('path');
const cors = require('cors');
const fs = require('fs'); // Added for file checks
const crypto = require('crypto');
const { 
    generateRegistrationOptions, 
    verifyRegistrationResponse, 
    generateAuthenticationOptions, 
    verifyAuthenticationResponse 
} = require('@simplewebauthn/server');

const app = express(); // Line 15: Create App
const PORT = process.env.PORT || 3000;

app.use(cors({ origin: '*' })); 
app.use(express.json());

// ==========================================
// 1. PERSISTENCE (Admin DNA)
// ==========================================
const Users = new Map(); 
if (process.env.ADMIN_DNA) {
    try {
        const adminData = JSON.parse(process.env.ADMIN_DNA);
        if(adminData.credentialID) Users.set('admin-user', adminData);
        console.log(">>> SYSTEM LOCKED. ADMIN RESTORED FROM ENV.");
    } catch (e) { console.error("DNA LOAD FAILED"); }
}

// ==========================================
// 2. ABYSS & NIGHTMARE
// ==========================================
const Abyss = {
    partners: new Map(),
    sessions: new Map(),
    agents: new Map(),
    hash: (key) => crypto.createHash('sha256').update(key).digest('hex'),
};

// Seed Data
const demoHash = Abyss.hash('sk_chaos_demo123');
Abyss.partners.set(demoHash, { company: 'Public Demo', plan: 'free', usage: 0, limit: 50, active: true });
Abyss.agents.set('DEMO_AGENT_V1', { id: 'DEMO_AGENT_V1', usage: 0, limit: 500 });

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
// 3. AUTH ROUTES (Biometrics)
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
            const userData = { credentialID, credentialPublicKey, counter };
            Users.set(userID, userData);
            Challenges.delete(userID);
            // Send DNA back for mobile setup
            res.json({ verified: true, adminDNA: JSON.stringify(userData) });
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

// --- SAAS & BETA ROUTES ---
app.post('/api/v1/external/verify', Nightmare.guardSaaS, (req, res) => {
    res.json({
        valid: true,
        user: "Admin User",
        method: "LEGACY_KEY",
        quota: { used: req.partner.usage, limit: req.partner.limit, remaining: req.partner.limit - req.partner.usage }
    });
});

app.get('/api/v1/beta/pulse-demo', (req, res) => {
    const agent = Abyss.agents.get('DEMO_AGENT_V1');
    if (agent.usage >= agent.limit) return res.status(402).json({ error: "LIMIT", msg: "Limit Reached" });
    agent.usage++;
    setTimeout(() => {
        const pulseHash = crypto.createHash('sha256').update(Date.now().toString()).digest('hex');
        res.json({ 
            valid: true, 
            hash: pulseHash, 
            ms: Math.floor(Math.random() * 30) + 5,
            quota: { used: agent.usage, limit: agent.limit }
        });
    }, 200);
});

// ==========================================
// STATIC FILES & DEBUG ROUTING
// ==========================================
const publicPath = path.join(__dirname, 'public');
app.use(express.static(publicPath));

// DEBUG ROUTE: Check if dashboard exists
app.get('/dashboard.html', (req, res) => {
    const file = path.join(publicPath, 'dashboard.html');
    if (fs.existsSync(file)) {
        res.sendFile(file);
    } else {
        console.error(`[ERROR] Missing: ${file}`);
        res.status(404).send("<h1>ERROR: dashboard.html missing from public folder</h1>");
    }
});

// STANDARD ROUTING
app.get('/', (req, res) => res.sendFile(path.join(publicPath, 'app.html')));
app.get('/app', (req, res) => res.sendFile(path.join(publicPath, 'app.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(publicPath, 'dashboard.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(publicPath, 'admin.html')));

app.get('*', (req, res) => res.redirect('/'));

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V22 ONLINE: ${PORT}`));
