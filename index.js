/**
 * A+ CHAOS ID: V25 (DEBUGGER EDITION)
 * STATUS: Request Logging Active + Explicit File Mapping
 */
const express = require('express');
const path = require('path');
const cors = require('cors');
const fs = require('fs');
const crypto = require('crypto');
const { 
    generateRegistrationOptions, 
    verifyRegistrationResponse, 
    generateAuthenticationOptions, 
    verifyAuthenticationResponse 
} = require('@simplewebauthn/server');

const app = express();
const PORT = process.env.PORT || 3000;
const publicPath = path.join(__dirname, 'public');

// ==========================================
// 1. TRAFFIC LOGGER (WATCH YOUR LOGS!)
// ==========================================
app.use((req, res, next) => {
    console.log(`[REQUEST] ${req.method} ${req.url}`);
    next();
});

app.use(cors({ origin: '*' })); 
app.use(express.json());

// Serve Static Files (CSS/JS/HTML)
app.use(express.static(publicPath));

// ==========================================
// 2. SECURITY ENGINES
// ==========================================
const Abyss = {
    partners: new Map(),
    agents: new Map(),
    hash: (key) => crypto.createHash('sha256').update(key).digest('hex'),
};
Abyss.partners.set(Abyss.hash('sk_chaos_demo123'), { company: 'Demo', plan: 'free', usage: 0, limit: 50, active: true });
Abyss.agents.set('DEMO_AGENT_V1', { id: 'DEMO_AGENT_V1', usage: 0, limit: 500 });

const Nightmare = {
    guardSaaS: (req, res, next) => {
        const rawKey = req.get('X-CHAOS-API-KEY');
        if (!rawKey) return res.status(401).json({ error: "MISSING_KEY" });
        const partner = Abyss.partners.get(Abyss.hash(rawKey));
        if (!partner || partner.usage >= partner.limit) return res.status(403).json({ error: "ACCESS_DENIED" });
        partner.usage++;
        req.partner = partner;
        next();
    }
};

const Chaos = { mintToken: () => 'tk_' + crypto.randomBytes(16).toString('hex') };
const Users = new Map();
const Challenges = new Map();

// Load DNA
if (process.env.ADMIN_DNA) {
    try {
        const adminData = JSON.parse(process.env.ADMIN_DNA);
        if(adminData.credentialID) Users.set('admin-user', adminData);
        console.log(">>> ADMIN RESTORED.");
    } catch (e) { console.error("DNA LOAD FAILED"); }
}

// ==========================================
// 3. AUTH ROUTES
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
            res.json({ verified: true, token: Chaos.mintToken() });
        } else { res.status(400).json({ verified: false }); }
    } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post('/api/v1/external/verify', Nightmare.guardSaaS, (req, res) => {
    if (!req.partner) return res.status(500).json({ error: "ERR" });
    res.json({ valid: true, user: "Admin", quota: { used: req.partner.usage, limit: req.partner.limit } });
});

app.get('/api/v1/beta/pulse-demo', (req, res) => {
    setTimeout(() => res.json({ valid: true, hash: 'pulse_' + Date.now(), ms: 15 }), 200);
});

// ==========================================
// 4. EXPLICIT ROUTING (THE MAP)
// ==========================================

// Helper to serve file with debug logs
const serve = (filename, res) => {
    const file = path.join(publicPath, filename);
    if (fs.existsSync(file)) {
        console.log(`   > Serving: ${filename}`);
        res.sendFile(file);
    } else {
        console.error(`   > ERROR: ${filename} MISSING in public folder!`);
        res.status(404).send(`<h1>ERROR: ${filename} Not Found</h1>`);
    }
};

// Map EVERY page explicitly
app.get('/', (req, res) => serve('app.html', res));
app.get('/app', (req, res) => serve('app.html', res));
app.get('/app.html', (req, res) => serve('app.html', res));

app.get('/dashboard', (req, res) => serve('dashboard.html', res));
app.get('/dashboard.html', (req, res) => serve('dashboard.html', res));

app.get('/admin', (req, res) => serve('admin.html', res));
app.get('/admin.html', (req, res) => serve('admin.html', res));

// Catch-All
app.get('*', (req, res) => {
    console.log(`   > Unknown Route: ${req.url} -> Redirecting to /`);
    res.redirect('/');
});

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V25 (DEBUG) ONLINE: ${PORT}`));
