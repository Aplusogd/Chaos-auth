/**
 * A+ CHAOS ID: V24 (STABILITY ENGINE)
 * STATUS: Crash Proofing + Global Error Handling
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

// 1. SETUP APP
const app = express();
const PORT = process.env.PORT || 3000;
const publicPath = path.join(__dirname, 'public');

app.use(cors({ origin: '*' })); 
app.use(express.json());
app.use(express.static(publicPath));

// 2. DEFINE SECURITY ENGINES (MUST BE AT TOP)
const Abyss = {
    partners: new Map(),
    agents: new Map(),
    hash: (key) => crypto.createHash('sha256').update(key).digest('hex'),
};

// Seed Data
const demoHash = Abyss.hash('sk_chaos_demo123');
Abyss.partners.set(demoHash, { company: 'Demo', plan: 'free', usage: 0, limit: 50, active: true });
Abyss.agents.set('DEMO_AGENT_V1', { id: 'DEMO_AGENT_V1', usage: 0, limit: 500 });

const Nightmare = {
    guardSaaS: (req, res, next) => {
        try {
            const rawKey = req.get('X-CHAOS-API-KEY');
            if (!rawKey) return res.status(401).json({ error: "MISSING_KEY" });
            
            const partner = Abyss.partners.get(Abyss.hash(rawKey));
            if (!partner) return res.status(403).json({ error: "INVALID_KEY" });
            
            if (partner.usage >= partner.limit) return res.status(402).json({ error: "QUOTA_EXCEEDED" });

            partner.usage++;
            req.partner = partner; // Attach for next step
            next();
        } catch (e) {
            console.error("Nightmare Error:", e);
            res.status(500).json({ error: "SECURITY_CHECK_FAILED" });
        }
    }
};

const Chaos = { mintToken: () => 'tk_' + crypto.randomBytes(16).toString('hex') };
const Users = new Map(); 
const Challenges = new Map();

// 3. PERSISTENCE (Admin DNA)
if (process.env.ADMIN_DNA) {
    try {
        const adminData = JSON.parse(process.env.ADMIN_DNA);
        if(adminData.credentialID) Users.set('admin-user', adminData);
        console.log(">>> ADMIN RESTORED FROM ENV.");
    } catch (e) { console.error("DNA LOAD FAILED"); }
}

// 4. AUTH ROUTES
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

// 5. SAAS & BETA ROUTES
app.post('/api/v1/external/verify', Nightmare.guardSaaS, (req, res) => {
    // Safety check in case middleware failed but passed through
    if (!req.partner) return res.status(500).json({ error: "INTERNAL_ERROR_NO_PARTNER" });
    
    res.json({
        valid: true,
        user: "Admin User",
        method: "LEGACY_KEY",
        quota: { used: req.partner.usage, limit: req.partner.limit }
    });
});

app.get('/api/v1/beta/pulse-demo', (req, res) => {
    const agent = Abyss.agents.get('DEMO_AGENT_V1');
    if (agent.usage >= agent.limit) return res.status(402).json({ error: "LIMIT", msg: "Limit Reached" });
    agent.usage++;
    
    setTimeout(() => {
        res.json({ 
            valid: true, 
            hash: 'pulse_' + Date.now(), 
            ms: Math.floor(Math.random() * 30) + 5,
            quota: { used: agent.usage, limit: agent.limit }
        });
    }, 200);
});

// 6. ROUTING (THE WHITE SCREEN FIXER)
// This forces the server to explicitly find the files.
app.get('/dashboard', (req, res) => {
    const file = path.join(publicPath, 'dashboard.html');
    if (fs.existsSync(file)) res.sendFile(file);
    else res.send("<h1>ERROR: dashboard.html is missing in public folder</h1>");
});

app.get('/admin', (req, res) => {
    const file = path.join(publicPath, 'admin.html');
    if (fs.existsSync(file)) res.sendFile(file);
    else res.send("<h1>ERROR: admin.html is missing in public folder</h1>");
});

// Root & Catch-All
app.get('/', (req, res) => res.sendFile(path.join(publicPath, 'app.html')));
app.get('/app', (req, res) => res.sendFile(path.join(publicPath, 'app.html')));

// 7. GLOBAL ERROR HANDLER (PREVENTS CRASHES)
app.use((err, req, res, next) => {
    console.error("!!! SERVER ERROR:", err.stack);
    res.status(500).send("<h1>System Critical Error</h1><p>Check Logs.</p>");
});

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V24 STABLE: ${PORT}`));
