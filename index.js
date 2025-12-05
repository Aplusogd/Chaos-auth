/**
 * A+ CHAOS ID: V18 (LIVE TRIAL ENGINE)
 * Features: Real Quota Tracking for Legacy vs Pulse
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
// 1. ABYSS (THE LEDGER)
// ==========================================
const Abyss = {
    partners: new Map(), // Legacy API Keys
    agents: new Map(),   // Chaos Pulse Agents
    sessions: new Map(),
    
    hash: (key) => crypto.createHash('sha256').update(key).digest('hex'),
};

// --- SEED DATA: LEGACY KEY (Limit: 50) ---
const demoHash = Abyss.hash('sk_chaos_demo123');
Abyss.partners.set(demoHash, { 
    company: 'Public Demo', 
    plan: 'free', 
    usage: 0, 
    limit: 50, // TIGHT LEASH
    active: true 
});

// --- SEED DATA: PULSE AGENT (Limit: 500) ---
Abyss.agents.set('DEMO_AGENT_V1', {
    id: 'DEMO_AGENT_V1',
    usage: 0,
    limit: 500 // ABUNDANCE
});

// ==========================================
// 2. NIGHTMARE (THE GATEKEEPER)
// ==========================================
const Nightmare = {
    guardSaaS: (req, res, next) => {
        const rawKey = req.get('X-CHAOS-API-KEY');
        if (!rawKey) return res.status(401).json({ error: "MISSING_KEY" });

        const hashedKey = Abyss.hash(rawKey);
        const partner = Abyss.partners.get(hashedKey);

        if (!partner) return res.status(403).json({ error: "INVALID_KEY" });

        // REAL LIMIT CHECK
        if (partner.usage >= partner.limit) {
            return res.status(402).json({ 
                error: "TRIAL_ENDED", 
                message: "Legacy Limit Reached (50/50). Upgrade to Chaos Pulse." 
            });
        }

        partner.usage++;
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
            // MINT TOKEN for SaaS testing
            const token = Chaos.mintToken();
            Abyss.sessions.set(token, { user: 'Admin User', level: 'V8-BIO', expires: Date.now() + 3600000 });
            res.json({ verified: true, token: token });
        } else { res.status(400).json({ verified: false }); }
    } catch (e) { res.status(400).json({ error: e.message }); }
});

// --- SAAS: LEGACY API (Tracked & Limited) ---
app.post('/api/v1/external/verify', Nightmare.guardSaaS, (req, res) => {
    // If we are here, usage was already incremented by Nightmare
    res.json({
        valid: true,
        user: "Admin User",
        method: "LEGACY_KEY",
        quota: {
            used: req.partner.usage,
            limit: req.partner.limit,
            remaining: req.partner.limit - req.partner.usage
        }
    });
});

// --- SAAS: CHAOS PULSE (The "Hook") ---
app.get('/api/v1/beta/pulse-demo', (req, res) => {
    const agent = Abyss.agents.get('DEMO_AGENT_V1');
    
    // 1. Check Limits
    if (agent.usage >= agent.limit) {
        return res.status(402).json({ error: "PULSE_TRIAL_ENDED", msg: "500/500 Used. Contact Sales." });
    }

    // 2. Increment
    agent.usage++;

    // 3. Simulate High-Speed Math
    setTimeout(() => {
        const pulseHash = crypto.createHash('sha256').update(Date.now().toString()).digest('hex');
        res.json({ 
            valid: true, 
            hash: pulseHash, 
            ms: Math.floor(Math.random() * 30) + 5, // Faster than Legacy
            quota: {
                used: agent.usage,
                limit: agent.limit,
                remaining: agent.limit - agent.usage
            }
        });
    }, 200); // Fast response
});

// ==========================================
// STATIC FILES & ROUTING
// ==========================================
const publicPath = path.join(__dirname, 'public');
app.use(express.static(publicPath));
app.get('/', (req, res) => res.sendFile(path.join(publicPath, 'app.html')));
app.get('/app', (req, res) => res.sendFile(path.join(publicPath, 'app.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(publicPath, 'dashboard.html')));
app.get('*', (req, res) => res.redirect('/'));

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V18 ONLINE: ${PORT}`));
