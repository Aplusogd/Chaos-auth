/**
 * A+ CHAOS ID: COMPLETE CORE (V16)
 * INCLUDES: SaaS API, Chaos Pulse, and Routing Fixes
 */
const express = require('express');
const path = require('path'); // <--- THIS WAS LIKELY MISSING
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

// ALLOW ALL ORIGINS
app.use(cors({ origin: '*' })); 
app.use(express.json());

// ==========================================
// 1. ABYSS (THE SECURE LEDGER)
// ==========================================
const Abyss = {
    partners: new Map(),
    sessions: new Map(),
    
    hash: (key) => crypto.createHash('sha256').update(key).digest('hex'),

    registerPartner: (company, plan) => {
        const rawKey = Chaos.mintKey();
        const hashedKey = Abyss.hash(rawKey);
        const limit = plan === 'pro' ? 10000 : 50; // Legacy Limits
        
        Abyss.partners.set(hashedKey, {
            company,
            plan,
            usage: 0,
            limit,
            active: true
        });
        return rawKey;
    }
};

// ==========================================
// 2. CHAOS (THE ENTROPY ENGINE)
// ==========================================
const Chaos = {
    mintKey: () => 'sk_chaos_' + crypto.randomBytes(24).toString('hex'),
    mintToken: () => 'tk_' + crypto.randomBytes(16).toString('hex')
};

// ==========================================
// 3. NIGHTMARE (THE GATEKEEPER)
// ==========================================
const Nightmare = {
    guardSaaS: (req, res, next) => {
        const rawKey = req.get('X-CHAOS-API-KEY');

        if (!rawKey) return res.status(401).json({ error: "MISSING_KEY" });

        const hashedKey = Abyss.hash(rawKey);
        const partner = Abyss.partners.get(hashedKey);

        if (!partner) {
            setTimeout(() => res.status(403).json({ error: "INVALID_KEY" }), 500); 
            return;
        }

        if (partner.usage >= partner.limit) {
            return res.status(402).json({ error: "QUOTA_EXCEEDED" });
        }

        partner.usage++;
        req.partner = partner;
        next();
    }
};

// --- SEED DATA ---
const demoHash = Abyss.hash('sk_chaos_demo123');
Abyss.partners.set(demoHash, { company: 'Demo Corp', plan: 'free', usage: 48, limit: 50, active: true });

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

// ==========================================
// ROUTES
// ==========================================

// --- AUTH: REGISTER ---
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

// --- AUTH: LOGIN ---
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

// --- SAAS: EXTERNAL VERIFY ---
app.post('/api/v1/external/verify', Nightmare.guardSaaS, (req, res) => {
    const { token } = req.body;
    if (!token) return res.status(400).json({ valid: false, error: "No Token" });

    const session = Abyss.sessions.get(token);
    if (!session || Date.now() > session.expires) return res.json({ valid: false, error: "Invalid/Expired Token" });

    res.json({
        valid: true,
        user: session.user,
        securityLevel: session.level,
        billing: { plan: req.partner.plan, creditsRemaining: req.partner.limit - req.partner.usage }
    });
});

// --- BETA: CHAOS PULSE DEMO ---
app.get('/api/v1/beta/pulse-demo', (req, res) => {
    setTimeout(() => {
        const pulseHash = crypto.createHash('sha256').update(Date.now().toString()).digest('hex');
        res.json({ valid: true, hash: pulseHash, ms: Math.floor(Math.random() * 50) + 10 });
    }, 500);
});

// ==========================================
// STATIC FILES & ROUTING (FIXED)
// ==========================================
const publicPath = path.join(__dirname, 'public');
app.use(express.static(publicPath));

app.get('/', (req, res) => res.sendFile(path.join(publicPath, 'app.html')));
app.get('/app', (req, res) => res.sendFile(path.join(publicPath, 'app.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(publicPath, 'dashboard.html')));

app.get('*', (req, res) => res.redirect('/'));

// LISTEN
app.listen(PORT, '0.0.0.0', () => console.log(`>>> A+ CHAOS ONLINE: ${PORT}`));
