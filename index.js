/**
 * A+ CHAOS ID: ARMORED SAAS (V13)
 * DEFENSE: Chaos (Entropy), Abyss (Hashing), Nightmare (Throttling)
 */
const express = require('express');
const path = require('path');
const cors = require('cors');
const crypto = require('crypto'); // The Chaos Engine
const { 
    generateRegistrationOptions, 
    verifyRegistrationResponse, 
    generateAuthenticationOptions, 
    verifyAuthenticationResponse 
} = require('@simplewebauthn/server');

const app = express();
const PORT = process.env.PORT || 3000;

// ALLOW ALL ORIGINS (SaaS needs this)
app.use(cors({ origin: '*' })); 
app.use(express.json());

// ==========================================
// 1. ABYSS (THE SECURE LEDGER)
// ==========================================
// We NEVER store raw API keys. We store their HASH.
// If this map is leaked, the keys are still safe.
const Abyss = {
    partners: new Map(),  // Stores Hashed Keys -> Partner Data
    sessions: new Map(),  // Stores Active User Tokens
    
    // Hash a key to look it up safely
    hash: (key) => crypto.createHash('sha256').update(key).digest('hex'),

    // Add a new partner (Simulated DB Write)
    registerPartner: (company, plan) => {
        const rawKey = Chaos.mintKey();
        const hashedKey = Abyss.hash(rawKey);
        
        const limit = plan === 'pro' ? 10000 : 50;
        
        Abyss.partners.set(hashedKey, {
            company,
            plan,
            usage: 0,
            limit,
            active: true
        });
        
        return rawKey; // Show this ONCE to the user, then forget it.
    }
};

// ==========================================
// 2. CHAOS (THE ENTROPY ENGINE)
// ==========================================
const Chaos = {
    // Generates a military-grade random API key
    mintKey: () => {
        return 'sk_chaos_' + crypto.randomBytes(24).toString('hex');
    },
    
    // Generates public session tokens
    mintToken: () => {
        return 'tk_' + crypto.randomBytes(16).toString('hex');
    }
};

// ==========================================
// 3. NIGHTMARE (THE GATEKEEPER)
// ==========================================
const Nightmare = {
    
    // Middleware: Protects the SaaS Route
    guardSaaS: (req, res, next) => {
        const rawKey = req.get('X-CHAOS-API-KEY');

        // A. EXISTENCE CHECK
        if (!rawKey) {
            return res.status(401).json({ error: "MISSING_KEY", msg: "Purchase key at A+ Dashboard." });
        }

        // B. HASH LOOKUP (Secure Compare)
        const hashedKey = Abyss.hash(rawKey);
        const partner = Abyss.partners.get(hashedKey);

        if (!partner) {
            // Delay response by 500ms to slow down brute-force attacks
            setTimeout(() => {
                res.status(403).json({ error: "INVALID_KEY", msg: "Access Denied." });
            }, 500); 
            return;
        }

        // C. STATUS CHECK
        if (!partner.active) {
            return res.status(403).json({ error: "ACCOUNT_SUSPENDED", msg: "Contact Support." });
        }

        // D. QUOTA ENFORCEMENT (The Money Check)
        if (partner.usage >= partner.limit) {
            return res.status(402).json({ 
                error: "QUOTA_EXCEEDED", 
                msg: `Limit of ${partner.limit} reached. Upgrade required.` 
            });
        }

        // E. PASS THROUGH
        partner.usage++;
        req.partner = partner; // Attach data for the route to use
        next();
    }
};

// --- SEED DATA (For Testing) ---
// Create a Demo Key: sk_chaos_demo123
// We manually hash it and put it in Abyss so you can test immediately.
const demoHash = Abyss.hash('sk_chaos_demo123');
Abyss.partners.set(demoHash, { company: 'Demo Corp', plan: 'free', usage: 0, limit: 50, active: true });


// ==========================================
// BIOMETRIC & API ROUTES
// ==========================================

// --- UTILS ---
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

// --- AUTH ROUTES (Standard V11 Logic) ---
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
            
            // USE CHAOS TO MINT TOKEN
            const token = Chaos.mintToken();
            
            // STORE IN ABYSS
            Abyss.sessions.set(token, {
                user: 'Admin User',
                level: 'V8-BIO',
                expires: Date.now() + 3600000 
            });

            res.json({ verified: true, token: token });
        } else {
            res.status(400).json({ verified: false });
        }
    } catch (e) { res.status(400).json({ error: e.message }); }
});


// ==========================================
// THE MONEY ROUTE (PROTECTED BY NIGHTMARE)
// ==========================================
app.post('/api/v1/external/verify', Nightmare.guardSaaS, (req, res) => {
    const { token } = req.body;
    
    // Nightmare has already validated the API Key and Quota.
    
    if (!token) return res.status(400).json({ valid: false, error: "No Token Provided" });

    const session = Abyss.sessions.get(token);

    if (!session) return res.json({ valid: false, error: "Invalid Token" });
    if (Date.now() > session.expires) {
        Abyss.sessions.delete(token);
        return res.json({ valid: false, error: "Token Expired" });
    }

    // SUCCESS - SEND BILLING INFO
    res.json({
        valid: true,
        user: session.user,
        securityLevel: session.level,
        billing: {
            plan: req.partner.plan,
            creditsRemaining: req.partner.limit - req.partner.usage
        }
    });
});

// --- ADMIN: GENERATE KEYS ---
app.get('/api/v1/admin/new-key', (req, res) => {
    // In production, protect this with a password!
    const key = Abyss.registerPartner('New Client', 'free');
    res.json({ note: "SAVE THIS KEY. IT WILL NOT BE SHOWN AGAIN.", apiKey: key });
});

// --- STATIC FILES ---
const publicPath = path.join(__dirname, 'public');
app.use(express.static(publicPath));
app.get('/', (req, res) => res.sendFile(path.join(publicPath, 'app.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(publicPath, 'dashboard.html')));

app.listen(PORT, '0.0.0.0', () => console.log(`>>> A+ CHAOS ARMORED: ${PORT}`));
