/**
 * A+ TOTEM SECURITY CORE: SAAS EDITION (STABLE)
 * Fixes: Dynamic RP_ID detection to prevent WebAuthn failures.
 */

const express = require('express');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } = require('@simplewebauthn/server');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
const publicPath = path.join(__dirname, 'public');

// ==========================================
// 🌌 THE ABYSS (State)
// ==========================================
const Users = new Map(); 
const Challenges = new Map(); 

// DYNAMIC DOMAIN CONFIGURATION
// This is crucial for WebAuthn to work on both Replit and Render without manual changes.
const getOrigin = (req) => {
    const host = req.get('host'); // e.g., 'chaos-auth-iff2.onrender.com'
    // If localhost, use http. If cloud, use https.
    const protocol = host.includes('localhost') ? 'http' : 'https';
    return `${protocol}://${host}`;
};

const getRpId = (req) => {
    // Returns just the domain (e.g., 'chaos-auth-iff2.onrender.com')
    return req.get('host').split(':')[0]; 
};

// ==========================================
// 👹 NIGHTMARE DEFENSE
// ==========================================
const Nightmare = {
    rateLimiter: (req, res, next) => next(),
    antiBot: (req, res, next) => {
        const secretHeader = req.get('X-APLUS-SECURE');
        if (req.path.startsWith('/api') && secretHeader !== 'TOTEM_V8_BIO') {
            return res.status(403).json({ error: "ERR_MISSING_HEADER" });
        }
        next();
    }
};

app.use(Nightmare.rateLimiter);
app.use(Nightmare.antiBot);

// ==========================================
// 🧬 BIO-LINK ROUTES
// ==========================================

// 1. REGISTER OPTIONS
app.get('/api/v1/auth/register-options', async (req, res) => {
    const userId = 'admin';
    const rpID = getRpId(req);
    
    try {
        const options = await generateRegistrationOptions({
            rpName: 'A+ Totem Core',
            rpID: rpID,
            userID: userId,
            userName: 'admin@aplus.com',
            attestationType: 'none',
            authenticatorSelection: {
                residentKey: 'preferred',
                userVerification: 'required',
            },
        });

        Challenges.set(userId, options.challenge);
        res.json(options);
    } catch (err) {
        console.error("Reg Options Error:", err);
        res.status(500).json({ error: err.message });
    }
});

// 2. REGISTER VERIFY
app.post('/api/v1/auth/register-verify', async (req, res) => {
    const userId = 'admin';
    const expectedChallenge = Challenges.get(userId);
    const rpID = getRpId(req);
    const origin = getOrigin(req);

    if (!expectedChallenge) return res.status(400).json({ error: "Challenge expired" });

    try {
        const verification = await verifyRegistrationResponse({
            response: req.body,
            expectedChallenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
        });

        if (verification.verified) {
            const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
            Users.set(userId, { credentialID, credentialPublicKey, counter });
            Challenges.delete(userId);
            res.json({ verified: true });
        } else {
            res.status(400).json({ verified: false });
        }
    } catch (error) {
        console.error("Reg Verify Error:", error);
        res.status(400).json({ error: error.message });
    }
});

// 3. LOGIN OPTIONS
app.get('/api/v1/auth/login-options', async (req, res) => {
    const userId = 'admin';
    const user = Users.get(userId);
    const rpID = getRpId(req);
    
    if (!user) return res.status(404).json({ error: "No Admin Registered" });

    const options = await generateAuthenticationOptions({
        rpID: rpID,
        allowCredentials: [{
            id: user.credentialID,
            type: 'public-key',
            transports: ['internal'],
        }],
        userVerification: 'required',
    });

    Challenges.set(userId, options.challenge);
    res.json(options);
});

// 4. LOGIN VERIFY
app.post('/api/v1/auth/login-verify', async (req, res) => {
    const userId = 'admin';
    const user = Users.get(userId);
    const expectedChallenge = Challenges.get(userId);
    const rpID = getRpId(req);
    const origin = getOrigin(req);

    if (!user || !expectedChallenge) return res.status(400).json({ error: "Invalid State" });

    try {
        const verification = await verifyAuthenticationResponse({
            response: req.body,
            expectedChallenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
            authenticator: user,
        });

        if (verification.verified) {
            user.counter = verification.authenticationInfo.newCounter;
            Users.set(userId, user);
            Challenges.delete(userId);
            const sessionToken = crypto.randomBytes(32).toString('hex');
            res.json({ verified: true, session: sessionToken });
        } else {
            res.status(400).json({ verified: false });
        }
    } catch (error) {
        console.error("Auth Verify Error:", error);
        res.status(400).json({ error: error.message });
    }
});

// 5. STATUS CHECK
app.get('/api/v1/auth/status', (req, res) => {
    res.json({ registered: Users.has('admin') });
});


// ROUTES
app.use(express.static(publicPath));

app.get('/', (req, res) => {
    res.sendFile(path.join(publicPath, 'index.html')); // Landing Page
});

app.get('/app', (req, res) => {
    res.sendFile(path.join(publicPath, 'app.html')); // War Room
});

app.listen(PORT, () => console.log(`🛡️ A+ TOTEM V8 AUTO-CONFIG LIVE: ${PORT}`));


