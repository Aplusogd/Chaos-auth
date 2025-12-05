/**
 * A+ TOTEM SECURITY CORE V8: BIO-LINK
 * Pillars: CHAOS, IRON DOME, ABYSS, WEBAUTHN
 * Fix: Auto-detects domain to prevent WebAuthn origin errors.
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

if (!fs.existsSync(publicPath)) console.error("❌ CRITICAL: 'public' folder missing!");

// ==========================================
// 🌌 THE ABYSS (State)
// ==========================================
const Users = new Map(); 
const Challenges = new Map(); 

// AUTO-DETECT DOMAIN (Fixes Origin Mismatch Errors)
const getRpId = (req) => req.get('host').split(':')[0];
const getOrigin = (req) => {
    const host = req.get('host');
    const protocol = host.includes('localhost') ? 'http' : 'https';
    return `${protocol}://${host}`;
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

// 1. REGISTER
app.get('/api/v1/auth/register-options', async (req, res) => {
    const userId = 'admin';
    try {
        const options = await generateRegistrationOptions({
            rpName: 'A+ Totem Core',
            rpID: getRpId(req),
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
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/v1/auth/register-verify', async (req, res) => {
    const userId = 'admin';
    const expectedChallenge = Challenges.get(userId);
    if (!expectedChallenge) return res.status(400).json({ error: "Challenge expired" });

    try {
        const verification = await verifyRegistrationResponse({
            response: req.body,
            expectedChallenge,
            expectedOrigin: getOrigin(req),
            expectedRPID: getRpId(req),
        });

        if (verification.verified) {
            const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
            Users.set(userId, { credentialID, credentialPublicKey, counter });
            Challenges.delete(userId);
            res.json({ verified: true });
        } else {
            res.status(400).json({ verified: false });
        }
    } catch (error) { res.status(400).json({ error: error.message }); }
});

// 2. LOGIN
app.get('/api/v1/auth/login-options', async (req, res) => {
    const userId = 'admin';
    const user = Users.get(userId);
    if (!user) return res.status(404).json({ error: "No Admin Registered" });

    try {
        const options = await generateAuthenticationOptions({
            rpID: getRpId(req),
            allowCredentials: [{ id: user.credentialID, type: 'public-key', transports: ['internal'] }],
            userVerification: 'required',
        });
        Challenges.set(userId, options.challenge);
        res.json(options);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/v1/auth/login-verify', async (req, res) => {
    const userId = 'admin';
    const user = Users.get(userId);
    const expectedChallenge = Challenges.get(userId);
    if (!user || !expectedChallenge) return res.status(400).json({ error: "Invalid State" });

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
            Users.set(userId, user);
            Challenges.delete(userId);
            const sessionToken = crypto.randomBytes(32).toString('hex');
            res.json({ verified: true, session: sessionToken });
        } else {
            res.status(400).json({ verified: false });
        }
    } catch (error) { res.status(400).json({ error: error.message }); }
});

app.get('/api/v1/auth/status', (req, res) => {
    res.json({ registered: Users.has('admin') });
});

// ROUTES
app.use(express.static(publicPath));
app.get('/', (req, res) => {
    const landing = path.join(publicPath, 'landing.html');
    if (fs.existsSync(landing)) res.sendFile(landing);
    else res.sendFile(path.join(publicPath, 'index.html'));
});
app.get('/app', (req, res) => res.sendFile(path.join(publicPath, 'index.html')));

app.listen(PORT, () => console.log(`🛡️ A+ TOTEM V8 BIO-LINK ONLINE: ${PORT}`));


