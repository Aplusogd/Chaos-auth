/**
 * A+ TOTEM SECURITY CORE V8: BIO-LINK
 * Pillars: CHAOS, IRON DOME, ABYSS, WEBAUTHN
 * Feature: BIOMETRIC HUMAN VERIFICATION
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
// In a real app, 'Users' would be a Database.
// Here, we use memory to store the first admin who registers.
const Users = new Map(); 
const Challenges = new Map(); // Store active challenges
const RP_ID = 'chaos-auth-iff2.onrender.com'; // UPDATE THIS TO YOUR RENDER URL IF DIFFERENT
const ORIGIN = `https://${RP_ID}`;

// ==========================================
// 👹 NIGHTMARE DEFENSE
// ==========================================
const Nightmare = {
    rateLimiter: (req, res, next) => {
        // (Simplified Rate Limiter for V8 stability)
        next();
    },
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
// 🧬 BIO-LINK ROUTES (WebAuthn)
// ==========================================

// 1. REGISTER (Bind your Face/Fingerprint)
app.get('/api/v1/auth/register-options', (req, res) => {
    const userId = 'admin'; // Single user mode for now
    
    const options = generateRegistrationOptions({
        rpName: 'A+ Totem Core',
        rpID: RP_ID,
        userID: userId,
        userName: 'admin@aplus.com',
        attestationType: 'none', // Privacy first
        authenticatorSelection: {
            residentKey: 'preferred',
            userVerification: 'required', // Forces FaceID/PIN
        },
    });

    // Save challenge to Abyss
    Challenges.set(userId, options.challenge);
    res.json(options);
});

app.post('/api/v1/auth/register-verify', async (req, res) => {
    const userId = 'admin';
    const expectedChallenge = Challenges.get(userId);
    
    if (!expectedChallenge) return res.status(400).json({ error: "Challenge expired" });

    let verification;
    try {
        verification = await verifyRegistrationResponse({
            response: req.body,
            expectedChallenge,
            expectedOrigin: ORIGIN,
            expectedRPID: RP_ID,
        });
    } catch (error) {
        return res.status(400).json({ error: error.message });
    }

    if (verification.verified) {
        const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
        // Save this "Biometric Lock" to the User Profile
        Users.set(userId, { credentialID, credentialPublicKey, counter });
        Challenges.delete(userId);
        res.json({ verified: true });
    } else {
        res.status(400).json({ verified: false });
    }
});

// 2. LOGIN (Verify you are the Human)
app.get('/api/v1/auth/login-options', (req, res) => {
    const userId = 'admin';
    const user = Users.get(userId);
    
    if (!user) return res.status(404).json({ error: "No Admin Registered" });

    const options = generateAuthenticationOptions({
        rpID: RP_ID,
        allowCredentials: [{
            id: user.credentialID,
            type: 'public-key',
            transports: ['internal'], // Prefer built-in sensors
        }],
        userVerification: 'required',
    });

    Challenges.set(userId, options.challenge);
    res.json(options);
});

app.post('/api/v1/auth/login-verify', async (req, res) => {
    const userId = 'admin';
    const user = Users.get(userId);
    const expectedChallenge = Challenges.get(userId);

    if (!user || !expectedChallenge) return res.status(400).json({ error: "Invalid State" });

    let verification;
    try {
        verification = await verifyAuthenticationResponse({
            response: req.body,
            expectedChallenge,
            expectedOrigin: ORIGIN,
            expectedRPID: RP_ID,
            authenticator: user,
        });
    } catch (error) {
        return res.status(400).json({ error: error.message });
    }

    if (verification.verified) {
        // Update counter to prevent clone attacks
        user.counter = verification.authenticationInfo.newCounter;
        Users.set(userId, user);
        Challenges.delete(userId);
        
        // SUCCESS: Issue Session
        const sessionToken = crypto.randomBytes(32).toString('hex');
        res.json({ verified: true, session: sessionToken });
    } else {
        res.status(400).json({ verified: false });
    }
});

// 3. Check if Admin Exists
app.get('/api/v1/auth/status', (req, res) => {
    res.json({ registered: Users.has('admin') });
});

app.use(express.static(publicPath));

// ROUTING
app.get('/', (req, res) => res.sendFile(path.join(publicPath, 'index.html')));
app.get('/app', (req, res) => res.sendFile(path.join(publicPath, 'app.html')));

app.listen(PORT, () => console.log(`🛡️ A+ TOTEM V8 BIO-LINK ONLINE: ${PORT}`));


