/**
 * A+ TOTEM SECURITY CORE V8: BIO-LINK (STABLE)
 * Pillars: CHAOS, IRON DOME, ABYSS, WEBAUTHN
 * Feature: BIOMETRIC HUMAN VERIFICATION
 */

const express = require('express');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
// Import WebAuthn tools
const SimpleWebAuthn = require('@simplewebauthn/server');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
const publicPath = path.join(__dirname, 'public');

if (!fs.existsSync(publicPath)) {
    console.error("❌ CRITICAL: 'public' folder missing! Create it and add index.html");
}

// ==========================================
// 🌌 THE ABYSS (State)
// ==========================================
// In production, use a real database (Redis/Postgres)
const Users = new Map(); 
const Challenges = new Map(); 

// UPDATE THIS TO YOUR REAL RENDER URL (No 'https://', just the domain)
// Example: 'aplus-chaos.onrender.com'
const RP_ID = process.env.RENDER_EXTERNAL_HOSTNAME || 'localhost'; 
const ORIGIN = `https://${RP_ID}`;

console.log(`[SYSTEM] Bio-Link Configured for ID: ${RP_ID}`);
console.log(`[SYSTEM] Expected Origin: ${ORIGIN}`);

// ==========================================
// 👹 NIGHTMARE DEFENSE
// ==========================================
const Nightmare = {
    rateLimiter: (req, res, next) => next(), // Simplified for stability
    antiBot: (req, res, next) => {
        const secretHeader = req.get('X-APLUS-SECURE');
        // Allow public access to landing page, restrict API
        if (req.path.startsWith('/api') && secretHeader !== 'TOTEM_V8_BIO') {
             // console.log("[NIGHTMARE] Blocked request missing header");
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
    
    try {
        // Generate registration options
        const options = await SimpleWebAuthn.generateRegistrationOptions({
            rpName: 'A+ Totem Core',
            rpID: RP_ID,
            userID: userId,
            userName: 'admin@aplus.com',
            attestationType: 'none',
            authenticatorSelection: {
                residentKey: 'preferred',
                userVerification: 'required',
            },
        });

        // CRITICAL FIX: Ensure options generated correctly
        if (!options || !options.challenge) {
            console.error("❌ Error: Failed to generate registration options.");
            return res.status(500).json({ error: "Internal Server Error: Challenge Gen Failed" });
        }

        // Save challenge to Abyss
        Challenges.set(userId, options.challenge);
        console.log(`[ABYSS] Challenge Created for Register: ${options.challenge}`);
        
        res.json(options);
    } catch (err) {
        console.error("❌ EXCEPTION in register-options:", err);
        res.status(500).json({ error: err.message });
    }
});

// 2. REGISTER VERIFY
app.post('/api/v1/auth/register-verify', async (req, res) => {
    const userId = 'admin';
    const expectedChallenge = Challenges.get(userId);
    
    if (!expectedChallenge) {
        console.error("[ABYSS] No active challenge found for user.");
        return res.status(400).json({ error: "Challenge expired or not found" });
    }

    try {
        const verification = await SimpleWebAuthn.verifyRegistrationResponse({
            response: req.body,
            expectedChallenge,
            expectedOrigin: ORIGIN,
            expectedRPID: RP_ID,
        });

        if (verification.verified) {
            const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
            Users.set(userId, { credentialID, credentialPublicKey, counter });
            Challenges.delete(userId);
            console.log("[SUCCESS] Biometric Bound.");
            res.json({ verified: true });
        } else {
            console.error("[FAIL] Verification returned false.");
            res.status(400).json({ verified: false });
        }
    } catch (error) {
        console.error("❌ EXCEPTION in register-verify:", error);
        res.status(400).json({ error: error.message });
    }
});

// 3. LOGIN OPTIONS
app.get('/api/v1/auth/login-options', async (req, res) => {
    const userId = 'admin';
    const user = Users.get(userId);
    
    if (!user) return res.status(404).json({ error: "No Admin Registered" });

    try {
        const options = await SimpleWebAuthn.generateAuthenticationOptions({
            rpID: RP_ID,
            allowCredentials: [{
                id: user.credentialID,
                type: 'public-key',
                transports: ['internal'],
            }],
            userVerification: 'required',
        });

        Challenges.set(userId, options.challenge);
        res.json(options);
    } catch (err) {
        console.error("❌ EXCEPTION in login-options:", err);
        res.status(500).json({ error: err.message });
    }
});

// 4. LOGIN VERIFY
app.post('/api/v1/auth/login-verify', async (req, res) => {
    const userId = 'admin';
    const user = Users.get(userId);
    const expectedChallenge = Challenges.get(userId);

    if (!user || !expectedChallenge) return res.status(400).json({ error: "Invalid State" });

    try {
        const verification = await SimpleWebAuthn.verifyAuthenticationResponse({
            response: req.body,
            expectedChallenge,
            expectedOrigin: ORIGIN,
            expectedRPID: RP_ID,
            authenticator: user,
        });

        if (verification.verified) {
            user.counter = verification.authenticationInfo.newCounter;
            Users.set(userId, user);
            Challenges.delete(userId);
            
            const sessionToken = crypto.randomBytes(32).toString('hex');
            console.log("[SUCCESS] Login Verified.");
            res.json({ verified: true, session: sessionToken });
        } else {
            res.status(400).json({ verified: false });
        }
    } catch (error) {
        console.error("❌ EXCEPTION in login-verify:", error);
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
    // If landing.html exists, serve it. Otherwise index.html
    const landing = path.join(publicPath, 'landing.html');
    if (fs.existsSync(landing)) res.sendFile(landing);
    else res.sendFile(path.join(publicPath, 'index.html'));
});
app.get('/app', (req, res) => res.sendFile(path.join(publicPath, 'index.html')));

app.listen(PORT, () => console.log(`🛡️ A+ TOTEM V8 BIO-LINK ONLINE: ${PORT}`));


