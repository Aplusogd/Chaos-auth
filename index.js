/**
 * A+ CHAOS CORE: IDENTITY PROVIDER (IdP)
 * Features: Biometric Auth + Public Verification API
 */
const express = require('express');
const path = require('path');
const fs = require('fs');
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

// ALLOW EXTERNAL VERIFICATION (CORS)
app.use(cors({ origin: '*' })); 
app.use(express.json());

// --- IN-MEMORY DB ---
const Users = new Map(); 
const Challenges = new Map();
const ActiveSessions = new Map(); // Stores valid tokens

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

// --- MIDDLEWARE ---
const checkHeader = (req, res, next) => {
    const secret = req.get('X-APLUS-SECURE');
    // Allow external verify calls without the header (they use tokens instead)
    if (req.path === '/api/v1/external/verify') return next();
    
    if (req.path.startsWith('/api') && secret !== 'TOTEM_V8_BIO') {
        return res.status(403).json({ error: "SECURE_HEADER_MISSING" });
    }
    next();
};

app.use(checkHeader);

// --- 1. BIOMETRIC AUTH ROUTES ---

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
            
            // GENERATE PUBLIC TOKEN
            const token = "CHAOS-" + crypto.randomBytes(16).toString('hex').toUpperCase();
            
            // Store token in Active Sessions (valid for 1 hour)
            ActiveSessions.set(token, {
                user: 'Admin User',
                level: 'V8',
                expires: Date.now() + 3600000 
            });

            res.json({ verified: true, token: token });
        } else {
            res.status(400).json({ verified: false });
        }
    } catch (e) { res.status(400).json({ error: e.message }); }
});

// --- 2. EXTERNAL VERIFICATION API (The "SaaS" Feature) ---
// This is the endpoint partners call to check if a user is valid
app.post('/api/v1/external/verify', (req, res) => {
    const { token } = req.body;
    
    if (!token) return res.status(400).json({ valid: false, error: "No Token Provided" });

    const session = ActiveSessions.get(token);

    if (!session) {
        return res.json({ valid: false, error: "Invalid Token" });
    }

    if (Date.now() > session.expires) {
        ActiveSessions.delete(token);
        return res.json({ valid: false, error: "Token Expired" });
    }

    // SUCCESS: Tell the partner who this is
    res.json({
        valid: true,
        user: session.user,
        securityLevel: session.level,
        timestamp: new Date().toISOString()
    });
});

// --- STATIC FILES ---
const publicPath = path.join(__dirname, 'public');
app.use(express.static(publicPath));

app.get('/', (req, res) => res.sendFile(path.join(publicPath, 'app.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(publicPath, 'dashboard.html')));

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS ID ONLINE: ${PORT}`));
