/**
 * A+ CHAOS CORE: V8 BIOMETRIC SERVER
 * STATUS: SYNCED WITH APP.HTML
 */
const express = require('express');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const { 
    generateRegistrationOptions, 
    verifyRegistrationResponse, 
    generateAuthenticationOptions, 
    verifyAuthenticationResponse 
} = require('@simplewebauthn/server');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cors());

// --- IN-MEMORY DATABASE ---
// (In a real app, these would be in a database like MongoDB/Postgres)
const Users = new Map(); 
const Challenges = new Map(); 

// --- 1. CONFIGURATION ---
const rpName = 'A+ Chaos Security';
const rpID = 'localhost'; // NOTE: On production (Render), this detects automatically below
const origin = `http://${rpID}:${PORT}`;

// Dynamic Origin Detector (For Render/Replit/Local)
const getOrigin = (req) => {
    const host = req.headers['x-forwarded-host'] || req.get('host');
    const proto = req.headers['x-forwarded-proto'] || 'http';
    return `${proto}://${host}`;
};

const getRpId = (req) => {
    const host = req.headers['x-forwarded-host'] || req.get('host');
    return host.split(':')[0];
};

// --- 2. SECURITY MIDDLEWARE ---
const Nightmare = {
    checkHeader: (req, res, next) => {
        // This matches the HEADERS const in your app.html
        const secret = req.get('X-APLUS-SECURE');
        if (req.path.startsWith('/api') && secret !== 'TOTEM_V8_BIO') {
            console.log(`[BLOCK] Header Mismatch. Received: ${secret}`);
            return res.status(403).json({ error: "ERR_SECURE_HEADER_MISSING" });
        }
        next();
    }
};

app.use(Nightmare.checkHeader);

// --- 3. BIOMETRIC ROUTES (Matching app.html) ---

// REGISTER: Step 1 (Get Options)
app.get('/api/v1/auth/register-options', async (req, res) => {
    const userID = 'admin-user'; 
    try {
        const options = await generateRegistrationOptions({
            rpName,
            rpID: getRpId(req),
            userID,
            userName: 'admin@aplus.com',
            attestationType: 'none',
            authenticatorSelection: {
                residentKey: 'preferred',
                userVerification: 'preferred',
            },
        });
        
        // Save challenge to verify later
        Challenges.set(userID, options.challenge);
        
        console.log(`[CHAOS] Register Options Sent to ${getRpId(req)}`);
        res.json(options);
    } catch (e) {
        console.error(e);
        res.status(400).json({ error: e.message });
    }
});

// REGISTER: Step 2 (Verify)
app.post('/api/v1/auth/register-verify', async (req, res) => {
    const userID = 'admin-user';
    const expectedChallenge = Challenges.get(userID);

    if (!expectedChallenge) return res.status(400).json({ error: "Challenge Expired" });

    try {
        const verification = await verifyRegistrationResponse({
            response: req.body,
            expectedChallenge,
            expectedOrigin: getOrigin(req),
            expectedRPID: getRpId(req),
        });

        if (verification.verified) {
            const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
            // Save user
            Users.set(userID, { credentialID, credentialPublicKey, counter });
            Challenges.delete(userID);
            console.log("[CHAOS] User Registered Successfully");
            res.json({ verified: true });
        } else {
            res.status(400).json({ verified: false });
        }
    } catch (e) {
        console.error(e);
        res.status(400).json({ error: e.message });
    }
});

// LOGIN: Step 1 (Get Options)
app.get('/api/v1/auth/login-options', async (req, res) => {
    const userID = 'admin-user';
    const user = Users.get(userID);

    if (!user) return res.status(404).json({ error: "User Not Found" });

    try {
        const options = await generateAuthenticationOptions({
            rpID: getRpId(req),
            allowCredentials: [{
                id: user.credentialID,
                type: 'public-key',
                transports: ['internal'],
            }],
        });

        Challenges.set(userID, options.challenge);
        res.json(options);
    } catch (e) {
        console.error(e);
        res.status(400).json({ error: e.message });
    }
});

// LOGIN: Step 2 (Verify)
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
            Users.set(userID, user); // Update counter
            Challenges.delete(userID);
            console.log("[CHAOS] Login Verified");
            res.json({ verified: true });
        } else {
            res.status(400).json({ verified: false });
        }
    } catch (e) {
        console.error(e);
        res.status(400).json({ error: e.message });
    }
});

// --- STATIC FILES ---
const publicPath = path.join(__dirname, 'public');
app.use(express.static(publicPath));

app.get('/', (req, res) => {
    // Tries to find index.html, defaults to app.html if missing
    const storefront = path.join(publicPath, 'index.html');
    if (fs.existsSync(storefront)) res.sendFile(storefront);
    else res.sendFile(path.join(publicPath, 'app.html'));
});

app.get('/app', (req, res) => {
    res.sendFile(path.join(publicPath, 'app.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n>>> A+ CHAOS V8 ONLINE: PORT ${PORT} <<<`);
});
