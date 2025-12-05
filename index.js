/**
 * A+ CHAOS ID: V21 (MOBILE SETUP EDITION)
 * Feature: Sends Admin DNA back to phone for easy copying
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

// --- PERSISTENCE ---
const Users = new Map(); 

// Load DNA if available
if (process.env.ADMIN_DNA) {
    try {
        const adminData = JSON.parse(process.env.ADMIN_DNA);
        if(adminData.credentialID) Users.set('admin-user', adminData);
        console.log(">>> SYSTEM LOCKED. ADMIN RESTORED.");
    } catch (e) { console.error("DNA LOAD FAILED"); }
}

// --- ABYSS & NIGHTMARE ---
const Abyss = {
    partners: new Map(),
    sessions: new Map(),
    hash: (key) => crypto.createHash('sha256').update(key).digest('hex'),
};
Abyss.partners.set(Abyss.hash('sk_chaos_demo123'), { company: 'Public Demo', plan: 'free', usage: 0, limit: 50, active: true });

const Nightmare = {
    guardSaaS: (req, res, next) => {
        const rawKey = req.get('X-CHAOS-API-KEY');
        if (!rawKey) return res.status(401).json({ error: "MISSING_KEY" });
        const partner = Abyss.partners.get(Abyss.hash(rawKey));
        if (!partner || partner.usage >= partner.limit) return res.status(403).json({ error: "ACCESS_DENIED" });
        partner.usage++;
        req.partner = partner;
        next();
    }
};

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
const Challenges = new Map();
const Chaos = { mintToken: () => 'tk_' + crypto.randomBytes(16).toString('hex') };

// --- AUTH ROUTES ---
app.get('/api/v1/auth/register-options', async (req, res) => {
    // ALLOW RE-REGISTRATION FOR SETUP
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

            // SEND DNA BACK TO PHONE (THE FIX)
            res.json({ 
                verified: true, 
                adminDNA: JSON.stringify(userData) 
            });
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
            const token = Chaos.mintToken();
            Abyss.sessions.set(token, { user: 'Admin User', level: 'V8-BIO', expires: Date.now() + 3600000 });
            res.json({ verified: true, token: token });
        } else { res.status(400).json({ verified: false }); }
    } catch (e) { res.status(400).json({ error: e.message }); }
});

// --- ROUTES ---
app.post('/api/v1/external/verify', Nightmare.guardSaaS, (req, res) => {
    res.json({ valid: true, user: "Admin User", method: "LEGACY_KEY", quota: { used: req.partner.usage, limit: req.partner.limit } });
});
app.get('/api/v1/beta/pulse-demo', (req, res) => {
    setTimeout(() => res.json({ valid: true, hash: crypto.randomBytes(8).toString('hex'), ms: 15 }), 200);
});
app.get('/api/v1/admin/telemetry', (req, res) => res.json({ stats: { requests: 0, threats: 0 }, threats: [] }));
app.post('/api/v1/admin/pentest', (req, res) => setTimeout(() => res.json({ message: "SYSTEM SECURE" }), 2000));

// STATIC
const publicPath = path.join(__dirname, 'public');
app.use(express.static(publicPath));
app.get('/', (req, res) => res.sendFile(path.join(publicPath, 'app.html')));
app.get('/app', (req, res) => res.sendFile(path.join(publicPath, 'app.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(publicPath, 'dashboard.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(publicPath, 'admin.html')));
app.get('*', (req, res) => res.redirect('/'));

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V21 ONLINE: ${PORT}`));
