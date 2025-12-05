/**
 * A+ CHAOS ID: V26 (HARDCODED DNA EDITION)
 * STATUS: Identity Locked. No Environment Variables needed.
 */
const express = require('express');
const path = require('path');
const cors = require('cors');
const fs = require('fs');
const crypto = require('crypto');
const { 
    generateRegistrationOptions, 
    verifyRegistrationResponse, 
    generateAuthenticationOptions, 
    verifyAuthenticationResponse 
} = require('@simplewebauthn/server');

const app = express();
const PORT = process.env.PORT || 3000;
const publicPath = path.join(__dirname, 'public');

app.use(cors({ origin: '*' })); 
app.use(express.json());
app.use(express.static(publicPath));

// ==========================================
// 1. HARDCODED ADMIN IDENTITY (YOUR DNA)
// ==========================================
const Users = new Map();

// This is the DNA you provided. It is now part of the source code.
const ADMIN_DNA = {
  "credentialID": {
    "0": 243, "1": 239, "2": 188, "3": 34, "4": 37, "5": 31, "6": 82, "7": 111, 
    "8": 222, "9": 3, "10": 159, "11": 12, "12": 230, "13": 175, "14": 238, "15": 223
  },
  "credentialPublicKey": {
    "0": 165, "1": 1, "2": 2, "3": 3, "4": 38, "5": 32, "6": 1, "7": 33, "8": 88, 
    "9": 32, "10": 221, "11": 215, "12": 24, "13": 103, "14": 135, "15": 41, 
    "16": 177, "17": 131, "18": 56, "19": 246, "20": 234, "21": 107, "22": 240, 
    "23": 63, "24": 37, "25": 48, "26": 10, "27": 187, "28": 160, "29": 9, 
    "30": 139, "31": 90, "32": 165, "33": 30, "34": 111, "35": 110, "36": 61, 
    "37": 27, "38": 72, "39": 169, "40": 152, "41": 68, "42": 34, "43": 88, 
    "44": 32, "45": 5, "46": 155, "47": 21, "48": 27, "49": 42, "50": 103, 
    "51": 140, "52": 139, "53": 43, "54": 44, "55": 155, "56": 253, "57": 147, 
    "58": 88, "59": 132, "60": 37, "61": 239, "62": 146, "63": 21, "64": 84, 
    "65": 53, "66": 248, "67": 254, "68": 86, "69": 138, "70": 152, "71": 24, 
    "72": 242, "73": 98, "74": 41, "75": 83, "76": 19
  },
  "counter": 0
};

// LOAD IT IMMEDIATELY
Users.set('admin-user', ADMIN_DNA);
console.log(">>> [SYSTEM] HARDCODED DNA LOADED. ADMIN RESTORED.");

// ==========================================
// 2. SECURITY ENGINES
// ==========================================
const Abyss = {
    partners: new Map(),
    agents: new Map(),
    hash: (key) => crypto.createHash('sha256').update(key).digest('hex'),
};
Abyss.partners.set(Abyss.hash('sk_chaos_demo123'), { company: 'Demo', plan: 'free', usage: 0, limit: 50, active: true });
Abyss.agents.set('DEMO_AGENT_V1', { id: 'DEMO_AGENT_V1', usage: 0, limit: 500 });

const Nightmare = {
    guardSaaS: (req, res, next) => {
        try {
            const rawKey = req.get('X-CHAOS-API-KEY');
            if (!rawKey) return res.status(401).json({ error: "MISSING_KEY" });
            const partner = Abyss.partners.get(Abyss.hash(rawKey));
            if (!partner) return res.status(403).json({ error: "INVALID_KEY" });
            if (partner.usage >= partner.limit) return res.status(402).json({ error: "QUOTA_EXCEEDED" });
            partner.usage++;
            req.partner = partner;
            next();
        } catch(e) { res.status(500).json({error: "SECURITY_FAIL"}); }
    }
};

const Chaos = { mintToken: () => 'tk_' + crypto.randomBytes(16).toString('hex') };
const Challenges = new Map();

// ==========================================
// 3. AUTH ROUTES
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

app.get('/api/v1/auth/register-options', async (req, res) => {
    // BLOCK NEW REGISTRATIONS SINCE DNA IS HARDCODED
    return res.status(403).json({ error: "SYSTEM LOCKED. ADMIN HARDCODED." });
});

app.post('/api/v1/auth/register-verify', async (req, res) => {
    return res.status(403).json({ error: "SYSTEM LOCKED. ADMIN HARDCODED." });
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
            Users.set(userID, user); // Update Counter in Memory
            Challenges.delete(userID);
            res.json({ verified: true, token: Chaos.mintToken() });
        } else { res.status(400).json({ verified: false }); }
    } catch (e) { res.status(400).json({ error: e.message }); }
});

// ==========================================
// 4. API & ROUTING
// ==========================================
app.post('/api/v1/external/verify', Nightmare.guardSaaS, (req, res) => {
    res.json({ valid: true, user: "Admin User", method: "LEGACY_KEY", quota: { used: req.partner.usage, limit: req.partner.limit } });
});

app.get('/api/v1/beta/pulse-demo', (req, res) => {
    const agent = Abyss.agents.get('DEMO_AGENT_V1');
    if(agent.usage >= agent.limit) return res.status(402).json({ error: "LIMIT" });
    agent.usage++;
    setTimeout(() => res.json({ valid: true, hash: 'pulse_' + Date.now(), ms: 15, quota: {used: agent.usage, limit: agent.limit} }), 200);
});

// DEBUG HELPER
const serve = (filename, res) => {
    const file = path.join(publicPath, filename);
    if (fs.existsSync(file)) res.sendFile(file);
    else res.status(404).send(`<h1>ERROR: ${filename} Not Found</h1>`);
};

app.get('/', (req, res) => serve('app.html', res));
app.get('/app', (req, res) => serve('app.html', res));
app.get('/dashboard', (req, res) => serve('dashboard.html', res));
app.get('/admin', (req, res) => serve('admin.html', res));
app.get('*', (req, res) => res.redirect('/'));

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V26 (HARDCODED) ONLINE: ${PORT}`));
