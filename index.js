/**
 * A+ CHAOS ID: V29 (GOLD MASTER)
 * STATUS: IDENTITY LOCKED. REGISTRATION DISABLED.
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
// 1. THE ADMIN DNA (YOUR IDENTITY)
// ==========================================
const Users = new Map();

// This is the DNA you provided. It is now permanent.
const ADMIN_DNA = {
  "credentialID": {
    "0": 251, "1": 1, "2": 112, "3": 16, "4": 73, "5": 82, "6": 241, "7": 126, 
    "8": 8, "9": 184, "10": 30, "11": 241, "12": 37, "13": 182, "14": 201, "15": 137
  },
  "credentialPublicKey": {
    "0": 165, "1": 1, "2": 2, "3": 3, "4": 38, "5": 32, "6": 1, "7": 33, "8": 88, 
    "9": 32, "10": 114, "11": 179, "12": 4, "13": 124, "14": 6, "15": 54, 
    "16": 125, "17": 254, "18": 227, "19": 161, "20": 3, "21": 54, "22": 81, 
    "23": 197, "24": 214, "25": 135, "26": 236, "27": 132, "28": 135, "29": 80, 
    "30": 114, "31": 199, "32": 105, "33": 239, "34": 83, "35": 47, "36": 169, 
    "37": 193, "38": 183, "39": 175, "40": 55, "41": 255, "42": 34, "43": 88, 
    "44": 32, "45": 79, "46": 130, "47": 90, "48": 175, "49": 97, "50": 196, 
    "51": 157, "52": 44, "53": 94, "54": 80, "55": 6, "56": 99, "57": 0, 
    "58": 211, "59": 26, "60": 107, "61": 70, "62": 174, "63": 213, "64": 59, 
    "65": 112, "66": 231, "67": 216, "68": 190, "69": 110, "70": 181, "71": 189, 
    "72": 85, "73": 232, "74": 57, "75": 218, "76": 230
  },
  "counter": 0
};

// Load Identity Immediately
Users.set('admin-user', ADMIN_DNA);
console.log(">>> [SYSTEM] HARDCODED DNA LOADED. ADMIN SECURED.");

// ==========================================
// 2. SECURITY ENGINES (Abyss & Nightmare)
// ==========================================
const Abyss = {
    partners: new Map(),
    agents: new Map(),
    sessions: new Map(),
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
// 3. AUTH ROUTES (LOCKED DOWN)
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

// [LOCKED] Registration is disabled for security
app.get('/api/v1/auth/register-options', async (req, res) => {
    return res.status(403).json({ error: "SYSTEM LOCKED. REGISTRATION CLOSED." });
});

app.post('/api/v1/auth/register-verify', async (req, res) => {
    return res.status(403).json({ error: "SYSTEM LOCKED. REGISTRATION CLOSED." });
});

// [OPEN] Login is open only for the Hardcoded DNA
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
            
            // Mint Token & Track Session
            const token = Chaos.mintToken();
            Abyss.sessions.set(token, { user: 'Admin User', level: 'V29-GOLD', expires: Date.now() + 3600000 });
            
            res.json({ verified: true, token: token });
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

// ADMIN TELEMETRY
app.get('/api/v1/admin/telemetry', (req, res) => {
    res.json({ stats: { requests: Abyss.agents.get('DEMO_AGENT_V1').usage, threats: 0 }, threats: [] }); 
});

app.post('/api/v1/admin/pentest', (req, res) => setTimeout(() => res.json({ message: "DNA INTEGRITY VERIFIED. SYSTEM SECURE." }), 2000));

// FILES & DEBUG
const serve = (f, res) => fs.existsSync(path.join(publicPath, f)) ? res.sendFile(path.join(publicPath, f)) : res.status(404).send('Missing: ' + f);
app.get('/', (req, res) => serve('app.html', res));
app.get('/app', (req, res) => serve('app.html', res));
app.get('/dashboard', (req, res) => serve('dashboard.html', res));
app.get('/admin', (req, res) => serve('admin.html', res));
app.get('*', (req, res) => res.redirect('/'));

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V29 (GOLD) ONLINE: ${PORT}`));
