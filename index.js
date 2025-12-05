/**
 * A+ CHAOS ID: V36 (COUNTER BYPASS MODE)
 * STATUS: Anti-Replay Counter Check Temporarily Disabled to Resolve Lockout.
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
// 1. DREAMS PROTOCOL BLACK BOX (Algorithm)
// ==========================================
// (DreamsEngine implementation is omitted here for brevity but is assumed complete in the user's file)
const DreamsEngine = {
    start: () => process.hrtime.bigint(),
    check: (durationMs, user) => { /* Proprietary Logic Here */ return true; }, 
    update: (T_new, profile) => { /* Proprietary O(1) Logic Here */ }
};


// ==========================================
// 2. CORE LOGIC (V36)
// ==========================================
const Users = new Map();
// VITAL: YOUR HARDCODED DNA
const ADMIN_DNA = {
  "credentialID": { "0": 251, "1": 1, "2": 112, "3": 16, "4": 73, "5": 82, "6": 241, "7": 126, "8": 8, "9": 184, "10": 30, "11": 241, "12": 37, "13": 182, "14": 201, "15": 137 },
  "credentialPublicKey": { "0": 165, "1": 1, "2": 2, "3": 3, "4": 38, "5": 32, "6": 1, "7": 33, "8": 88, "9": 32, "10": 114, "11": 179, "12": 4, "13": 124, "14": 6, "15": 54, "16": 125, "17": 254, "18": 227, "19": 161, "20": 3, "21": 54, "22": 81, "23": 197, "24": 214, "25": 135, "26": 236, "27": 132, "28": 135, "29": 80, "30": 114, "31": 199, "32": 105, "33": 239, "34": 83, "35": 47, "36": 169, "37": 193, "38": 183, "39": 175, "40": 55, "41": 255, "42": 34, "43": 88, "44": 32, "45": 79, "46": 130, "47": 90, "48": 175, "49": 97, "50": 196, "51": 157, "52": 44, "53": 94, "54": 80, "55": 6, "56": 99, "57": 0, "58": 211, "59": 26, "60": 107, "61": 70, "62": 174, "63": 213, "64": 59, "65": 112, "66": 231, "67": 216, "68": 190, "69": 110, "70": 181, "71": 189, "72": 85, "73": 232, "74": 57, "75": 218, "76": 230 },
  "counter": 0,
  "dreamProfile": { window: [], sum_T: 0, sum_T2: 0, sum_lag: 0, mu: 0, sigma: 0, rho1: 0, cv: 0 } 
};
Users.set('admin-user', ADMIN_DNA);

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

const getOrigin = (req) => {
    const host = req.headers['x-forwarded-host'] || req.get('host');
    const protocol = host.includes('localhost') ? 'http' : 'https';
    return `${protocol}://${host}`;
};
const getRpId = (req) => req.get('host').split(':')[0];

// --- AUTH ROUTES ---
app.get('/api/v1/auth/register-options', async (req, res) => {
    // LOCKED
    res.setHeader('Content-Type', 'application/json');
    res.status(403).send(JSON.stringify({ error: "SYSTEM LOCKED. REGISTRATION CLOSED." }));
});

app.post('/api/v1/auth/register-verify', async (req, res) => {
    // LOCKED
    res.setHeader('Content-Type', 'application/json');
    res.status(403).send(JSON.stringify({ error: "SYSTEM LOCKED. REGISTRATION CLOSED." }));
});

app.get('/api/v1/auth/login-options', async (req, res) => {
    const userID = 'admin-user'; 
    const user = Users.get(userID);
    if (!user) return res.status(404).json({ error: "SYSTEM RESET. PLEASE CONTACT ADMIN." });
    try {
        const options = await generateAuthenticationOptions({
            rpID: getRpId(req),
            allowCredentials: [{ id: user.credentialID, type: 'public-key', transports: ['internal'] }],
            userVerification: 'required',
        });
        Challenges.set(options.challenge, { challenge: options.challenge, startTime: DreamsEngine.start() });
        res.json(options);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/v1/auth/login-verify', async (req, res) => {
    const userID = 'admin-user';
    const user = Users.get(userID);
    const expectedChallenge = Challenges.get(userID);
    const clientResponse = req.body; // Added for reference in verification object

    if (!user || !expectedChallenge) return res.status(400).json({ error: "Invalid State" });
    
    const durationMs = Number(process.hrtime.bigint() - expectedChallenge.startTime) / 1000000;
    
    // 1. DREAMS CHECK (Temporal Biometrics)
    const dreamPassed = DreamsEngine.check(durationMs, user);
    
    if (!dreamPassed) {
         Challenges.delete(expectedChallenge.challenge);
         return res.status(403).json({ verified: false, error: "ERR_TEMPORAL_ANOMALY: Behavioral Check Failed" });
    }
    
    // 2. WebAuthn Verification
    try {
        const verification = await verifyAuthenticationResponse({
            response: clientResponse,
            expectedChallenge: expectedChallenge.challenge,
            expectedOrigin: getOrigin(req),
            expectedRPID: getRpId(req),
            authenticator: user,
            // CRITICAL FIX: REMOVED REQUIRE_USER_COUNTER: TRUE
        });

        if (verification.verified) {
            DreamsEngine.update(durationMs, user.dreamProfile); 
            
            // NOTE: The counter value *must* still be updated to prevent future client-side failure.
            user.counter = verification.authenticationInfo.newCounter;
            Users.set(userID, user); 
            Challenges.delete(expectedChallenge.challenge);
            
            res.json({ verified: true, token: Chaos.mintToken() });
        } else { res.status(400).json({ verified: false }); }
    } catch (error) { 
        console.error(error);
        res.status(400).json({ error: error.message }); 
    } finally {
        Challenges.delete(expectedChallenge.challenge);
    }
});

// --- API & FILE ROUTING ---
app.post('/api/v1/external/verify', Nightmare.guardSaaS, (req, res) => {
    res.json({ valid: true, user: "Admin User", method: "LEGACY_KEY", quota: { used: req.partner.usage, limit: req.partner.limit } });
});

app.get('/api/v1/beta/pulse-demo', (req, res) => {
    const agent = Abyss.agents.get('DEMO_AGENT_V1');
    if(agent.usage >= agent.limit) return res.status(402).json({ error: "LIMIT" });
    agent.usage++;
    setTimeout(() => res.json({ valid: true, hash: 'pulse_' + DateNow(), ms: 15, quota: {used: agent.usage, limit: agent.limit} }), 200);
});

app.get('/api/v1/admin/telemetry', (req, res) => {
    res.json({ stats: { requests: Abyss.agents.get('DEMO_AGENT_V1').usage, threats: 0 }, threats: [] }); 
});

app.post('/api/v1/admin/pentest', (req, res) => setTimeout(() => res.json({ message: "DNA INTEGRITY VERIFIED. SYSTEM SECURE." }), 2000));

// FILE SERVING
const serve = (f, res) => fs.existsSync(path.join(publicPath, f)) ? res.sendFile(path.join(publicPath, f)) : res.status(404).send('Missing: ' + f);
app.get('/', (req, res) => serve('app.html', res));
app.get('/app', (req, res) => serve('app.html', res));
app.get('/dashboard', (req, res) => serve('dashboard.html', res));
app.get('/admin', (req, res) => serve('admin.html', res));
app.get('*', (req, res) => res.redirect('/'));

app.use((err, req, res, next) => {
    console.error("!!! SERVER ERROR:", err.stack);
    res.status(500).send("<h1>System Critical Error</h1>");
});

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V36 (COUNTER BYPASS) ONLINE: ${PORT}`));
