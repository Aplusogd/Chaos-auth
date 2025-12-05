/**
 * A+ CHAOS ID: V27 (UNLOCK MODE)
 * STATUS: Registration Re-Enabled to Fix Keychain Mismatch
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
// 1. HARDCODED DNA (TEMPORARY PLACEHOLDER)
// ==========================================
const Users = new Map();

// We keep this here so the code doesn't break, 
// but we will OVERWRITE it when you register again.
const ADMIN_DNA = {
  "credentialID": { "0": 243 }, // Placeholder
  "counter": 0
};
Users.set('admin-user', ADMIN_DNA);{"credentialID":{"0":62,"1":218,"2":25,"3":160,"4":215,"5":119,"6":28,"7":179,"8":69,"9":85,"10":145,"11":229,"12":142,"13":170,"14":164,"15":122},"credentialPublicKey":{"0":165,"1":1,"2":2,"3":3,"4":38,"5":32,"6":1,"7":33,"8":88,"9":32,"10":33,"11":65,"12":54,"13":230,"14":226,"15":125,"16":63,"17":85,"18":140,"19":5,"20":156,"21":122,"22":186,"23":113,"24":86,"25":174,"26":153,"27":242,"28":229,"29":205,"30":13,"31":171,"32":194,"33":139,"34":68,"35":151,"36":84,"37":166,"38":22,"39":8,"40":81,"41":97,"42":34,"43":88,"44":32,"45":65,"46":119,"47":104,"48":44,"49":64,"50":96,"51":169,"52":6,"53":132,"54":84,"55":110,"56":217,"57":178,"58":48,"59":173,"60":237,"61":102,"62":117,"63":63,"64":176,"65":129,"66":64,"67":113,"68":166,"69":204,"70":182,"71":114,"72":238,"73":53,"74":178,"75":24,"76":209},"counter":0}

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
// 3. AUTH ROUTES (UNLOCKED)
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
    // *** UNLOCK: ALLOW RE-REGISTRATION ***
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
            authenticator: { ...Users.get(userID), counter: 0 } // Reset counter for new reg
        });

        // NOTE: verifyRegistrationResponse might fail if we pass the old authenticator
        // So we might need to handle the verification loosely for the reset.
        // Actually, for a new registration, we don't pass 'authenticator' to verifyRegistrationResponse.
        // Let's re-run standard verification logic.

        const cleanVerification = await verifyRegistrationResponse({
            response: req.body,
            expectedChallenge,
            expectedOrigin: getOrigin(req),
            expectedRPID: getRpId(req)
        });

        if (cleanVerification.verified) {
            const { credentialID, credentialPublicKey, counter } = cleanVerification.registrationInfo;
            const userData = { credentialID, credentialPublicKey, counter };
            
            // OVERWRITE MEMORY
            Users.set(userID, userData);
            Challenges.delete(userID);
            
            // SEND NEW DNA
            res.json({ verified: true, adminDNA: JSON.stringify(userData) });
        } else { res.status(400).json({ verified: false }); }
    } catch (e) { 
        console.error(e);
        res.status(400).json({ error: e.message }); 
    }
});

// ... (Rest of Login/SaaS routes remain the same) ...
app.get('/api/v1/auth/login-options', async (req, res) => {
    const userID = 'admin-user';
    const user = Users.get(userID);
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
            res.json({ verified: true, token: Chaos.mintToken() });
        } else { res.status(400).json({ verified: false }); }
    } catch (e) { res.status(400).json({ error: e.message }); }
});

// ROUTING
app.post('/api/v1/external/verify', Nightmare.guardSaaS, (req, res) => res.json({ valid: true, quota: req.partner.usage }));
app.get('/api/v1/beta/pulse-demo', (req, res) => setTimeout(() => res.json({ valid: true, hash: 'pulse_' + Date.now(), ms: 10 }), 200));

// FILES
const serve = (f, res) => fs.existsSync(path.join(publicPath, f)) ? res.sendFile(path.join(publicPath, f)) : res.status(404).send('Missing: ' + f);
app.get('/', (req, res) => serve('app.html', res));
app.get('/app', (req, res) => serve('app.html', res));
app.get('/dashboard', (req, res) => serve('dashboard.html', res));
app.get('/admin', (req, res) => serve('admin.html', res));
app.get('*', (req, res) => res.redirect('/'));

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V27 UNLOCKED: ${PORT}`));
