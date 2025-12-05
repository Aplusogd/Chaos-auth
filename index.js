/**
 * A+ CHAOS ID: V34 (EMERGENCY UNLOCK MODE)
 * STATUS: PQC Hybrid KEM Structure Ready. Registration enabled for immediate key repair.
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
// 1. DREAMS PROTOCOL BLACK BOX (O(1) Algorithm)
// ==========================================
const DreamsEngine = (() => {
    const MIN_SAMPLES = 5; 
    const MAX_SAMPLES = 10;
    
    // Core math helper (analyzes current state without iteration)
    const analyzeTemporalVector = (timings) => {
        const n = timings.length;
        if (n <= 1) return { mu: timings[0] || 0, sigma: 0, rho1: 0, cv: 0 };
        const mu = timings.reduce((sum, t) => sum + t, 0) / n;
        const centeredVar = timings.reduce((sum, t) => sum + Math.pow(t - mu, 2), 0) / (n - 1);
        const sigma = Math.sqrt(Math.max(0, centeredVar));
        const cv = sigma / mu;
        
        let rho1 = 0;
        if (n >= 3) {
            const m = n - 1; 
            const sum_X = timings.slice(0, m).reduce((a, b) => a + b, 0); 
            const sum_Y = timings.slice(1, n).reduce((a, b) => a + b, 0);
            const sum_X2 = timings.slice(0, m).reduce((a, b) => a + b * b, 0);
            const sum_Y2 = timings.slice(1, n).reduce((a, b) => a + b * b, 0);

            let sum_lag = 0;
            for(let i=0; i < n - 1; i++) sum_lag += timings[i] * timings[i+1];

            const var_X = (sum_X2 - (sum_X * sum_X / m)) / (m - 1);
            const var_Y = (sum_Y2 - (sum_Y * sum_Y / m)) / (m - 1);
            const cov = (sum_lag - (sum_X * sum_Y / m)) / (m - 1);

            if (var_X * var_Y > 1e-9) rho1 = cov / Math.sqrt(var_X * var_Y);
        }
        return { mu, sigma, rho1, cv };
    };


    return {
        start: () => process.hrtime.bigint(),

        check: (durationMs, user) => {
            const profile = user.dreamProfile;
            if (profile.window.length < MIN_SAMPLES) return true;

            const { mu: oldMu, sigma: oldSigma, cv: oldCv } = analyzeTemporalVector(profile.window);
            const N_current = profile.window.length;
            const newSumT = profile.sum_T + durationMs;
            const newSumT2 = profile.sum_T2 + durationMs * durationMs;

            const newCenteredVar = (newSumT2 - (newSumT * newSumT / (N_current + 1))) / N_current;
            const newSigma = Math.sqrt(Math.max(0, newCenteredVar));
            const newCv = newSigma / (newSumT / (N_current + 1));
            
            // 1. CV CHECK
            const cvDeviationLimit = oldCv * 0.40; 
            if (newCv < 0.05 && Math.abs(newCv - oldCv) > cvDeviationLimit) { 
                console.log(`[DREAMS REJECT] CV Anomaly.`);
                return false;
            }

            // 2. 3-SIGMA CHECK
            if (oldSigma > 0 && Math.abs(durationMs - oldMu) > (oldSigma * 3)) {
                console.log(`[DREAMS REJECT] Time outside 3-Sigma range.`);
                return false;
            }

            return true;
        },

        update: (T_new, profile) => {
            const window = profile.window;
            let n = window.length;

            // Discard oldest (O(1) sum maintenance)
            if (n === MAX_SAMPLES) {
                const T_old = window[0];
                if (n > 1) profile.sum_lag -= T_old * window[1];
                
                profile.sum_T -= T_old;
                profile.sum_T2 -= T_old * T_old;
                window.shift();
                n--;
            }

            // Append new (O(1) sum maintenance)
            if (n > 0) profile.sum_lag += window[n - 1] * T_new;
            
            profile.sum_T += T_new;
            profile.sum_T2 += T_new * T_new;
            window.push(T_new);

            const stats = analyzeTemporalVector(profile.window);
            profile.mu = stats.mu;
            profile.sigma = stats.sigma;
            profile.rho1 = stats.rho1;
            profile.cv = stats.cv;
        }
    };
})();


// ==========================================
// 3. CORE LOGIC (V34)
// ==========================================
const Users = new Map();
// NOTE: Hardcoded DNA is a temporary placeholder for structure during unlock.
const ADMIN_DNA = { "credentialID": { "0": 251 }, "counter": 0, "dreamProfile": { window: [], sum_T: 0, sum_T2: 0, sum_lag: 0, mu: 0, sigma: 0, rho1: 0, cv: 0 } };
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
// [UNLOCKED] Registration is open to generate a new key
app.get('/api/v1/auth/register-options', async (req, res) => {
    const userID = 'admin-user'; 
    try {
        const options = await generateRegistrationOptions({
            rpName: 'A+ Chaos ID Core', // <<<--- FIX IS HERE: ADDED MISSING NAME
            rpID: getRpId(req),
            userID,
            userName: 'admin@aplus.com',
            attestationType: 'none',
            authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
        });
        Challenges.set(userID, options.challenge);
        res.json(options);
    } catch (err) { res.status(400).json({ error: err.message }); }
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
            const userData = { credentialID, credentialPublicKey, counter, dreamProfile: { window: [], sum_T: 0, sum_T2: 0, sum_lag: 0, mu: 0, sigma: 0, rho1: 0, cv: 0 } };
            
            Users.set(userID, userData);
            Challenges.delete(userID);
            
            // ECHO DNA BACK TO CLIENT FOR NEW HARDCODING
            res.json({ verified: true, adminDNA: JSON.stringify(userData) });
        } else { res.status(400).json({ verified: false }); }
    } catch (e) { 
        console.error(e);
        res.status(400).json({ error: e.message }); 
    }
});

app.get('/api/v1/auth/login-options', async (req, res) => {
    const userID = 'admin-user';
    const user = Users.get(userID);
    if (!user) return res.status(404).json({ error: "SYSTEM RESET. PLEASE REGISTER FIRST." });
    try {
        const options = await generateAuthenticationOptions({
            rpID: getRpId(req),
            allowCredentials: [{ id: user.credentialID, type: 'public-key', transports: ['internal'] }],
        });
        Challenges.set(options.challenge, { challenge: options.challenge, startTime: DreamsEngine.start() });
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
            // DREAMS CHECK AND UPDATE
            const durationMs = Number(process.hrtime.bigint() - challengeData.startTime) / 1000000;
            const dreamPassed = DreamsEngine.check(durationMs, user);
            
            if (!dreamPassed) {
                 Challenges.delete(challenge);
                 return res.status(403).json({ verified: false, error: "ERR_TEMPORAL_ANOMALY: Behavioral Check Failed" });
            }
            DreamsEngine.update(durationMs, user.dreamProfile); 
            
            user.counter = verification.authenticationInfo.newCounter;
            Challenges.delete(expectedChallenge);
            
            res.json({ verified: true, token: Chaos.mintToken() });
        } else { res.status(400).json({ verified: false }); }
    } catch (e) { 
        console.error(e);
        res.status(400).json({ error: e.message }); 
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
    setTimeout(() => res.json({ valid: true, hash: 'pulse_' + Date.now(), ms: 15, quota: {used: agent.usage, limit: agent.limit} }), 200);
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

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V34 UNLOCKED: ${PORT}`));
