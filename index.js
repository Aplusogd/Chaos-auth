/**
 * A+ CHAOS ID: V33 (GOLD MASTER)
 * STATUS: O(1) DREAMS PROTOCOL + Hardened Security Framework
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
// 1. DREAMS PROTOCOL BLACK BOX (Algorithm Protected)
// ==========================================
// The proprietary logic for temporal biometric analysis.
const DreamsEngine = (() => {
    const MIN_SAMPLES = 5; 
    const MAX_SAMPLES = 10;
    
    // Core math helper (O(N) for analysis, but only called once during update)
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
            const T_n = timings[n - 1]; 
            const sum_X = timings.slice(0, m).reduce((a, b) => a + b, 0); 
            const sum_Y = timings.slice(1, n).reduce((a, b) => a + b, 0);
            const sum_X2 = timings.slice(0, m).reduce((a, b) => a + b * b, 0);
            const sum_Y2 = timings.slice(1, n).reduce((a, b) => a + b * b, 0);

            const var_X = (sum_X2 - (sum_X * sum_X / m)) / (m - 1);
            const var_Y = (sum_Y2 - (sum_Y * sum_Y / m)) / (m - 1);
            
            let sum_lag = 0;
            for(let i=0; i < n - 1; i++) sum_lag += timings[i] * timings[i+1];

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

            // Calculate hypothetical new stats for check
            const N_current = profile.window.length;
            const newSumT = profile.sum_T + durationMs;
            const newSumT2 = profile.sum_T2 + durationMs * durationMs;

            const newCenteredVar = (newSumT2 - (newSumT * newSumT / (N_current + 1))) / N_current;
            const newSigma = Math.sqrt(Math.max(0, newCenteredVar));
            const newCv = newSigma / (newSumT / (N_current + 1));
            
            // 1. CV CHECK (Anti-Automation)
            const cvDeviationLimit = oldCv * 0.40; 
            if (newCv < 0.05 && Math.abs(newCv - oldCv) > cvDeviationLimit) { 
                console.log(`[DREAMS REJECT] CV Anomaly. Too machine-like.`);
                return false;
            }

            // 2. 3-SIGMA CHECK (Anti-Spoofing/Extreme Jitter)
            if (oldSigma > 0 && Math.abs(durationMs - oldMu) > (oldSigma * 3)) {
                console.log(`[DREAMS REJECT] Time outside 3-Sigma range.`);
                return false;
            }

            return true;
        },

        update: (T_new, profile) => {
            const window = profile.window;
            let n = window.length;

            // Discard oldest
            if (n === MAX_SAMPLES) {
                const T_old = window[0];
                if (n > 1) profile.sum_lag -= T_old * window[1];
                
                profile.sum_T -= T_old;
                profile.sum_T2 -= T_old * T_old;
                window.shift();
                n--;
            }

            // Append new
            if (n > 0) profile.sum_lag += window[n - 1] * T_new;
            
            profile.sum_T += T_new;
            profile.sum_T2 += T_new * T_new;
            window.push(T_new);

            // Recalculate and cache all scalar stats
            const stats = analyzeTemporalVector(profile.window);
            profile.mu = stats.mu;
            profile.sigma = stats.sigma;
            profile.rho1 = stats.rho1;
            profile.cv = stats.cv;
        }
    };
})();


// ==========================================
// 4. CORE LOGIC & SECURITY ENGINES
// ==========================================
const Users = new Map();
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
    return res.status(403).json({ error: "SYSTEM LOCKED. REGISTRATION CLOSED." });
});
app.post('/api/v1/auth/register-verify', async (req, res) => {
    return res.status(403).json({ error: "SYSTEM LOCKED. REGISTRATION CLOSED." });
});

app.get('/api/v1/auth/login-options', async (req, res) => {
    const userID = 'admin-user'; 
    const user = Users.get(userID);
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
    const clientResponse = req.body;
    const challenge = clientResponse.response.clientDataJSON.challenge; 
    const challengeData = Challenges.get(challenge);
    const userCredential = Users.get(userID);

    if (!userCredential || !challengeData) return res.status(400).json({ error: "Invalid State" });
    
    // Calculate duration
    const durationMs = Number(process.hrtime.bigint() - challengeData.startTime) / 1000000;
    
    // 1. DREAMS CHECK (Temporal Biometrics)
    const dreamPassed = DreamsEngine.check(durationMs, userCredential);
    
    if (!dreamPassed) {
         Challenges.delete(challenge);
         return res.status(403).json({ verified: false, error: "ERR_TEMPORAL_ANOMALY: Behavioral Check Failed" });
    }
    
    // 2. WebAuthn Verification
    try {
        const verification = await verifyAuthenticationResponse({
            response: clientResponse,
            expectedChallenge: challengeData.challenge,
            expectedOrigin: getOrigin(req),
            expectedRPID: getRpId(req),
            authenticator: userCredential,
            requireUserCounter: true,
        });

        if (verification.verified) {
            // Update DREAMS Profile (O(1) Rolling Stats)
            DreamsEngine.update(durationMs, userCredential.dreamProfile); 
            
            userCredential.counter = verification.authenticationInfo.newCounter; // Update Auth Counter
            
            // Mint Token & Track Session
            const token = Chaos.mintToken();
            Abyss.sessions.set(token, { user: 'Admin User', level: 'V32-GOLD', expires: Date.now() + 3600000 });
            
            res.json({ verified: true, token: token });
        } else { res.status(400).json({ verified: false }); }
    } catch (error) { 
        console.error(error);
        res.status(400).json({ error: error.message }); 
    } finally {
        Challenges.delete(challenge);
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

// Admin Telemetry (Placeholder)
app.get('/api/v1/admin/telemetry', (req, res) => {
    res.json({ stats: { requests: Abyss.agents.get('DEMO_AGENT_V1').usage, threats: 0 }, threats: [] }); 
});

// FILE SERVER
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

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V32 (DREAMS BLACKBOX) ONLINE: ${PORT}`));
