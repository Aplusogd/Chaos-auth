/**
 * A+ CHAOS ID: V32 (DREAMS BLACKBOX EDITION)
 * STATUS: O(1) Temporal Biometrics Enabled + Algorithm Encapsulation
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
// 1. DREAMS PROTOCOL BLACK BOX (ALGORITHM)
// ==========================================
// Encapsulates all O(1) rolling math logic.

const DreamsEngine = (() => {
    const MIN_SAMPLES = 5; 
    const MAX_SAMPLES = 10;
    
    // Core math helper
    const analyzeVector = (profile) => {
        const { window, sum_T, sum_T2, sum_lag } = profile;
        const n = window.length;

        if (n <= 1) return { mu: sum_T || 0, sigma: 0, rho1: 0, cv: 0 };
        
        const mu = sum_T / n;
        const centeredVar = (sum_T2 - (sum_T * sum_T / n)) / (n - 1);
        const sigma = Math.sqrt(Math.max(0, centeredVar));
        const cv = sigma / mu;
        
        let rho1 = 0;
        if (n >= 3) {
            const m = n - 1; 
            const T_1 = window[0];     
            const T_n = window[n - 1]; 
            const sum_X = sum_T - T_n;
            const sum_Y = sum_T - T_1;
            const sum_X2 = sum_T2 - T_n * T_n;
            const sum_Y2 = sum_T2 - T_1 * T_1;

            const var_X = (sum_X2 - (sum_X * sum_X / m)) / (m - 1);
            const var_Y = (sum_Y2 - (sum_Y * sum_Y / m)) / (m - 1);
            const cov = (sum_lag - (sum_X * sum_Y / m)) / (m - 1);

            if (var_X * var_Y > 1e-9) rho1 = cov / Math.sqrt(var_X * var_Y);
        }

        return { mu, sigma, rho1, cv };
    };

    return {
        // Step 1: Start Timer
        start: () => process.hrtime.bigint(),

        // Step 2: Check for Anomalies (The Gate)
        check: (durationMs, user) => {
            const profile = user.dreamProfile;
            if (profile.window.length < MIN_SAMPLES) {
                return true; 
            }

            const { cv: oldCv, mu: oldMu, sigma: oldSigma } = analyzeTemporalVector(profile.window);

            // Calculate hypothetical new stats for check
            const N_current = profile.window.length;
            const newSumT = profile.sum_T + durationMs;
            const newSumT2 = profile.sumT2 + durationMs * durationMs;

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

        // Step 3: Update Profile (O(1) Rolling Stats)
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
// 3. CORE LOGIC (Rest of the Server)
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
            if (!partner || partner.usage >= partner.limit) return res.status(403).json({ error: "ACCESS_DENIED" });
            partner.usage++;
            req.partner = partner;
            next();
        } catch(e) { res.status(500).json({error: "SECURITY_FAIL"}); }
    }
};

const Users = new Map();
const ADMIN_DNA = {
  "credentialID": { "0": 251, "1": 1, "2": 112, "3": 16, "4": 73, "5": 82, "6": 241, "7": 126, "8": 8, "9": 184, "10": 30, "11": 241, "12": 37, "13": 182, "14": 201, "15": 137 },
  "credentialPublicKey": { "0": 165, "1": 1, "2": 2, "3": 3, "4": 38, "5": 32, "6": 1, "7": 33, "8": 88, "9": 32, "10": 114, "11": 179, "12": 4, "13": 124, "14": 6, "15": 54, "16": 125, "17": 254, "18": 227, "19": 161, "20": 3, "21": 54, "22": 81, "23": 197, "24": 214, "25": 135, "26": 236, "27": 132, "28": 135, "29": 80, "30": 114, "31": 199, "32": 105, "33": 239, "34": 83, "35": 47, "36": 169, "37": 193, "38": 183, "39": 175, "40": 55, "41": 255, "42": 34, "43": 88, "44": 32, "45": 79, "46": 130, "47": 90, "48": 175, "49": 97, "50": 196, "51": 157, "52": 44, "53": 94, "54": 80, "55": 6, "56": 99, "57": 0, "58": 211, "59": 26, "60": 107, "61": 70, "62": 174, "63": 213, "64": 59, "65": 112, "66": 231, "67": 216, "68": 190, "69": 110, "70": 181, "71": 189, "72": 85, "73": 232, "74": 57, "75": 218, "76": 230 },
  "counter": 0,
  "dreamProfile": { window: [], sum_T: 0, sum_T2: 0, sum_lag: 0, mu: 0, sigma: 0, rho1: 0, cv: 0 } 
};
Users.set('admin-user', ADMIN_DNA);

const Challenges = new Map();
const Chaos = { mintToken: () => 'tk_' + crypto.randomBytes(16).toString('hex') };

const getOrigin = (req) => {
    const host = req.headers['x-forwarded-host'] || req.get('host');
    const protocol = host.includes('localhost') ? 'http' : 'https';
    return `${protocol}://${host}`;
};
const getRpId = (req) => req.get('host').split(':')[0];


// --- AUTH ROUTES (Cleaned up) ---
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
            // Update DREAMS Profile (O(1) Time)
            DreamsEngine.update(durationMs, userCredential.dreamProfile); 
            
            userCredential.counter = verification.authenticationInfo.newCounter; // Update Auth Counter
            
            res.json({ verified: true, token: Chaos.mintToken() });
        } else { res.status(400).json({ verified: false }); }
    } catch (error) { 
        console.error(error);
        res.status(400).json({ error: error.message }); 
    } finally {
        Challenges.delete(challenge);
    }
});


// --- FINAL ROUTING ---
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
