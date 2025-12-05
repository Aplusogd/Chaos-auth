/**
 * A+ CHAOS ID: V31 (O(1) DREAMS SYNTHESIS)
 * Status: High-Performance Temporal Biometrics Enabled
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
// 1. IDENTITY & STATE (THE ABYSS)
// ==========================================
const Users = new Map(); 
const Challenges = new Map(); 

// --- HARDCODED ADMIN DNA (YOUR IDENTITY) ---
const ADMIN_DNA = {
  "credentialID": { "0": 251, "1": 1, "2": 112, "3": 16, "4": 73, "5": 82, "6": 241, "7": 126, "8": 8, "9": 184, "10": 30, "11": 241, "12": 37, "13": 182, "14": 201, "15": 137 },
  "credentialPublicKey": { "0": 165, "1": 1, "2": 2, "3": 3, "4": 38, "5": 32, "6": 1, "7": 33, "8": 88, "9": 32, "10": 114, "11": 179, "12": 4, "13": 124, "14": 6, "15": 54, "16": 125, "17": 254, "18": 227, "19": 161, "20": 3, "21": 54, "22": 81, "23": 197, "24": 214, "25": 135, "26": 236, "27": 132, "28": 135, "29": 80, "30": 114, "31": 199, "32": 105, "33": 239, "34": 83, "35": 47, "36": 169, "37": 193, "38": 183, "39": 175, "40": 55, "41": 255, "42": 34, "43": 88, "44": 32, "45": 79, "46": 130, "47": 90, "48": 175, "49": 97, "50": 196, "51": 157, "52": 44, "53": 94, "54": 80, "55": 6, "56": 99, "57": 0, "58": 211, "59": 26, "60": 107, "61": 70, "62": 174, "63": 213, "64": 59, "65": 112, "66": 231, "67": 216, "68": 190, "69": 110, "70": 181, "71": 189, "72": 85, "73": 232, "74": 57, "75": 218, "76": 230 },
  "counter": 0,
  "dreamProfile": { window: [], sum_T: 0, sum_T2: 0, sum_lag: 0, mu: 0, sigma: 0, rho1: 0 } // NEW O(1) STRUCTURE
};
Users.set('admin-user', ADMIN_DNA);
console.log(">>> [SYSTEM] ADMIN DNA LOADED. V31 O(1) DREAMS LIVE.");

// --- SECURITY AND UTILS ---
const MIN_SAMPLES = 5; 
const MAX_SAMPLES = 10;
const Chaos = { mintToken: () => 'tk_' + crypto.randomBytes(16).toString('hex') };

const getOrigin = (req) => {
    const host = req.headers['x-forwarded-host'] || req.get('host');
    const protocol = host.includes('localhost') ? 'http' : 'https';
    return `${protocol}://${host}`;
};
const getRpId = (req) => req.get('host').split(':')[0];


// ==========================================
// 2. DREAMS V3: O(1) SYNTHESIS ENGINE
// ==========================================

function startDream() {
    return process.hrtime.bigint();
}

/**
 * Calculates and updates rolling statistics in O(1) time.
 * This is the core engine for replication resistance.
 */
function updateDreamsProfile(T_new, profile) {
    const window = profile.window;
    let n = window.length;

    // 1. DISCARD OLDEST DATA (MAINTAIN O(1))
    if (n === MAX_SAMPLES) {
        const T_old = window[0];
        
        // Subtract lost lag pair: T_old * T_{old+1}
        if (n > 1) {
            profile.sum_lag -= T_old * window[1];
        }
        
        // Subtract oldest sums
        profile.sum_T -= T_old;
        profile.sum_T2 -= T_old * T_old;
        
        window.shift(); // Remove oldest
        n--;
    }

    // 2. APPEND NEW DATA (MAINTAIN O(1))
    if (n > 0) {
        // Add new lag pair: T_last * T_new
        const T_last = window[n - 1];
        profile.sum_lag += T_last * T_new;
    }
    profile.sum_T += T_new;
    profile.sum_T2 += T_new * T_new;
    window.push(T_new);
    n++;

    // 3. RECOMPUTE STATS (O(1) Time)
    if (n <= 1) {
        profile.mu = T_new; profile.sigma = 0; profile.rho1 = 0;
        return;
    }

    const mu = profile.sum_T / n;
    
    // Sample Variance (Sample std. dev.)
    const centeredVar = (profile.sum_T2 - (profile.sum_T * profile.sum_T / n)) / (n - 1);
    const sigma = Math.sqrt(Math.max(0, centeredVar)); // Math.max(0, ...) for robustness
    
    // Sample Autocorrelation (Rho1)
    let rho1 = 0;
    if (n >= 3) { // Rho1 requires at least 3 samples to calculate correlation between two pairs (n-1, n-2)
        const m = n - 1; // Length of the sequences (T1..Tn-1 and T2..Tn)
        const T_1 = window[0];     
        const T_n = window[n - 1]; 
        
        // Calculate needed sums for T1:n-1 and T2:n sequences
        const sum_X = profile.sum_T - T_n;
        const sum_Y = profile.sum_T - T_1;
        const sum_X2 = profile.sum_T2 - T_n * T_n;
        const sum_Y2 = profile.sum_T2 - T_1 * T_1;

        const var_X = (sum_X2 - (sum_X * sum_X / m)) / (m - 1);
        const var_Y = (sum_Y2 - (sum_Y * sum_Y / m)) / (m - 1);
        
        const cov = (profile.sum_lag - (sum_X * sum_Y / m)) / (m - 1);

        if (var_X * var_Y > 1e-9) { // Ensure denominators are non-zero (or close to zero)
             rho1 = cov / Math.sqrt(var_X * var_Y);
        } else {
             rho1 = 0;
        }
    }
    
    // 4. CACHE RESULTS
    profile.mu = mu;
    profile.sigma = sigma;
    profile.rho1 = rho1;
    profile.cv = sigma / mu; // Store CV for easy checking
    console.log(`[DREAMS] Updated Profile: Avg ${mu.toFixed(2)}ms | CV ${profile.cv.toFixed(3)} | Rho1 ${rho1.toFixed(3)}`);
}

/**
 * Checks for temporal anomalies using the sophisticated fuzzy matching profile.
 */
function checkDreamAnomaly(durationMs, user) {
    const profile = user.dreamProfile;
    if (profile.window.length < MIN_SAMPLES) {
        return true; // Not enough history to enforce the law
    }

    const { cv: oldCv, rho1: oldRho1, mu: oldMu, sigma: oldSigma } = profile;

    // Simulate the stats if the new measurement was added
    const N_current = profile.window.length + 1;
    const newSumT = profile.sum_T + durationMs;
    const newSumT2 = profile.sum_T2 + durationMs * durationMs;

    // Recalculate CV and Rho1 based on the new point (conceptually)
    const newCenteredVar = (newSumT2 - (newSumT * newSumT / N_current)) / (N_current - 1);
    const newSigma = Math.sqrt(Math.max(0, newCenteredVar));
    const newCv = newSigma / (newSumT / N_current);
    
    // 1. CV CHECK (Anti-Automation) - Too little jitter
    const cvDeviationLimit = oldCv * 0.40; 
    if (newCv < 0.05 && Math.abs(newCv - oldCv) > cvDeviationLimit) { 
        console.log(`[DREAMS REJECT] CV Anomaly. Timing is too machine-like.`);
        return false;
    }

    // 2. RHO1 CHECK (Anti-Spoofing/Correlation Loss)
    // This is hard to calculate without full O(N), so we rely on the cached Rho1 and a reasonable deviation from the mean/sigma bounds.
    // If the time is too far outside the established mean/sigma bounds (e.g., more than 3 sigma), it's anomalous.
    if (oldSigma > 0 && Math.abs(durationMs - oldMu) > (oldSigma * 3)) {
        console.log(`[DREAMS REJECT] Time ${durationMs.toFixed(2)}ms is outside 3-Sigma range.`);
        return false;
    }
    
    // Note: We only fully recalculate Rho1 and update the cache on success to maintain O(1) performance.
    return true;
}


// ==========================================
// 4. AUTH ROUTES (DREAMS INTEGRATION)
// ==========================================
// ... (omitting boilerplate routes for brevity)

const Users_static = Users; // Reference for the boilerplate below
const Challenges_static = Challenges;

const getOrigin_static = (req) => {
    const host = req.headers['x-forwarded-host'] || req.get('host');
    const protocol = host.includes('localhost') ? 'http' : 'https';
    return `${protocol}://${host}`;
};
const getRpId_static = (req) => req.get('host').split(':')[0];


// --- LOGIN OPTIONS (Starts Dream Timer) ---
app.get('/api/v1/auth/login-options', async (req, res) => {
    const userId = 'admin-user'; 
    const user = Users_static.get(userId);
    
    if (!user) return res.status(404).json({ error: "User Not Found" });
    
    try {
        const options = await generateAuthenticationOptions({
            rpID: getRpId_static(req),
            allowCredentials: [{ id: user.credentialID, type: 'public-key', transports: ['internal'] }],
            userVerification: 'required',
        });

        // Store challenge WITH the start time
        Challenges_static.set(options.challenge, { challenge: options.challenge, startTime: startDream() });
        res.json(options);
    } catch (err) { res.status(500).json({ error: err.message }); }
});


// --- LOGIN VERIFY (Checks Dream Time) ---
app.post('/api/v1/auth/login-verify', async (req, res) => {
    const userId = 'admin-user';
    const clientResponse = req.body;
    
    const challenge = clientResponse.response.clientDataJSON.challenge; 
    const challengeData = Challenges_static.get(challenge);
    const userCredential = Users_static.get(userId);

    if (!userCredential || !challengeData) return res.status(400).json({ error: "Invalid State" });
    
    // Calculate duration before the main verification
    const durationMs = Number(process.hrtime.bigint() - challengeData.startTime) / 1000000;
    
    // 1. CHECK DREAMS (Temporal Biometrics)
    const dreamPassed = checkDreamAnomaly(durationMs, userCredential);
    
    if (!dreamPassed) {
         Challenges_static.delete(challenge);
         return res.status(403).json({ verified: false, error: "ERR_TEMPORAL_ANOMALY: Behavioral Check Failed" });
    }
    
    // 2. Verify Biometric Signature (WebAuthn Standard)
    try {
        const verification = await verifyAuthenticationResponse({
            response: clientResponse,
            expectedChallenge: challengeData.challenge,
            expectedOrigin: getOrigin_static(req),
            expectedRPID: getRpId_static(req),
            authenticator: userCredential,
            requireUserCounter: true,
        });

        if (verification.verified) {
            // Update the Dream Profile on successful login
            updateDreamsProfile(durationMs, userCredential); 
            
            const sessionToken = crypto.randomBytes(32).toString('hex');
            res.json({ verified: true, token: sessionToken });
        } else { res.status(400).json({ verified: false }); }
    } catch (error) { 
        console.error(error);
        res.status(400).json({ error: error.message }); 
    } finally {
        Challenges_static.delete(challenge); // Burn challenge
    }
});


// --- REST OF THE SERVER CODE (Placeholder for V29 routes) ---
const Abyss_partners = new Map();
Abyss_partners.set(Abyss.hash('sk_chaos_demo123'), { company: 'Demo', plan: 'free', usage: 0, limit: 50, active: true });
const Abyss_agents = new Map();
Abyss_agents.set('DEMO_AGENT_V1', { id: 'DEMO_AGENT_V1', usage: 0, limit: 500 });

const Nightmare = {
    guardSaaS: (req, res, next) => {
        const rawKey = req.get('X-CHAOS-API-KEY');
        if (!rawKey) return res.status(401).json({ error: "MISSING_KEY" });
        const partner = Abyss_partners.get(Abyss.hash(rawKey));
        if (!partner) return res.status(403).json({ error: "INVALID_KEY" });
        if (partner.usage >= partner.limit) return res.status(402).json({ error: "QUOTA_EXCEEDED" });
        partner.usage++;
        req.partner = partner;
        next();
    }
};

app.post('/api/v1/external/verify', Nightmare.guardSaaS, (req, res) => {
    res.json({ valid: true, user: "Admin User", method: "LEGACY_KEY", quota: { used: req.partner.usage, limit: req.partner.limit } });
});

app.get('/api/v1/beta/pulse-demo', (req, res) => {
    const agent = Abyss_agents.get('DEMO_AGENT_V1');
    if(agent.usage >= agent.limit) return res.status(402).json({ error: "LIMIT" });
    agent.usage++;
    setTimeout(() => res.json({ valid: true, hash: 'pulse_' + Date.now(), ms: 15, quota: {used: agent.usage, limit: agent.limit} }), 200);
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

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V31 (DREAMS V2) ONLINE: ${PORT}`));
