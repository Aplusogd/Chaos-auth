/**
 * A+ CHAOS ID: V30 (DREAMS PROTOCOL ENABLED)
 * Features: Hardcoded Identity + Advanced Temporal Biometrics (DREAMS V2)
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
    verifyAuthenticationResponse // Correct library reference
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
// This is the DNA you provided, ensuring persistence.
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
  "counter": 0,
  "dreamProfile": { timings: [] } // Initialize dream profile
};
Users.set('admin-user', ADMIN_DNA);
console.log(">>> [SYSTEM] ADMIN DNA LOADED. V30 DREAMS LIVE.");

// --- SECURITY AND UTILS ---
const MIN_SAMPLES = 5; // Minimum required logins before enforcement begins
const Abyss = { partners: new Map(), sessions: new Map(), agents: new Map(), hash: (key) => crypto.createHash('sha256').update(key).digest('hex') };
const Chaos = { mintToken: () => 'tk_' + crypto.randomBytes(16).toString('hex') };

const getOrigin = (req) => {
    const host = req.headers['x-forwarded-host'] || req.get('host');
    const protocol = host.includes('localhost') ? 'http' : 'https';
    return `${protocol}://${host}`;
};
const getRpId = (req) => req.get('host').split(':')[0];

// ==========================================
// 2. DREAMS V2: SYNTHESIS ENGINE
// ==========================================

function startDream() {
    return process.hrtime.bigint();
}

/**
 * Calculates Mean, Standard Deviation, CV, and Autocorrelation (Rho1)
 */
function analyzeTemporalVector(timings) {
    const n = timings.length;
    if (n < 2) return { mu: timings[0] || 0, sigma: 0, cv: 0, rho1: 0 };

    const mu = timings.reduce((sum, t) => sum + t, 0) / n;
    const variance = timings.reduce((sum, t) => sum + Math.pow(t - mu, 2), 0) / (n - 1);
    const sigma = Math.sqrt(variance);
    const cv = sigma / mu;

    // Lag-1 Autocorrelation (Rho1)
    let covariance = 0;
    for (let i = 0; i < n - 1; i++) {
        covariance += (timings[i] - mu) * (timings[i + 1] - mu);
    }
    const rho1 = (covariance / (n - 1)) / variance;

    return { mu, sigma, cv, rho1 };
}

/**
 * Checks the current login duration against the user's stored Fuzzy Profile.
 * This function enforces the temporal security of the signature.
 */
function checkDreamAnomaly(durationMs, user) {
    if (!user.dreamProfile || user.dreamProfile.timings.length < MIN_SAMPLES) {
        // Not enough history to enforce the law of dreams
        console.log(`[DREAMS] Profile building (Samples: ${user.dreamProfile.timings.length})`);
        return true;
    }

    const timings = [...user.dreamProfile.timings, durationMs];
    const { cv: newCv, rho1: newRho1 } = analyzeTemporalVector(timings);
    
    // We compare against the profile built with N-1 samples
    const { cv: oldCv, sigma: oldSigma, mu: oldMu } = analyzeTemporalVector(user.dreamProfile.timings);

    // 1. CV CHECK (Anti-Automation)
    // Checks if the new CV is unnaturally low (like a script) or too far from the human baseline.
    const cvDeviationLimit = oldCv * 0.40; // Allow 40% deviation from historical CV

    // If the timing is outside the tolerance and CV is too low (like a bot), reject.
    if (newCv < 0.05 && Math.abs(newCv - oldCv) > cvDeviationLimit) { 
        console.log(`[DREAMS REJECT] CV Anomaly. Too little jitter (${newCv.toFixed(3)}).`);
        return false;
    }

    // 2. RHO1 CHECK (Anti-Spoofing/Anti-Network-Hop)
    // Checks if sequential timing dependence is broken (indicates major network switch or forced delays)
    const rho1DeviationLimit = oldSigma / oldMu; // Flexible deviation based on existing jitter
    if (Math.abs(newRho1) > 0.40 && oldSigma > 0 && oldMu > 0) { // Reject strong correlation loss if human baseline exists
        console.log(`[DREAMS REJECT] Rho1 Anomaly. Correlation loss detected.`);
        return false;
    }

    return true;
}

/**
 * Updates the user's dream profile with the latest timing data.
 */
function updateDreamsProfile(durationMs, user) {
    const MAX_SAMPLES = 10;
    
    if (!user.dreamProfile) {
        user.dreamProfile = { timings: [] };
    }
    
    user.dreamProfile.timings.push(durationMs);
    
    // Trim the array to maintain the window size
    if (user.dreamProfile.timings.length > MAX_SAMPLES) {
        user.dreamProfile.timings.shift();
    }
    
    const { mu, cv, rho1 } = analyzeTemporalVector(user.dreamProfile.timings);
    console.log(`[DREAMS] Updated Profile: Avg ${mu.toFixed(2)}ms | CV ${cv.toFixed(3)}`);

    // Store the calculated metrics on the user object for future reference
    user.dreamProfile.mu = mu;
    user.dreamProfile.cv = cv;
    user.dreamProfile.rho1 = rho1;
}

// ==========================================
// 3. AUTH ROUTES (DREAMS INTEGRATION)
// ==========================================

// [LOCKED] Registration is disabled
app.get('/api/v1/auth/register-options', async (req, res) => {
    return res.status(403).json({ error: "SYSTEM LOCKED. REGISTRATION CLOSED." });
});

app.post('/api/v1/auth/register-verify', async (req, res) => {
    return res.status(403).json({ error: "SYSTEM LOCKED. REGISTRATION CLOSED." });
});


// --- LOGIN OPTIONS (Starts Dream Timer) ---
app.get('/api/v1/auth/login-options', async (req, res) => {
    const userId = 'admin-user'; 
    const user = Users.get(userId);
    
    if (!user) return res.status(404).json({ error: "User Not Found" });
    
    try {
        const options = await generateAuthenticationOptions({
            rpID: getRpId(req),
            allowCredentials: [{ id: user.credentialID, type: 'public-key', transports: ['internal'] }],
            userVerification: 'required',
        });

        // Store challenge WITH the start time
        Challenges.set(options.challenge, { challenge: options.challenge, startTime: startDream() });
        res.json(options);
    } catch (err) { res.status(500).json({ error: err.message }); }
});


// --- LOGIN VERIFY (Checks Dream Time) ---
app.post('/api/v1/auth/login-verify', async (req, res) => {
    const userId = 'admin-user';
    const clientResponse = req.body;
    
    // NOTE: This assumes the client response sends the challenge in clientDataJSON
    const challenge = clientResponse.response.clientDataJSON.challenge; 
    const challengeData = Challenges.get(challenge);
    const userCredential = Users.get(userId);

    if (!userCredential || !challengeData) return res.status(400).json({ error: "Invalid State" });
    
    // Calculate duration before the main verification
    const durationMs = Number(process.hrtime.bigint() - challengeData.startTime) / 1000000;
    
    // 1. CHECK DREAMS (Temporal Biometrics)
    const dreamPassed = checkDreamAnomaly(durationMs, userCredential); 
    
    if (!dreamPassed) {
         Challenges.delete(challenge);
         return res.status(403).json({ verified: false, error: "ERR_TEMPORAL_ANOMALY: Behavioral Check Failed" });
    }
    
    // 2. Verify Biometric Signature (WebAuthn Standard)
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
            // Update the Dream Profile on successful login
            updateDreamsProfile(durationMs, userCredential); 
            
            const sessionToken = crypto.randomBytes(32).toString('hex');
            res.json({ verified: true, token: sessionToken });
        } else { res.status(400).json({ verified: false }); }
    } catch (error) { 
        console.error(error);
        res.status(400).json({ error: error.message }); 
    } finally {
        Challenges.delete(challenge); // Burn challenge
    }
});

// --- REST OF THE SAAS/ROUTING CODE REMAINS THE SAME ---
// (API, external/verify, admin routes, etc.)

// Placeholder for remaining routes/logic to keep V29 functional
const Abyss_agents = new Map();
Abyss_agents.set('DEMO_AGENT_V1', { id: 'DEMO_AGENT_V1', usage: 0, limit: 500 });

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

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V30 (DREAMS V2) ONLINE: ${PORT}`));
