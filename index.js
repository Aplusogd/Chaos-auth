/**
 * A+ CHAOS ID: SAAS EDITION (V12)
 * Features: API Keys, Usage Tracking, Monetization Ready
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

// --- DATABASE SIMULATION ---
const Users = new Map(); 
const Challenges = new Map();
const ActiveSessions = new Map(); 

// --- PARTNER DATABASE (The Money Maker) ---
// In the future, this moves to a real database (MongoDB/Postgres)
const Partners = new Map();

// SEED DATA: Create a free key for testing
// Partner uses 'DEMO-KEY-123' in their headers
Partners.set('DEMO-KEY-123', {
    company: 'Test Corp',
    plan: 'free',
    usage: 0,
    limit: 50 // Blocks after 50 hits
});

// --- MIDDLEWARE: THE TOLL BOOTH ---
const requireApiKey = (req, res, next) => {
    // 1. Look for the API Key in headers
    const apiKey = req.get('X-CHAOS-API-KEY');

    if (!apiKey) {
        return res.status(401).json({ 
            valid: false, 
            error: "MISSING_API_KEY", 
            message: "Please purchase an API Key to verify users." 
        });
    }

    // 2. Check if Key exists
    if (!Partners.has(apiKey)) {
        return res.status(403).json({ 
            valid: false, 
            error: "INVALID_API_KEY", 
            message: "Access Denied. Unknown Partner." 
        });
    }

    // 3. Check Usage Limits (Monetization Logic)
    const partner = Partners.get(apiKey);
    
    if (partner.usage >= partner.limit) {
        return res.status(402).json({ // 402 = Payment Required
            valid: false, 
            error: "PAYMENT_REQUIRED", 
            message: `Usage limit of ${partner.limit} reached. Upgrade your plan.` 
        });
    }

    // 4. Increment Usage & Pass Partner info to request
    partner.usage++;
    req.partner = partner; // Attach partner to the request object
    next();
};

// --- CORE UTILS ---
const getOrigin = (req) => {
    const host = req.headers['x-forwarded-host'] || req.get('host');
    const proto = req.headers['x-forwarded-proto'] || 'http';
    return `${proto}://${host}`;
};

const getRpId = (req) => {
    const host = req.headers['x-forwarded-host'] || req.get('host');
    return host.split(':')[0];
};

// --- ROUTES ---

// ... (Biometric Register/Login Routes remain the same as V11) ...
// ... Copy/Paste the 'auth' routes from previous V11 code here ...
// ... I will skip them here to save space, but DO NOT DELETE THEM ...

/* ================================================================
   PASTE THE REGISTER/LOGIN LOGIC HERE FROM PREVIOUS V11 CODE
   (It is the engine that creates the Tokens)
   ================================================================
*/
// (For this example, I assume you kept the auth routes)

// --- THE MONEY ROUTE (External Verification) ---
// Now protected by 'requireApiKey'
app.post('/api/v1/external/verify', requireApiKey, (req, res) => {
    const { token } = req.body;
    
    // The 'requireApiKey' middleware already handled the billing check.
    // If we are here, the partner is paying and valid.

    if (!token) return res.status(400).json({ valid: false, error: "No Token Provided" });

    const session = ActiveSessions.get(token);

    if (!session) {
        return res.json({ valid: false, error: "Invalid Token" });
    }

    if (Date.now() > session.expires) {
        ActiveSessions.delete(token);
        return res.json({ valid: false, error: "Token Expired" });
    }

    // SUCCESS
    console.log(`[BILLING] Charged 1 credit to ${req.partner.company}. Usage: ${req.partner.usage}/${req.partner.limit}`);
    
    res.json({
        valid: true,
        user: session.user,
        verificationTier: session.level,
        partnerRemainingCredits: req.partner.limit - req.partner.usage, // Show them what they have left
        timestamp: new Date().toISOString()
    });
});

// --- NEW ROUTE: ISSUE API KEY (Admin Only) ---
app.post('/api/v1/admin/create-partner', (req, res) => {
    // In real life, protect this route with a master password!
    const { company, plan } = req.body;
    
    const newKey = "sk_live_" + crypto.randomBytes(12).toString('hex');
    const limit = plan === 'pro' ? 10000 : 50; // Pro gets 10k, Free gets 50
    
    Partners.set(newKey, { company, plan, usage: 0, limit });
    
    res.json({ company, apiKey: newKey, limit });
});

// --- STATIC FILES ---
const publicPath = path.join(__dirname, 'public');
app.use(express.static(publicPath));
app.get('/', (req, res) => res.sendFile(path.join(publicPath, 'app.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(publicPath, 'dashboard.html')));

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS SAAS ONLINE: ${PORT}`));
