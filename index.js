/**
 * A+ CHAOS ID: V23 (DIAGNOSTIC MODE)
 * FEATURE: Prints file list on startup to find the missing dashboard.
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

// ==========================================
// 🔍 THE STARTUP SCAN (LOOK AT YOUR LOGS!)
// ==========================================
console.log("\n>>> STARTING FILE SYSTEM DIAGNOSTIC <<<");
console.log(`Target Folder: ${publicPath}`);
try {
    const files = fs.readdirSync(publicPath);
    console.log("FILES FOUND:");
    files.forEach(file => {
        console.log(` - ${file}`);
    });
    
    if (!files.includes('dashboard.html')) {
        console.error("❌ CRITICAL ERROR: 'dashboard.html' is MISSING.");
        console.error("   Did you name it 'dashbaord.html' (typo)?");
        console.error("   Is it in the root folder instead of 'public'?");
    } else {
        console.log("✅ SUCCESS: 'dashboard.html' was found.");
    }
} catch (e) {
    console.error("❌ ERROR READING PUBLIC FOLDER:", e.message);
}
console.log(">>> DIAGNOSTIC COMPLETE <<<\n");
// ==========================================

app.use(cors({ origin: '*' })); 
app.use(express.json());
app.use(express.static(publicPath));

// --- PERSISTENCE ---
const Users = new Map(); 
if (process.env.ADMIN_DNA) {
    try {
        const adminData = JSON.parse(process.env.ADMIN_DNA);
        if(adminData.credentialID) Users.set('admin-user', adminData);
        console.log(">>> ADMIN RESTORED.");
    } catch (e) { console.error("DNA LOAD FAILED"); }
}

// --- DATABASE & SECURITY ---
const Abyss = {
    partners: new Map(),
    hash: (key) => crypto.createHash('sha256').update(key).digest('hex'),
};
const demoHash = Abyss.hash('sk_chaos_demo123');
Abyss.partners.set(demoHash, { company: 'Demo', plan: 'free', usage: 0, limit: 50, active: true });

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

// --- AUTH ROUTES ---
const getOrigin = (req) => {
    const host = req.headers['x-forwarded-host'] || req.get('host');
    const proto = req.headers['x-forwarded-proto'] || 'http';
    return `${proto}://${host}`;
};
const getRpId = (req) => {
    const host = req.headers['x-forwarded-host'] || req.get('host');
    return host.split(':')[0];
};
const Challenges = new Map();
const Chaos = { mintToken: () => 'tk_' + crypto.randomBytes(16).toString('hex') };

app.get('/api/v1/auth/register-options', async (req, res) => {
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
        });
        if (verification.verified) {
            const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
            const userData = { credentialID, credentialPublicKey, counter };
            Users.set(userID, userData);
            Challenges.delete(userID);
            res.json({ verified: true, adminDNA: JSON.stringify(userData) });
        } else { res.status(400).json({ verified: false }); }
    } catch (e) { res.status(400).json({ error: e.message }); }
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
    const
