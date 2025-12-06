/**
 * A+ CHAOS ID: V55 (NUCLEAR RESET)
 * STATUS: Fresh Start. Hardcoding removed to fix "undefined" crash.
 */
import express from 'express';
import path from 'path';
import cors from 'cors';
import fs from 'fs';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { dirname } from 'path';     
import { 
    generateRegistrationOptions, 
    verifyRegistrationResponse, 
    generateAuthenticationOptions, 
    verifyAuthenticationResponse 
} from '@simplewebauthn/server';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const publicPath = path.join(__dirname, 'public');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({ origin: '*' })); 
app.use(express.json());
app.use(express.static(publicPath));

// ==========================================
// CORE STATE (FRESH)
// ==========================================
const Users = new Map(); 
const Challenges = new Map();
const Chaos = { mintToken: () => crypto.randomBytes(16).toString('hex') };

// Default Admin ID (Used for the first registration)
const ADMIN_ID = 'admin-user';

// ==========================================
// UTILS
// ==========================================
const getOrigin = (req) => {
    const host = req.headers['x-forwarded-host'] || req.get('host');
    const protocol = host.includes('localhost') ? 'http' : 'https';
    return `${protocol}://${host}`;
};
const getRpId = (req) => req.get('host').split(':')[0];

// ==========================================
// AUTH ROUTES (CLEAN)
// ==========================================

// 1. REGISTER OPTIONS
app.get('/api/v1/auth/register-options', async (req, res) => {
    try {
        console.log(`[SETUP] Generating options for RP: ${getRpId(req)}`);
        
        const options = await generateRegistrationOptions({
            rpName: 'A+ Chaos ID Core',
            rpID: getRpId(req),
            userID: new Uint8Array(Buffer.from(ADMIN_ID)),
            userName: 'admin@aplus.com',
            attestationType: 'none',
            authenticatorSelection: { 
                residentKey: 'preferred', 
                userVerification: 'preferred',
                authenticatorAttachment: 'platform' // Forces FaceID/TouchID
            },
        });

        // Save Challenge
        Challenges.set(ADMIN_ID, options.challenge);
        
        console.log("[SETUP] Options Generated Successfully.");
        res.json(options);
    } catch (err) { 
        console.error("[ERROR] Options Gen Failed:", err);
        res.status(500).json({ error: err.message }); 
    }
});

// 2. REGISTER VERIFY
app.post('/api/v1/auth/register-verify', async (req, res) => {
    const expectedChallenge = Challenges.get(ADMIN_ID);
    if (!expectedChallenge) return res.status(400).json({ error: "Challenge Expired or Missing" });

    try {
        const verification = await verifyRegistrationResponse({
            response: req.body,
            expectedChallenge,
            expectedOrigin: getOrigin(req),
            expectedRPID: getRpId(req),
        });

        if (verification.verified) {
            const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
            
            // SAVE USER
            const userData = { credentialID, credentialPublicKey, counter };
            Users.set(ADMIN_ID, userData);
            Challenges.delete(ADMIN_ID);
            
            console.log("[SETUP] Identity Secured.");
            
            // Send DNA back for backup (Optional)
            res.json({ verified: true, adminDNA: JSON.stringify(userData) });
        } else {
            res.status(400).json({ verified: false, error: "Verification Logic Failed" });
        }
    } catch (e) { 
        console.error("[ERROR] Verify Failed:", e);
        res.status(400).json({ error: e.message }); 
    }
});

// 3. LOGIN OPTIONS
app.get('/api/v1/auth/login-options', async (req, res) => {
    const user = Users.get(ADMIN_ID);
    if (!user) return res.status(404).json({ error: "NO IDENTITY FOUND. PLEASE INITIALIZE." });

    try {
        const options = await generateAuthenticationOptions({
            rpID: getRpId(req),
            allowCredentials: [], // Auto-discover
            userVerification: 'required',
        });
        Challenges.set(options.challenge, options.challenge); // Simple storage
        res.json(options);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 4. LOGIN VERIFY
app.post('/api/v1/auth/login-verify', async (req, res) => {
    const user = Users.get(ADMIN_ID);
    if (!user) return res.status(400).json({ error: "User Not Found" });

    // Extract challenge from client response
    let clientChallenge;
    try {
        const json = Buffer.from(req.body.response.clientDataJSON, 'base64url').toString('utf8');
        clientChallenge = JSON.parse(json).challenge;
    } catch(e) { return res.status(400).json({ error: "Bad Payload" }); }

    if (!Challenges.has(clientChallenge)) return res.status(400).json({ error: "Challenge Expired" });

    try {
        const verification = await verifyAuthenticationResponse({
            response: req.body,
            expectedChallenge: clientChallenge,
            expectedOrigin: getOrigin(req),
            expectedRPID: getRpId(req),
            authenticator: user, 
        });

        if (verification.verified) {
            user.counter = verification.authenticationInfo.newCounter;
            Users.set(ADMIN_ID, user);
            Challenges.delete(clientChallenge);
            res.json({ verified: true, token: Chaos.mintToken() });
        } else { res.status(400).json({ verified: false }); }
    } catch (e) { res.status(400).json({ error: e.message }); }
});

// --- ROUTES & SERVING ---
app.post('/api/v1/external/verify', (req, res) => res.json({ valid: true }));
app.get('/api/v1/admin/telemetry', (req, res) => res.json({ stats: { requests: 0 } }));

const serve = (f, res) => fs.existsSync(path.join(publicPath, f)) ? res.sendFile(path.join(publicPath, f)) : res.status(404).send('Missing: ' + f);
app.get('/', (req, res) => serve('index.html', res)); 
app.get('/app', (req, res) => serve('app.html', res)); 
app.get('/dashboard', (req, res) => serve('dashboard.html', res)); 
app.get('*', (req, res) => res.redirect('/'));

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V55 (NUCLEAR RESET) ONLINE: ${PORT}`));
