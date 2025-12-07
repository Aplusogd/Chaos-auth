/**
 * A+ CHAOS ID: V82 (UNIVERSAL KEY + ORIGIN SPY)
 * STATUS: Removes credential restriction to force browser discovery.
 * DEBUG: Logs exact RP ID/Origin mismatches.
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

// --- UTILITIES ---
const toBuffer = (base64) => Buffer.from(base64, 'base64url');
const toBase64 = (buffer) => Buffer.from(buffer).toString('base64url');

const DreamsEngine = {
    start: () => process.hrtime.bigint(),
    check: () => true, 
    update: () => {}
};

// ==========================================
// 1. IDENTITY CORE
// ==========================================
const Users = new Map();
const ADMIN_USER_ID = 'admin-user';

// LOAD ENV VARS (But allow Reset)
if (process.env.ADMIN_CRED_ID && process.env.ADMIN_PUB_KEY) {
    try {
        const dna = {
            credentialID: process.env.ADMIN_CRED_ID,
            credentialPublicKey: new Uint8Array(toBuffer(process.env.ADMIN_PUB_KEY)),
            counter: 0,
            dreamProfile: { window: [], sum_T: 0, sum_T2: 0 }
        };
        Users.set(ADMIN_USER_ID, dna);
        console.log(">>> [SYSTEM] RESTORED FROM ENV.");
    } catch (e) { console.error("!!! [ERROR] BAD ENV DATA:", e); }
}

const Abyss = { partners: new Map(), hash: (k) => crypto.createHash('sha256').update(k).digest('hex') };
const Nightmare = { guardSaaS: (req, res, next) => next() };
const Chaos = { mintToken: () => crypto.randomBytes(16).toString('hex') };
const Challenges = new Map();

// --- DYNAMIC ORIGIN DEBUGGER ---
const getOrigin = (req) => {
    const host = req.headers['x-forwarded-host'] || req.get('host');
    // Force HTTPS protocol for Render
    return `https://${host}`;
};
const getRpId = (req) => req.get('host').split(':')[0];

// ==========================================
// 2. AUTH ROUTES
// ==========================================

// KILL SWITCH
app.post('/api/v1/auth/reset', (req, res) => {
    Users.clear();
    console.log(">>> [SYSTEM] MEMORY WIPED.");
    res.json({ success: true });
});

// REGISTER
app.get('/api/v1/auth/register-options', async (req, res) => {
    try {
        console.log(`[REG OPTION] RPID: ${getRpId(req)} | Origin: ${getOrigin(req)}`);
        
        const options = await generateRegistrationOptions({
            rpName: 'A+ Chaos ID',
            rpID: getRpId(req),
            userID: new Uint8Array(Buffer.from(ADMIN_USER_ID)),
            userName: 'admin@aplus.com',
            attestationType: 'none',
            authenticatorSelection: { 
                residentKey: 'required',
                userVerification: 'preferred',
            },
        });
        Challenges.set(ADMIN_USER_ID, options.challenge);
        res.json(options);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/v1/auth/register-verify', async (req, res) => {
    const clientResponse = req.body;
    const expectedChallenge = Challenges.get(ADMIN_USER_ID);
    
    // DEBUG LOG: See what the client sent
    try {
        const clientData = JSON.parse(Buffer.from(clientResponse.response.clientDataJSON, 'base64url').toString('utf8'));
        console.log(`[REG VERIFY] Client Origin: ${clientData.origin}`);
    } catch(e) { console.log("[REG VERIFY] Failed to parse clientData"); }

    if (!expectedChallenge) return res.status(400).json({ error: "Expired" });

    try {
        const verification = await verifyRegistrationResponse({
            response: clientResponse,
            expectedChallenge,
            expectedOrigin: getOrigin(req),
            expectedRPID: getRpId(req),
        });

        if (verification.verified) {
            const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
            
            const idString = toBase64(credentialID);
            const keyString = toBase64(credentialPublicKey);

            const userData = { 
                credentialID: idString, 
                credentialPublicKey: credentialPublicKey, 
                counter, 
                dreamProfile: { window: [], sum_T: 0, sum_T2: 0 } 
            };
            Users.set(ADMIN_USER_ID, userData);
            Challenges.delete(ADMIN_USER_ID);
            
            res.json({ verified: true, env_ID: idString, env_KEY: keyString });
        } else { res.status(400).json({ verified: false }); }
    } catch (e) { 
        console.error("[REG ERROR]", e.message);
        res.status(400).json({ error: e.message }); 
    }
});

// LOGIN (UNIVERSAL)
app.get('/api/v1/auth/login-options', async (req, res) => {
    const user = Users.get(ADMIN_USER_ID);
    // Note: We allow login options even if user missing, to debug the "Reset" state
    
    try {
        const options = await generateAuthenticationOptions({
            rpID: getRpId(req),
            // V82 FIX: Empty list forces browser to find ANY valid key
            allowCredentials: [], 
            userVerification: 'preferred',
        });
        Challenges.set(options.challenge, { challenge: options.challenge, startTime: process.hrtime.bigint() });
        res.json(options);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/v1/auth/login-verify', async (req, res) => {
    const user = Users.get(ADMIN_USER_ID);
    if (!user) return res.status(404).json({ error: "NO USER IN MEMORY" });

    let challengeString;
    try {
         const json = Buffer.from(req.body.response.clientDataJSON, 'base64url').toString('utf8');
         challengeString = JSON.parse(json).challenge;
         console.log(`[LOGIN VERIFY] Client Origin: ${JSON.parse(json).origin}`);
    } catch(e) { return res.status(400).json({error: "Bad Payload"}); }
    
    const expectedChallenge = Challenges.get(challengeString); 
    if (!expectedChallenge) return res.status(400).json({ error: "Invalid Challenge" });
    
    try {
        const verification = await verifyAuthenticationResponse({
            response: req.body,
            expectedChallenge: expectedChallenge.challenge,
            expectedOrigin: getOrigin(req),
            expectedRPID: getRpId(req),
            authenticator: {
                credentialID: toBuffer(user.credentialID), // Convert stored string to Buffer
                credentialPublicKey: user.credentialPublicKey,
                counter: user.counter,
            },
            requireUserVerification: false, // Loosen check for stability
        });

        if (verification.verified) {
            user.counter = verification.authenticationInfo.newCounter;
            Users.set(ADMIN_USER_ID, user); 
            Challenges.delete(expectedChallenge.challenge);
            res.json({ verified: true, token: Chaos.mintToken() });
        } else { res.status(400).json({ verified: false }); }
    } catch (error) { 
        console.error("[LOGIN ERROR]", error.message);
        res.status(400).json({ error: error.message }); 
    } 
});

// ROUTING
app.post('/api/v1/external/verify', Nightmare.guardSaaS, (req, res) => res.json({ valid: true }));
const serve = (f, res) => fs.existsSync(path.join(publicPath, f)) ? res.sendFile(path.join(publicPath, f)) : res.status(404).send('Missing: ' + f);
app.get('/', (req, res) => serve('index.html', res));
app.get('/app', (req, res) => serve('app.html', res));
app.get('/dashboard', (req, res) => serve('dashboard.html', res));
app.get('*', (req, res) => res.redirect('/'));

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V82 (UNIVERSAL) ONLINE: ${PORT}`));


