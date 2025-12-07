/**
 * A+ CHAOS ID: V78 (IMMORTAL CONFIG)
 * STATUS: Fixed 'replace' crash (String ID). Implemented Env Var Persistence.
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

// --- UTILITY: BASE64URL HELPERS ---
const toBuffer = (base64) => Buffer.from(base64, 'base64url');
const toBase64 = (buffer) => Buffer.from(buffer).toString('base64url');

// ==========================================
// 1. IDENTITY CORE (PERSISTENT)
// ==========================================
const Users = new Map();
const ADMIN_USER_ID = 'admin-user';

// CHECK FOR SAVED DNA IN ENVIRONMENT VARIABLES
// This survives redeployments!
if (process.env.ADMIN_CRED_ID && process.env.ADMIN_PUB_KEY) {
    try {
        console.log(">>> [SYSTEM] LOADING IDENTITY FROM ENVIRONMENT VAULT...");
        const dna = {
            // Keep ID as String (Fixes 'replace' error)
            credentialID: process.env.ADMIN_CRED_ID,
            // Convert Key to Uint8Array (Required for Crypto)
            credentialPublicKey: new Uint8Array(toBuffer(process.env.ADMIN_PUB_KEY)),
            counter: 0,
            dreamProfile: { window: [], sum_T: 0, sum_T2: 0 }
        };
        Users.set(ADMIN_USER_ID, dna);
        console.log(">>> [SYSTEM] ADMIN RESTORED. SYSTEM LOCKED.");
    } catch (e) {
        console.error("!!! [ERROR] CORRUPT ENV DATA:", e);
    }
} else {
    console.log(">>> [SYSTEM] NO DNA FOUND. REGISTRATION OPEN.");
}

const Abyss = { partners: new Map(), hash: (k) => crypto.createHash('sha256').update(k).digest('hex') };
Abyss.partners.set(Abyss.hash('sk_chaos_demo123'), { company: 'Demo', plan: 'free', usage: 0, limit: 50, active: true });
const Nightmare = { guardSaaS: (req, res, next) => next() };
const Chaos = { mintToken: () => crypto.randomBytes(16).toString('hex') };
const Challenges = new Map();

const getOrigin = (req) => `https://${req.headers['x-forwarded-host'] || req.get('host')}`;
const getRpId = (req) => req.get('host').split(':')[0];


// ==========================================
// 2. AUTH ROUTES
// ==========================================

// REGISTER
app.get('/api/v1/auth/register-options', async (req, res) => {
    // Lock if Admin exists
    if (Users.has(ADMIN_USER_ID)) {
        res.setHeader('Content-Type', 'application/json');
        return res.status(403).send(JSON.stringify({ error: "SYSTEM LOCKED. IDENTITY EXISTS." }));
    }

    try {
        const options = await generateRegistrationOptions({
            rpName: 'A+ Chaos ID',
            rpID: getRpId(req),
            userID: new Uint8Array(Buffer.from(ADMIN_USER_ID)),
            userName: 'admin@aplus.com',
            attestationType: 'none',
            authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
        });
        Challenges.set(ADMIN_USER_ID, options.challenge);
        res.json(options);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/v1/auth/register-verify', async (req, res) => {
    const clientResponse = req.body;
    const expectedChallenge = Challenges.get(ADMIN_USER_ID);

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
            
            // CONVERT TO STRINGS FOR EASY COPYING
            const idString = toBase64(credentialID);
            const keyString = toBase64(credentialPublicKey);

            const userData = { 
                credentialID: idString, // Store as String
                credentialPublicKey: credentialPublicKey, // Store as Buffer in Memory
                counter, 
                dreamProfile: { window: [], sum_T: 0, sum_T2: 0 } 
            };
            
            Users.set(ADMIN_USER_ID, userData);
            Challenges.delete(ADMIN_USER_ID);
            
            // RETURN THE STRINGS TO YOU
            res.json({ 
                verified: true, 
                env_ID: idString,
                env_KEY: keyString
            });
        } else { res.status(400).json({ verified: false }); }
    } catch (e) { res.status(400).json({ error: e.message }); }
});

// LOGIN
app.get('/api/v1/auth/login-options', async (req, res) => {
    const user = Users.get(ADMIN_USER_ID);
    if (!user) return res.status(404).json({ error: "NO IDENTITY. PLEASE REGISTER." });

    try {
        const options = await generateAuthenticationOptions({
            rpID: getRpId(req),
            allowCredentials: [{
                id: user.credentialID, // This is a String now, which is valid for Options
                type: 'public-key'
            }], 
            userVerification: 'required',
        });
        Challenges.set(options.challenge, { challenge: options.challenge, startTime: process.hrtime.bigint() });
        res.json(options);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/v1/auth/login-verify', async (req, res) => {
    const user = Users.get(ADMIN_USER_ID);
    
    // Manual Challenge Extraction
    let challengeString;
    try {
         const json = Buffer.from(req.body.response.clientDataJSON, 'base64url').toString('utf8');
         challengeString = JSON.parse(json).challenge;
    } catch(e) { return res.status(400).json({error: "Bad Payload"}); }

    const expectedChallenge = Challenges.get(challengeString); 

    if (!user || !expectedChallenge) return res.status(400).json({ error: "Invalid State" });
    
    try {
        const verification = await verifyAuthenticationResponse({
            response: req.body,
            expectedChallenge: expectedChallenge.challenge,
            expectedOrigin: getOrigin(req),
            expectedRPID: getRpId(req),
            authenticator: {
                credentialID: user.credentialID, // PASSING STRING (FIXES REPLACE ERROR)
                credentialPublicKey: user.credentialPublicKey, // PASSING BUFFER
                counter: user.counter,
            },
            requireUserVerification: true,
        });

        if (verification.verified) {
            user.counter = verification.authenticationInfo.newCounter;
            Users.set(ADMIN_USER_ID, user); 
            Challenges.delete(expectedChallenge.challenge);
            res.json({ verified: true, token: Chaos.mintToken() });
        } else { res.status(400).json({ verified: false }); }
    } catch (error) { 
        console.error("Verify Error:", error);
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

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V78 (IMMORTAL) ONLINE: ${PORT}`));


