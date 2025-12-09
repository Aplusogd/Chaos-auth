/**
 * A+ CHAOS ID: V140 (GATED ENROLLMENT)
 * STATUS: PRODUCTION.
 * SECURITY: Registration now requires MASTER_KEY to prevent unauthorized device additions.
 * FEATURE: Multi-Device Keyring.
 */
import express from 'express';
import path from 'path';
import cors from 'cors';
import fs from 'fs';
import crypto from 'crypto';
import helmet from 'helmet';
import { fileURLToPath } from 'url';
import { dirname } from 'path';     
import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
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
app.use(express.static(publicPath, { maxAge: '1h' })); 

// --- CONFIGURATION ---
// The Master Key is required to add new devices.
const MASTER_KEY = process.env.MASTER_KEY || "chaos-genesis";

// --- UTILITIES ---
const toBuffer = (base64) => Buffer.from(base64, 'base64url');
const toBase64 = (buffer) => Buffer.from(buffer).toString('base64url');
function extractChallengeFromClientResponse(clientResponse) {
    try {
        const json = Buffer.from(clientResponse.response.clientDataJSON, 'base64url').toString('utf8');
        return JSON.parse(json).challenge;
    } catch (e) { return null; }
}

const DreamsEngine = {
    start: () => process.hrtime.bigint(),
    score: (durationMs, kinetic) => 100, 
    check: (durationMs, kinetic) => true, 
    update: (T_new, profile) => {}
};

// ==========================================
// 1. CORE IDENTITY (KEYRING)
// ==========================================
const Users = new Map();
const ADMIN_USER_ID = 'admin-user';

// --- KEY #1 (DESKTOP) ---
const DESKTOP_ID = "cWtBQ3Buc1ZnN2g2QlNGRlRjVGV6QQ";
const DESKTOP_KEY = "pQECAyYgASFYIHB_wbSVKRbTQgp7v4MEHhUa-GsFUzMQV49jJ1w8OvsqIlggFwXFALOUUKlfasQOhh3rSNG3zT3jVjiJA4ITr7u5uv0";

// INIT KEYRING
const adminData = {
    id: ADMIN_USER_ID,
    credentials: [], 
    dreamProfile: { window: [], sum_T: 0, sum_T2: 0 }
};

try {
    adminData.credentials.push({
        credentialID: toBuffer(DESKTOP_ID),
        credentialID_String: DESKTOP_ID,
        credentialPublicKey: new Uint8Array(toBuffer(DESKTOP_KEY)),
        counter: 0
    });
    Users.set(ADMIN_USER_ID, adminData);
    console.log(">>> [SYSTEM] DESKTOP KEY LOADED. REGISTRATION GATED.");
} catch(e) { console.error("Key Load Error", e); }

const Abyss = { partners: new Map(), hash: (k) => crypto.createHash('sha256').update(k).digest('hex') };
const Nightmare = { guardSaaS: (req, res, next) => next() };
const Chaos = { mintToken: () => crypto.randomBytes(32).toString('hex') };
const Challenges = new Map();

const getOrigin = (req) => {
    const host = req.get('host');
    if (host && host.includes('overthere.ai')) return 'https://overthere.ai';
    return `https://${req.headers['x-forwarded-host'] || host}`;
};
const getRpId = (req) => {
    const host = req.get('host');
    if (host && host.includes('overthere.ai')) return 'overthere.ai';
    return host ? host.split(':')[0] : 'localhost';
};

// ==========================================
// 2. AUTH ROUTES (GATED)
// ==========================================

// REGISTER (REQUIRES MASTER KEY)
app.get('/api/v1/auth/register-options', async (req, res) => {
    const authHeader = req.headers['x-chaos-master-key'];
    
    // SECURITY GATE
    if (authHeader !== MASTER_KEY) {
        return res.status(403).json({ error: "ACCESS DENIED. INVALID MASTER KEY." });
    }

    try {
        const options = await generateRegistrationOptions({
            rpName: 'A+ Chaos ID', 
            rpID: getRpId(req), 
            userID: new Uint8Array(Buffer.from(ADMIN_USER_ID)), 
            userName: 'admin@aplus.com',
            attestationType: 'none', 
            authenticatorSelection: { 
                residentKey: 'required', 
                userVerification: 'preferred', 
                authenticatorAttachment: 'platform' 
            },
        });
        Challenges.set(ADMIN_USER_ID, options.challenge);
        res.json(options);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/v1/auth/register-verify', async (req, res) => {
    const authHeader = req.headers['x-chaos-master-key'];
    
    // SECURITY GATE
    if (authHeader !== MASTER_KEY) {
        return res.status(403).json({ error: "ACCESS DENIED. INVALID MASTER KEY." });
    }

    const clientResponse = req.body;
    const expectedChallenge = Challenges.get(ADMIN_USER_ID);
    if (!expectedChallenge) return res.status(400).json({ error: "Expired" });

    try {
        const verification = await verifyRegistrationResponse({ 
            response: clientResponse, 
            expectedChallenge, 
            expectedOrigin: getOrigin(req), 
            expectedRPID: getRpId(req) 
        });

        if (verification.verified) {
            const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
            const user = Users.get(ADMIN_USER_ID);
            
            // Add new key to keyring
            user.credentials.push({
                credentialID: credentialID,
                credentialID_String: toBase64(credentialID),
                credentialPublicKey: credentialPublicKey,
                counter: counter
            });
            Users.set(ADMIN_USER_ID, user);
            Challenges.delete(ADMIN_USER_ID);
            
            console.log(">>> [AUTH] NEW DEVICE AUTHORIZED VIA MASTER KEY.");
            
            // Return keys for manual backup if desired
            res.json({ 
                verified: true, 
                env_ID: toBase64(credentialID), 
                env_KEY: toBase64(credentialPublicKey) 
            });
        } else { res.status(400).json({ verified: false }); }
    } catch (e) { res.status(400).json({ error: e.message }); }
});

// LOGIN (OPEN FOR KEY HOLDERS)
app.get('/api/v1/auth/login-options', async (req, res) => {
    const user = Users.get(ADMIN_USER_ID);
    if (!user) return res.status(404).json({ error: "NO IDENTITY" });
    
    try {
        const allowed = user.credentials.map(c => ({
            id: c.credentialID, 
            type: 'public-key'
        }));

        const options = await generateAuthenticationOptions({ 
            rpID: getRpId(req), 
            allowCredentials: allowed, 
            userVerification: 'preferred' 
        });
        Challenges.set(options.challenge, { challenge: options.challenge, startTime: DreamsEngine.start() });
        res.json(options);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/v1/auth/login-verify', async (req, res) => {
    const user = Users.get(ADMIN_USER_ID);
    let challengeString;
    try {
         const json = Buffer.from(req.body.response.clientDataJSON, 'base64url').toString('utf8');
         challengeString = JSON.parse(json).challenge;
    } catch(e) { return res.status(400).json({error: "Bad Payload"}); }
    
    const challengeData = Challenges.get(challengeString); 
    if (!user || !challengeData) return res.status(400).json({ error: "Invalid State" });
    
    const credIDBuffer = toBuffer(req.body.id);
    const match = user.credentials.find(c => Buffer.compare(c.credentialID, credIDBuffer) === 0);

    if (!match) return res.status(400).json({ error: "Unknown Device" });

    try {
        const verification = await verifyAuthenticationResponse({
            response: req.body, 
            expectedChallenge: challengeString, 
            expectedOrigin: getOrigin(req), 
            expectedRPID: getRpId(req),
            authenticator: { 
                credentialID: match.credentialID, 
                credentialPublicKey: match.credentialPublicKey, 
                counter: match.counter 
            },
            requireUserVerification: false,
        });

        if (verification.verified) {
            match.counter = verification.authenticationInfo.newCounter;
            Users.set(ADMIN_USER_ID, user); 
            Challenges.delete(challengeString);
            const token = Chaos.mintToken();
            res.json({ verified: true, token: token });
        } else { res.status(400).json({ verified: false }); }
    } catch (error) { res.status(400).json({ error: error.message }); } 
});

// ROUTING
app.post('/api/v1/external/verify', Nightmare.guardSaaS, (req, res) => res.json({ valid: true }));
app.post('/api/v1/auth/reset', (req, res) => { Users.clear(); res.json({ success: true }); });
const serve = (f, res) => fs.existsSync(path.join(publicPath, f)) ? res.sendFile(path.join(publicPath, f)) : res.status(404).send('Missing: ' + f);
app.get('/', (req, res) => serve('index.html', res));
app.get('/app', (req, res) => serve('app.html', res));
app.get('/dashboard', (req, res) => serve('dashboard.html', res));
app.get('/admin', (req, res) => serve('admin.html', res));
app.get('/sdk', (req, res) => serve('sdk.html', res));
app.get('/admin/portal', (req, res) => serve('portal.html', res));
app.get('*', (req, res) => res.redirect('/'));

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V140 (GATED ENROLLMENT) ONLINE: ${PORT}`));


