/**
 * A+ CHAOS ID: V144.2 (TYPE-SAFE BUNDLE)
 * STATUS: PRODUCTION
 * FIX: Solves 'isBase64URL' crash by forcing String format for IDs.
 */
import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import helmet from 'helmet';
import { 
    generateRegistrationOptions, 
    verifyRegistrationResponse, 
    generateAuthenticationOptions, 
    verifyAuthenticationResponse 
} from '@simplewebauthn/server';

// --- ZOMBIE MODE (Anti-Crash) ---
process.on('uncaughtException', (err) => console.error('>>> CRITICAL:', err));
process.on('unhandledRejection', (r) => console.error('>>> REJECT:', r));

const app = express();
const PORT = process.env.PORT || 3000;
const MASTER_KEY = process.env.MASTER_KEY || "chaos-genesis";

// --- UTILS ---
const toBuffer = (base64) => { 
    try { return Buffer.from(base64, 'base64url'); } 
    catch (e) { return Buffer.alloc(0); } 
};
const toBase64 = (buffer) => {
    if (typeof buffer === 'string') return buffer; // Already string
    return Buffer.from(buffer).toString('base64url');
};

// --- IDENTITY STORE ---
const Users = new Map();
const ADMIN_USER_ID = 'admin-user';
const Challenges = new Map();
const Sessions = new Map();

// YOUR HARDCODED ID (PHONE)
const PERMANENT_ID = "cWtBQ3Buc1ZnN2g2QlNGRlRjVGV6QQ";
const PERMANENT_KEY = "pQECAyYgASFYIHB_wbSVKRbTQgp7v4MEHhUa-GsFUzMQV49jJ1w8OvsqIlggFwXFALOUUKlfasQOhh3rSNG3zT3jVjiJA4ITr7u5uv0";

try {
    Users.set(ADMIN_USER_ID, {
        id: ADMIN_USER_ID,
        credentials: [{ credentialID: toBuffer(PERMANENT_ID), credentialPublicKey: toBuffer(PERMANENT_KEY), counter: 0 }]
    });
    console.log(">>> [SYSTEM] IDENTITY LOADED.");
} catch (e) { console.log(">>> [WARN] EMPTY START."); Users.set(ADMIN_USER_ID, { id: ADMIN_USER_ID, credentials: [] }); }

let REGISTRATION_LOCKED = true;
let GATE_UNLOCK_TIMER = null;

// --- MIDDLEWARE ---
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*' })); 
app.use(express.json());

// --- LIVE WIRE ---
let connectedClients = [];
const LiveWire = {
    broadcast: (event, data) => { try { connectedClients.forEach(c => c.res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)); } catch(e){} },
    addClient: (req, res) => { res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive' }); connectedClients.push({ id: Date.now(), res }); }
};

// ==========================================
// CLIENT SOURCE CODE (EMBEDDED)
// ==========================================
const HTML_CLIENT = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>A+ CHAOS v144.2</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/@simplewebauthn/browser@10.0.0/dist/bundle/index.umd.min.js"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;800&display=swap');
        body { background-color: #000; color: #00ff41; font-family: 'JetBrains Mono', monospace; touch-action: none; overflow: hidden; user-select: none; }
        .hud-status { font-size: 1.8rem; font-weight: 800; text-align: center; margin-top: 20vh; text-shadow: 0 0 15px #00ff41; pointer-events: none; }
        .totem { width: 90px; height: 90px; background: #00ff41; border-radius: 50%; position: absolute; bottom: 130px; left: 50%; transform: translateX(-50%); display: flex; align-items: center; justify-content: center; font-size: 36px; color: #002200; box-shadow: 0 0 25px #00ff41; transition: all 0.5s; z-index: 50; cursor: pointer; }
        .totem.offline { filter: grayscale(100%); opacity: 0.3; }
        .totem.imprint { background: #0088ff; box-shadow: 0 0 25px #0088ff; color: #001133; }
        #error-toast { position: fixed; top: 0; left: 0; width: 100%; background: #aa0000; color: white; padding: 5px; font-size: 10px; text-align: center; display: none; z-index: 9999; }
    </style>
</head>
<body class="h-screen w-screen bg-black">
    <div id="error-toast"></div>
    <div id="hud" class="hud-status text-yellow-500">CONNECTING...</div>
    <div class="totem offline" id="totem"><i class="fas fa-fingerprint"></i></div>
    
    <div id="hidden-trigger" style="position:fixed;top:0;left:50%;width:100px;height:50px;transform:translateX(-50%);z-index:100;"></div>

    <script>
        const { startRegistration, startAuthentication } = SimpleWebAuthnBrowser;
        const API_BASE = '/api/v1';
        let mode = 'LOGIN';
        
        const log = (txt) => { document.getElementById('error-toast').style.display='block'; document.getElementById('error-toast').innerText = txt; setTimeout(()=>document.getElementById('error-toast').style.display='none', 5000); };

        async function init() {
            try {
                const health = await fetch(API_BASE + '/health');
                if(!health.ok) throw new Error("Sleep");
                
                const resp = await fetch(API_BASE + '/auth/login-options');
                if(resp.ok) {
                    mode = 'LOGIN';
                    document.getElementById('hud').innerText = "CAST TOTEM";
                    document.getElementById('hud').className = "hud-status text-green-500";
                    document.getElementById('totem').classList.remove('offline', 'imprint');
                } else {
                    mode = 'REGISTER';
                    document.getElementById('hud').innerText = "IMPRINT IDENTITY";
                    document.getElementById('hud').className = "hud-status text-blue-500";
                    document.getElementById('totem').classList.add('imprint');
                    document.getElementById('totem').classList.remove('offline');
                }
            } catch(e) {
                document.getElementById('hud').innerText = "WAKING SERVER...";
                setTimeout(init, 2000);
            }
        }
        
        document.getElementById('totem').addEventListener('click', async () => {
            const t = document.getElementById('totem');
            if(t.classList.contains('offline')) return;
            document.getElementById('hud').innerText = "PROCESSING...";
            
            try {
                if(mode === 'LOGIN') {
                    const opts = await (await fetch(API_BASE + '/auth/login-options')).json();
                    if(opts.error) throw new Error(opts.error);
                    
                    const asseResp = await startAuthentication(opts);
                    const ver = await fetch(API_BASE + '/auth/login-verify', {
                        method: 'POST', headers: {'Content-Type':'application/json'},
                        body: JSON.stringify({...asseResp, kinetic_data: { velocity: 10, entropy: 1.0 }})
                    });
                    const res = await ver.json();
                    if(res.verified) {
                        document.getElementById('hud').innerText = "ACCEPTED";
                        sessionStorage.setItem('chaos_session', res.token);
                        setTimeout(() => location.href = '/dashboard', 1000);
                    } else throw new Error(res.error || "Denied");
                } else {
                    const key = prompt("MASTER KEY:");
                    const opts = await (await fetch(API_BASE + '/auth/register-options', {headers:{'x-chaos-master-key': key}})).json();
                    if(opts.error) throw new Error(opts.error);
                    
                    const attResp = await startRegistration(opts);
                    const ver = await fetch(API_BASE + '/auth/register-verify', {
                        method: 'POST', headers: {'Content-Type':'application/json', 'x-chaos-master-key': key},
                        body: JSON.stringify(attResp)
                    });
                    if((await ver.json()).verified) location.reload(); else throw new Error("Reg Failed");
                }
            } catch(e) {
                log(e.message);
                document.getElementById('hud').innerText = "FAILED";
                setTimeout(init, 2000);
            }
        });
        
        let taps = 0;
        document.getElementById('hidden-trigger').addEventListener('click', () => {
            taps++;
            if(taps===3) { mode='REGISTER'; document.getElementById('hud').innerText="FORCE ADD"; document.getElementById('totem').classList.add('imprint'); taps=0; }
        });
        init();
    </script>
</body>
</html>
`;

// ==========================================
// ROUTES
// ==========================================

// *** SERVE APP.HTML FROM MEMORY ***
app.get('/app', (req, res) => res.send(HTML_CLIENT));
app.get('/', (req, res) => res.redirect('/app'));

// HEALTH
app.get('/api/v1/health', (req, res) => res.json({ status: "ALIVE" }));

// REGISTER - OPTIONS
app.get('/api/v1/auth/register-options', async (req, res) => {
    const key = req.headers['x-chaos-master-key'];
    if((key !== MASTER_KEY) && REGISTRATION_LOCKED) return res.status(403).json({ error: "LOCKED" });
    try {
        const o = await generateRegistrationOptions({
            rpName: 'Chaos', rpID: (req.headers['x-forwarded-host'] || req.get('host')).split(':')[0], 
            userID: new Uint8Array(Buffer.from(ADMIN_USER_ID)), userName: 'admin',
            attestationType: 'none', authenticatorSelection: { residentKey: 'required', userVerification: 'preferred', authenticatorAttachment: 'platform' },
        });
        Challenges.set(ADMIN_USER_ID, o.challenge);
        res.json(o);
    } catch(e) { res.status(500).json({error:e.message}); }
});

// REGISTER - VERIFY
app.post('/api/v1/auth/register-verify', async (req, res) => {
    if((req.headers['x-chaos-master-key'] !== MASTER_KEY) && REGISTRATION_LOCKED) return res.status(403).json({ error: "LOCKED" });
    try {
        const expectedRPID = (req.headers['x-forwarded-host'] || req.get('host')).split(':')[0];
        const expectedOrigin = `https://${req.headers['x-forwarded-host'] || req.get('host')}`;
        
        const v = await verifyRegistrationResponse({ 
            response: req.body, expectedChallenge: Challenges.get(ADMIN_USER_ID), 
            expectedOrigin, expectedRPID 
        });
        if(v.verified) {
            const u = Users.get(ADMIN_USER_ID);
            // Ensure ID is stored as Buffer
            const newCred = { ...v.registrationInfo, credentialID: toBuffer(toBase64(v.registrationInfo.credentialID)) };
            
            const exists = u.credentials.find(c => toBase64(c.credentialID) === toBase64(newCred.credentialID));
            if(!exists) { u.credentials.push(newCred); Users.set(ADMIN_USER_ID, u); REGISTRATION_LOCKED=true; }
            res.json({verified:true});
        } else res.status(400).json({verified:false});
    } catch(e) { res.status(400).json({error:e.message}); }
});

// LOGIN - OPTIONS (FIXED HERE)
app.get('/api/v1/auth/login-options', async (req, res) => {
    const u = Users.get(ADMIN_USER_ID);
    if(!u || u.credentials.length===0) return res.status(404).json({error:"NO ID"});
    
    // *** THE CRITICAL FIX: Convert ID to Base64URL String ***
    const allowed = u.credentials.map(c => ({
        id: toBase64(c.credentialID), // Ensure String!
        type: 'public-key'
    }));
    
    const o = await generateAuthenticationOptions({ 
        rpID: (req.headers['x-forwarded-host'] || req.get('host')).split(':')[0], 
        allowCredentials: allowed, 
        userVerification:'preferred' 
    });
    Challenges.set(o.challenge, {challenge:o.challenge});
    res.json(o);
});

// LOGIN - VERIFY
app.post('/api/v1/auth/login-verify', async (req, res) => {
    try {
        const json = Buffer.from(req.body.response.clientDataJSON, 'base64url').toString('utf8');
        const chal = JSON.parse(json).challenge;
        if(!Challenges.has(chal)) return res.status(400).json({error:"Bad Challenge"});
        
        const u = Users.get(ADMIN_USER_ID);
        const match = u.credentials.find(c => toBase64(c.credentialID) === req.body.id);
        if(!match) return res.status(400).json({error:"Device Not Found"});
        
        const expectedRPID = (req.headers['x-forwarded-host'] || req.get('host')).split(':')[0];
        const expectedOrigin = `https://${req.headers['x-forwarded-host'] || req.get('host')}`;

        const v = await verifyAuthenticationResponse({ 
            response: req.body, expectedChallenge: chal, expectedOrigin, expectedRPID, 
            authenticator: match, requireUserVerification: false 
        });
        if(v.verified) {
            match.counter = v.authenticationInfo.newCounter;
            Users.set(ADMIN_USER_ID, u);
            const t = crypto.randomBytes(32).toString('hex');
            Sessions.set(t, true);
            res.json({verified:true, token:t});
        } else res.status(400).json({verified:false});
    } catch(e) { res.status(500).json({error:e.message}); }
});

// Gate Unlock
app.post('/api/v1/auth/unlock-gate', (req, res) => {
    if(!Sessions.has(req.headers['x-chaos-token'])) return res.status(401).json({error:"Login First"});
    REGISTRATION_LOCKED = false;
    if(GATE_UNLOCK_TIMER) clearTimeout(GATE_UNLOCK_TIMER);
    GATE_UNLOCK_TIMER = setTimeout(()=>REGISTRATION_LOCKED=true, 30000);
    res.json({success:true, message:"UNLOCKED 30s"});
});

// STREAM
app.get('/api/v1/stream', (req,res) => LiveWire.addClient(req,res));

// DASHBOARD
app.get('/dashboard', (req, res) => res.send(`
    <body style="background:#000;color:#0f0;font-family:monospace;text-align:center;padding:50px;">
        <h1>A+ DASHBOARD (SECURE)</h1>
        <p>SYSTEM ONLINE. IDENTITY VERIFIED.</p>
        <button onclick="unlock()" style="padding:20px;background:#300;color:#fff;border:none;margin-top:20px;cursor:pointer;">UNLOCK GATE (30s)</button>
        <script>
            function unlock() {
                fetch('/api/v1/auth/unlock-gate', {method:'POST', headers:{'x-chaos-token':sessionStorage.getItem('chaos_session')}})
                .then(r=>r.json()).then(d=>alert(d.message||d.error));
            }
        </script>
    </body>
`));

app.listen(PORT, '0.0.0.0', () => console.log(`>>> V144.2 BUNDLE ONLINE`));
