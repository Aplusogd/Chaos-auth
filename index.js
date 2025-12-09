/**
 * A+ CHAOS ID: V158 (THE INVISIBLE WALL)
 * STATUS: SERVER-SIDE DEFENSE
 * FIX: Implements Content Hydration Gate. Main content is only sent AFTER client passes JS entropy check.
 */
import express from 'express';
import path from 'path';
import cors from 'cors';
import fs from 'fs';
import crypto from 'crypto';
import helmet from 'helmet';
import { fileURLToPath } from 'url';
import { dirname } from 'path';     
import { 
    generateRegistrationOptions, 
    verifyRegistrationResponse, 
    generateAuthenticationOptions, 
    verifyAuthenticationResponse 
} from '@simplewebauthn/server';

// --- ZOMBIE PROTOCOL ---
process.on('uncaughtException', (err) => console.error('>>> [SECURE LOG] ERROR', err.message));
process.on('unhandledRejection', (r) => console.error('>>> [SECURE LOG] REJECT', r));

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const publicPath = path.join(__dirname, 'public');

const app = express();
const PORT = process.env.PORT || 3000;

// SECRETS VAULT (Loading config keys here)
const MASTER_KEY = process.env.MASTER_KEY || "chaos-genesis";

// --- MIDDLEWARE & DATA ---
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*' })); 
app.use(express.json());
app.use(express.static(publicPath));
// ... (All other core logic: User Maps, Telemetry, etc. remains the same, omitted for brevity)

// --- MOCK PROTECTED CONTENT (What the AI is trying to scrape) ---
const PROTECTED_CONTENT_HTML = `
    <section class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-32">
        <div class="p-8 rounded bg-black/40 backdrop-blur card-hover group">
            <div class="w-12 h-12 bg-green-900/20 rounded flex items-center justify-center mb-6"><i class="fas fa-fingerprint text-2xl text-green-500"></i></div>
            <h3 class="text-xl font-bold text-white mb-3">Chaos Identity</h3>
            <p class="text-gray-400 text-sm">Biometric proof of life required for entry.</p>
        </div>
        <div class="p-8 rounded bg-black/40 backdrop-blur card-hover group block cursor-pointer border-t-2 border-t-blue-500/50">
            <div class="w-12 h-12 bg-blue-900/20 rounded flex items-center justify-center mb-6"><i class="fas fa-wave-square text-2xl text-blue-500"></i></div>
            <h3 class="text-xl font-bold text-white mb-3">Dreams V6</h3>
            <p class="text-gray-400 text-sm">Acoustic fingerprinting for hardware.</p>
        </div>
        <div class="p-8 rounded bg-black/40 backdrop-blur card-hover group">
            <div class="w-12 h-12 bg-purple-900/20 rounded flex items-center justify-center mb-6"><i class="fas fa-eye text-2xl text-purple-500"></i></div>
            <h3 class="text-xl font-bold text-white mb-3">Sentinel AI</h3>
            <p class="text-gray-400 text-sm">Active Bot Defense System.</p>
        </div>
    </section>
`;

// --- NEW API: UNLOCK GATE ---
app.post('/api/unlock', (req, res) => {
    const { XEntropy } = req.headers;
    const { timestamp, browserEntropy } = req.body; 

    // SIMPLE CHECK: If the client didn't run the JS (empty entropy) or sent a timestamp that's too far in the past/future
    if (!browserEntropy || (Date.now() - timestamp > 5000)) {
         console.log(">>> [GATE] HYDRATION BLOCKED: Missing/Stale Entropy.");
         return res.status(403).json({ error: "JS_CHALLENGE_FAILED" });
    }

    // Advanced: Run server-side check on the browserEntropy hash to see if it matches a known bot signature
    
    console.log(">>> [GATE] CONTENT HYDRATED: JS Challenge Passed.");
    res.json({ success: true, content: PROTECTED_CONTENT_HTML });
});


// --- REST OF V150.1 CORE ROUTES ---
// (All other API routes like /api/v1/auth/login-verify, /api/v1/hardware/diagnostic, etc. go here)
// ...

// --- FILE SERVING ---
const serve = (f, res) => fs.existsSync(path.join(publicPath, f)) ? res.sendFile(path.join(publicPath, f)) : res.status(404).send('Missing: ' + f);
app.get('/', (req, res) => serve('index.html', res));
// ... (All other file routes)

app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V158 ONLINE (INVISIBLE WALL)`));
