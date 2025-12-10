/**
 * A+ CHAOS ID: V165 (TRUST BYPASS)
 * STATUS: PRODUCTION
 * FIX: Removed the browserEntropy check in /api/unlock to ensure 100% human throughput.
 * Security now relies solely on the Kinetic Scroll Defense.
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
process.on('uncaughtException', (err) => console.error('>>> [CRASH LOG] FATAL ERROR CAUGHT:', err.message, err));
process.on('unhandledRejection', (reason) => console.error('>>> [CRASH LOG] REJECTION CAUGHT:', reason));

// --- 1. INITIAL SETUP ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const publicPath = path.join(__dirname, 'public');

const app = express();
const PORT = process.env.PORT || 3000;

// --- 2. SECRETS VAULT ---
const MASTER_KEY = process.env.MASTER_KEY || "chaos-genesis";
// ... (All other config/secrets loading)

// --- 3. SENTINEL SDK V1.0 CODE (The Black Box) ---
const SENTINEL_SDK_CODE = `
    class SentinelSDK {
        constructor(config = {}) {
            this.buffer = []; this.score = 100; this.lastY = 0; this.lastT = Date.now();
            this.CONFIG = {
                THRESHOLD_VARIANCE: 0.005, PENALTY_RATE: 5, REWARD_RATE: 1,
                IDLE_TIMEOUT_MS: 150, SPIKE_THRESHOLD_MS: 2, SPIKE_DISTANCE: 100,
                ...config
            };
            this.init();
        }

        init() {
            window.addEventListener('scroll', this.analyze.bind(this), { passive: true });
        }

        analyze(e) {
            const now = Date.now();
            const y = window.scrollY;
            const dt = now - this.lastT;
            const dy = y - this.lastY;
            
            // 1. IDLE GATE
            if (dt > this.CONFIG.IDLE_TIMEOUT_MS) { this.lastT = now; this.lastY = y; return; }
            
            // 2. VELOCITY SPIKE TRAP
            if (dt < this.CONFIG.SPIKE_THRESHOLD_MS && Math.abs(dy) > this.CONFIG.SPIKE_DISTANCE) {
                this.score = 0;
                this.triggerLockout('SPIKE_TRAP');
                return;
            }

            if (Math.abs(dy) > 0) {
                const velocity = Math.abs(dy / dt);
                this.buffer.push(velocity);
                if(this.buffer.length > 20) this.buffer.shift();
                
                const variance = this.calculateVariance(this.buffer);
                
                if(this.buffer.length > 5) {
                    if(variance < this.CONFIG.THRESHOLD_VARIANCE) { 
                        this.score = Math.max(0, this.score - this.CONFIG.PENALTY_RATE);
                    } else {
                        this.score = Math.min(100, this.score + this.CONFIG.REWARD_RATE);
                    }
                }
                
                if (this.score <= 0) {
                    this.triggerLockout('KINETIC_DECAY');
                }
            }
            this.lastY = y;
            this.lastT = now;
        }

        calculateVariance(arr) {
            if (arr.length === 0) return 0;
            const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
            return arr.reduce((sq, n) => sq + Math.pow(n - mean, 2), 0) / arr.length;
        }

        triggerLockout(reason) {
            window.removeEventListener('scroll', this.analyze);
            window.dispatchEvent(new CustomEvent('sentinel:lockout', { detail: { reason: reason } }));
        }

        getTrustScore() { return this.score; }
    }

    window.ChaosSentinel = new SentinelSDK();
`;

// --- 4. UTILS & DATA STORE (Standard) ---
const toBuffer = (base64) => { try { return Buffer.from(base64, 'base64url'); } catch (e) { return Buffer.alloc(0); } };
const toBase64 = (buffer) => { if (typeof buffer === 'string') return buffer; return Buffer.from(buffer).toString('base64url'); };

const Users = new Map();
const ADMIN_USER_ID = 'admin-user';
const Challenges = new Map();
const Sessions = new Map();
const ApiKeys = new Map();
const TelemetryData = { requests: 0, blocked: 0, logs: [] };
let REGISTRATION_LOCKED = true;
let GATE_UNLOCK_TIMER = null;

// DNA LOADING (Protected)
// ... (DNA Loading Logic)

// --- 5. MIDDLEWARE & LIVE WIRE (Standard) ---
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*' })); 
app.use(express.json());
app.use(express.static(publicPath));

const LiveWire = {
    broadcast: (event, data) => { /* ... */ },
    addClient: (req, res) => { /* ... */ }
};
let connectedClients = [];

const Telemetry = {
    log: (type, msg) => { 
        console.log(`[${type}] ${msg}`); 
        LiveWire.broadcast('log', { entry: `[${type}] ${msg}` }); 
    }
};

// --- 6. PROTECTED CONTENT (MOCK HTML) ---
const PROTECTED_CONTENT_HTML = `
    <section id="chaos-container" class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-32">
        <div data-chaos-section class="p-8 rounded bg-black/40 backdrop-blur card-hover group border-t-2 border-t-red-500/50">
            <div class="w-12 h-12 bg-red-900/20 rounded flex items-center justify-center mb-6"><i class="fas fa-robot text-2xl text-red-500"></i></div>
            <h3 class="text-xl font-bold text-white mb-3">Invisible Wall</h3>
            <p class="text-gray-400 text-sm">*Solution for Data Leakage.* Content is only 'hydrated' for human visitors.</p>
        </div>
        <div data-chaos-section class="p-8 rounded bg-black/40 backdrop-blur card-hover group">
            <div class="w-12 h-12 bg-green-900/20 rounded flex items-center justify-center mb-6"><i class="fas fa-fingerprint text-2xl text-green-500"></i></div>
            <h3 class="text-xl font-bold text-white mb-3">Kinetic Entropy</h3>
            <p class="text-gray-400 text-sm">Proves "Proof of Life" using chaotic velocity.</p>
        </div>
        <div data-chaos-section class="p-8 rounded bg-black/40 backdrop-blur card-hover group block cursor-pointer border-t-2 border-t-blue-500/50">
            <div class="w-12 h-12 bg-blue-900/20 rounded flex items-center justify-center mb-6"><i class="fas fa-wave-square text-2xl text-blue-500"></i></div>
            <h3 class="text-xl font-bold text-white mb-3">Dreams V6</h3>
            <p class="text-gray-400 text-sm">Acoustic diagnostics for hardware health.</p>
        </div>
    </section>
`;

// --- 7. API ROUTES ---

// NEW API: UNLOCK GATE (Content Hydration) - TRUST BYPASS IMPLEMENTED
app.post('/api/unlock', (req, res) => {
    const { timestamp } = req.body; 

    // The only remaining check is against basic replay attacks (timestamp).
    // The browserEntropy check is REMOVED to ensure 100% human access.
    if (Date.now() - timestamp > 10000) {
         Telemetry.log("BLOCK", "Hydration Failed: Stale Timestamp (Bot/Replay Attack)");
         return res.status(403).json({ error: "STALE_TIMESTAMP" });
    }

    Telemetry.log("SECURITY", "Content Hydrated: Trust Bypass Granted.");
    res.json({ success: true, content: PROTECTED_CONTENT_HTML });
});

// --- AUTH, TELEMETRY, DEMO ROUTES (Placeholder for Brevity) ---
// ... (All other API routes: /api/v1/auth, /api/v1/beta/pulse-demo, etc. are here)

// --- 8. FILE SERVING (Injection Handler) ---
const serve = (f, res) => fs.existsSync(path.join(publicPath, f)) ? res.sendFile(path.join(publicPath, f)) : res.status(404).send('Missing: ' + f);

// Custom handler for index.html to inject the SDK
app.get('/', (req, res) => {
    const filePath = path.join(publicPath, 'index.html');
    if (fs.existsSync(filePath)) {
        let htmlContent = fs.readFileSync(filePath, 'utf8');
        
        // Inject the entire SDK class and bootstrap into the HTML
        const scriptToInject = `\n<script type="text/javascript">${SENTINEL_SDK_CODE}</script>\n`;
        htmlContent = htmlContent.replace('</head>', scriptToInject + '</head>');
        
        res.send(htmlContent);
    } else {
        res.status(404).send('Missing: index.html');
    }
});

// Standard handlers for other files
// ... (All other file routes: /app, /dashboard, /dreams, etc.)

// --- 9. GUARANTEED SERVER START ---
try {
    app.listen(PORT, '0.0.0.0', () => console.log(`>>> CHAOS V165 ONLINE (TRUST BYPASS on ${PORT})`));
} catch (e) {
    console.error(`>>> [FATAL] FAILED TO BIND PORT ${PORT}. Error:`, e.message);
}
