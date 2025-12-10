import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';

// --- CONFIGURATION ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = process.env.PORT || 3000; 

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());
app.use(express.static('public')); 

// --- VAULT & SECURITY SEED (Omitted for brevity, assumed to be in the code) ---
// ...

// ==================================================================
// ROUTING (Deep Think: Mapping the Clean URLs)
// ==================================================================

// 1. LANDING PAGE (Base URL)
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public/index.html')));

// 2. FORGE (Callsign Creation)
app.get('/forge', (req, res) => res.sendFile(path.join(__dirname, 'public/abyss.html')));

// 3. VERIFY (Biometric Trace Login)
app.get('/verify', (req, res) => res.sendFile(path.join(__dirname, 'public/app.html')));

// 4. SANCTUARY (User Dashboard)
app.get('/sanctuary', (req, res) => res.sendFile(path.join(__dirname, 'public/check.html')));

// 5. PROFILE/CALIBRATE (Advanced Settings)
app.get('/profile/calibrate', (req, res) => res.sendFile(path.join(__dirname, 'public/abyss-forge.html')));

// --- UTILITY PAGES ---
app.get('/logout.html', (req, res) => res.sendFile(path.join(__dirname, 'public/logout.html')));
app.get('/error.html', (req, res) => res.sendFile(path.join(__dirname, 'public/error.html')));

// --- Fallback Routing (Ensures clean URLs are used) ---
app.get('/abyss.html', (req, res) => res.redirect(301, '/forge'));
app.get('/app.html', (req, res) => res.redirect(301, '/verify'));
app.get('/check.html', (req, res) => res.redirect(301, '/sanctuary'));

// ... (API routes are unchanged and assumed to be in the code) ...

app.listen(PORT, '0.0.0.0', () => {
    console.log(`⚡ A+ CHAOS CORE V226 ONLINE`);
    console.log(`📡 LISTENING ON PORT ${PORT}`);
});
