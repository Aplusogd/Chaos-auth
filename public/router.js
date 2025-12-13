// router.js — V3.0 — MASTER LOCKDOWN
// 🛡️ SECURITY LEVEL: CRIMSON

const PROTECTED_ROUTES = ['/dashboard', '/admin', '/pair', '/search', '/examples.html'];
const ADMIN_ROUTE = '/admin';

// 🛑 THE MASTER KEY
const MASTER_CALLSIGN = "APLUS-OGD-ADMIN"; 

function checkAuth() {
    const path = window.location.pathname;
    
    // 1. GLOBAL CHECK (Are you logged in?)
    if (PROTECTED_ROUTES.some(route => path.includes(route))) {
        const key = localStorage.getItem('chaos_key_vault');
        const session = localStorage.getItem('session_start');
        
        if (!key || !session) {
            console.warn("⛔ ACCESS DENIED: Missing Keys. Redirecting to Login.");
            window.location.href = '/login';
            return;
        }
    }

    // 2. ADMIN FIREWALL (The Chaos Gate)
    if (path.includes(ADMIN_ROUTE)) {
        const currentCallsign = localStorage.getItem('callsign_history') || "UNKNOWN";
        const currentTrust = parseInt(localStorage.getItem('chaos_trust_score') || '0');

        console.log(`🔒 Checking Admin Access for: ${currentCallsign}`);

        // CONDITION A: Wrong Identity
        if (currentCallsign !== MASTER_CALLSIGN) {
            alert(`⛔ ACCESS DENIED\nUser '${currentCallsign}' is not authorized. Access Restricted to ${MASTER_CALLSIGN}.`);
            window.location.href = '/dashboard';
            return;
        }

        // CONDITION B: Weak Biometrics (The 90% Threshold)
        if (currentTrust < 90) {
            alert(`⛔ BIOMETRIC MISMATCH\nTrust Score (${currentTrust}%) is too low. Recalibrate.`);
            window.location.href = '/dashboard';
            return;
        }
    }
}

// Execute Guard
checkAuth();
