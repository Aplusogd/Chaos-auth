// router.js — V260 — BIOMETRIC FIREWALL

const PROTECTED_ROUTES = ['/dashboard', '/admin', '/pair', '/search', '/examples.html'];
const ADMIN_ROUTE = '/admin';

// 🛑 SET YOUR MASTER CALLSIGN HERE
const MASTER_CALLSIGN = "APLUS-ROOT"; 

function checkAuth() {
    const path = window.location.pathname;
    
    // 1. GLOBAL CHECK (Are you logged in?)
    if (PROTECTED_ROUTES.some(route => path.includes(route))) {
        const key = localStorage.getItem('chaos_key_vault');
        const session = localStorage.getItem('session_start');
        
        if (!key || !session) {
            console.warn("⛔ ACCESS DENIED: Missing Keys.");
            window.location.href = '/login';
            return;
        }
    }

    // 2. ADMIN FIREWALL (The Chaos Gate)
    if (path.includes(ADMIN_ROUTE)) {
        const currentCallsign = localStorage.getItem('callsign_history') || "UNKNOWN";
        const currentTrust = parseInt(localStorage.getItem('chaos_trust_score') || '0');

        // CONDITION A: Wrong Name
        if (currentCallsign !== MASTER_CALLSIGN) {
            alert(`⛔ ACCESS DENIED\nUser '${currentCallsign}' is not Authorized.\nThis incident has been logged.`);
            window.location.href = '/dashboard';
            return;
        }

        // CONDITION B: Weak Biometrics (The Hacker Trap)
        // If someone steals your name but doesn't have your finger history, 
        // their score will be low (50). They need > 90 to enter.
        if (currentTrust < 90) {
            alert(`⛔ BIOMETRIC MISMATCH\nTrust Score ${currentTrust}% is too low.\nOnly the True Operator (90%+) can enter.`);
            window.location.href = '/dashboard';
            return;
        }
    }
}

// Execute Guard
checkAuth();
