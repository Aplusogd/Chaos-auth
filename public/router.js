// router.js — V4.2 — HARMONY ROUTING
// 🛡️ FUNCTION: Ensures all non-public pages require login, prevents reload loops.

// 1. SAFE ZONES (Router will NOT check auth here)
const PUBLIC_ROUTES = ['/', '/index.html', '/login.html', '/login'];

// 🛑 MASTER KEY DEFINITION
const MASTER_CALLSIGN = "APLUS-OGD-ADMIN"; 

function checkAuth() {
    const path = window.location.pathname;

    // 🛑 STEP 1: If we are on a public page, immediately exit. (Fixes the loop!)
    if (PUBLIC_ROUTES.some(route => path.endsWith(route)) || path === '/') {
        return; 
    }

    // 🔒 STEP 2: PROTECTED ZONE CHECK (Requires keys)
    const key = localStorage.getItem('chaos_key_vault');

    if (!key) {
        console.warn("⛔ ACCESS DENIED: Missing Credentials. Redirecting to Index.");
        window.location.href = '/index.html'; 
        return;
    }

    // 🔐 STEP 3: ADMIN GATEKEEPER CHECK
    if (path.includes('/admin.html')) {
        const currentCallsign = localStorage.getItem('callsign_history') || "UNKNOWN";
        const currentTrust = parseInt(localStorage.getItem('chaos_trust_score') || '0');

        if (currentCallsign !== MASTER_CALLSIGN) {
            alert("⛔ ACCESS DENIED: Not Master Operator.");
            window.location.href = '/dashboard.html';
            return;
        }
        
        if (currentTrust < 90) {
            alert(`⚠️ BIOMETRIC ALERT: Trust Score (${currentTrust}%) too low for Admin Console.`);
            // Note: This still allows temporary Admin access if keys are set, 
            // but strongly warns you about low trust.
        }
    }
}

// Run immediately
checkAuth();
