// router.js — V4.0 — STABLE ROUTING
// 🛡️ SECURITY LEVEL: STANDARD (Prevents Reload Loops)

// 1. SAFE ZONES (Router will NOT check auth here)
const PUBLIC_ROUTES = ['/', '/index.html', '/login.html', '/login'];
const ADMIN_ROUTE = '/admin.html'; // Explicit file name for clarity

// 🛑 MASTER KEY DEFINITION
const MASTER_CALLSIGN = "APLUS-OGD-ADMIN"; 

function checkAuth() {
    const path = window.location.pathname;

    // 🛑 STOP: If we are on a public page, DO NOTHING.
    // This fixes the "Reload Loop".
    if (PUBLIC_ROUTES.some(route => path.endsWith(route)) || path === '/') {
        console.log("✅ Public Zone: No Auth Required");
        return; 
    }

    // 🔒 PROTECTED CHECK: Anything else requires keys
    const key = localStorage.getItem('chaos_key_vault');
    const session = localStorage.getItem('session_start');

    if (!key || !session) {
        console.warn("⛔ No Credentials Found. Redirecting to Landing.");
        // Only redirect if we aren't already there!
        window.location.href = '/index.html'; 
        return;
    }

    // 🔐 ADMIN GATEKEEPER
    if (path.includes('admin')) {
        const currentCallsign = localStorage.getItem('callsign_history') || "UNKNOWN";
        const currentTrust = parseInt(localStorage.getItem('chaos_trust_score') || '0');

        if (currentCallsign !== MASTER_CALLSIGN) {
            alert(`⛔ ACCESS DENIED: User '${currentCallsign}' is not Admin.`);
            window.location.href = '/dashboard.html';
            return;
        }
        
        if (currentTrust < 90) {
            alert("⚠️ BIOMETRIC ALERT: Trust Score too low for Admin Console.");
             // Allow access for now to fix issues, but warn
        }
    }
}

// Run immediately
checkAuth();
