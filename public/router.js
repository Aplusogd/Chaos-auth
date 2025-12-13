// router.js — V4.1
// 🛡️ SECURITY LEVEL: STANDARD

// 1. SAFE ZONES (Public)
const PUBLIC_ROUTES = ['/', '/index.html', '/login.html', '/login'];
const ADMIN_ROUTE = '/admin.html'; 

// 🛑 MASTER KEY
const MASTER_CALLSIGN = "APLUS-OGD-ADMIN"; 

function checkAuth() {
    const path = window.location.pathname;

    if (PUBLIC_ROUTES.some(route => path.endsWith(route)) || path === '/') {
        return; 
    }

    // 🔒 CHECK KEYS
    const key = localStorage.getItem('chaos_key_vault');
    if (!key) {
        window.location.href = '/index.html'; 
        return;
    }

    // 🔐 ADMIN CHECK
    if (path.includes('admin')) {
        const currentCallsign = localStorage.getItem('callsign_history');
        if (currentCallsign !== MASTER_CALLSIGN) {
            alert("⛔ ACCESS DENIED.");
            window.location.href = '/dashboard.html';
        }
    }
}
checkAuth();
