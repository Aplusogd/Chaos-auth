// router.js — V256 — STABLE GUARD

const PROTECTED_ROUTES = ['/dashboard', '/admin', '/pair', '/search', '/examples.html'];

function checkAuth() {
    const path = window.location.pathname;
    
    // Only check security on protected pages
    if (PROTECTED_ROUTES.some(route => path.includes(route))) {
        
        const key = localStorage.getItem('chaos_key_vault');
        const session = localStorage.getItem('session_start');
        
        // DEBUG: Uncomment this line to see what's happening in Console
        // console.log("Checking Auth:", { key, session, path });

        if (!key || !session) {
            console.warn("⛔ ACCESS DENIED: Missing Keys. Redirecting to Login.");
            window.location.href = '/login';
        }
    }
}

// Execute immediately
checkAuth();
