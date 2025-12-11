// public/router.js - V245 Client Security
const PROTECTED_ROUTES = ['/dashboard', '/admin', '/pair'];

function checkAuth() {
    const path = window.location.pathname;
    
    // 1. Check if we are on a protected page
    if (PROTECTED_ROUTES.some(route => path.startsWith(route))) {
        // 2. Check for the keys in storage
        const key = localStorage.getItem('chaos_key_vault');
        const session = localStorage.getItem('session_start');
        
        // 3. If missing, kick to login
        if (!key || !session) {
            console.warn("⛔ ACCESS DENIED: The Abyss requires a key.");
            window.location.href = '/login';
        }
    }
}

// Run immediately
checkAuth();
