// router.js - CENTRAL ROUTING SCRIPT (V228)
// This file enforces flow, guards protected routes, and handles initial load stability.

function router() {
    // Current Path
    const path = window.location.pathname;

    // Data Status Checks (CRASH-PROOF)
    const hasCallsign = localStorage.getItem('chaos_key_vault') !== null;
    const isVerified = sessionStorage.getItem('verified_user_data') !== null;

    // --- MAIN ROUTING LOGIC ---
    switch (path) {
        case '/':
            // Landing: If verified, go straight to Sanctuary.
            if (isVerified) {
                window.location.href = '/sanctuary';
                return;
            }
            // If user has a key but hasn't verified this session, go to login.
            if (hasCallsign) {
                window.location.href = '/verify';
                return;
            }
            // Otherwise, stay on landing page (index.html).
            break;

        case '/forge':
            // Creation: Skip creation if a key already exists.
            if (hasCallsign) {
                window.location.href = '/verify';
                return;
            }
            break;

        case '/verify':
            // Login: If no key exists, force creation first.
            if (!hasCallsign) {
                window.location.href = '/forge';
                return;
            }
            // If already verified this session, skip verification.
            if (isVerified) {
                window.location.href = '/sanctuary';
                return;
            }
            // Add Anti-White Screen Delay for Input Auto-Fill (Grok's Fix)
            setTimeout(() => {
                try {
                    const history = localStorage.getItem('callsign_history');
                    if (history) document.getElementById('callsignInput').value = history;
                } catch (e) {
                    console.warn('Router error during auto-fill:', e);
                }
            }, 100);
            break;

        case '/sanctuary':
        case '/profile/calibrate':
            // Guarded Destinations: Requires fresh session verification.
            if (!isVerified) {
                // If key exists but session data is gone, re-verify.
                window.location.href = '/verify';
                return;
            }
            break;

        case '/logout':
            // Logout is handled by logout.html directly.
            break;
            
        default:
            // 404 handler
            window.location.href = '/error.html?code=404';
    }
}

// Attach the router to run immediately after the DOM content is loaded
window.addEventListener('DOMContentLoaded', router);
window.addEventListener('popstate', router);
