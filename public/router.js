// router.js - CENTRAL ROUTING SCRIPT (V231)
// This file enforces flow, guards protected routes, and handles initial load stability.

function router() {
    const path = window.location.pathname;

    // Data Status Checks (CRASH-PROOF)
    const hasCallsign = localStorage.getItem('chaos_key_vault') !== null;
    const isVerified = sessionStorage.getItem('verified_user_data') !== null;
    
    // NOTE: We only implement the auto-fill UX here for minimal code footprint.
    // The main routing flow is handled by the server (index.js).

    // --- MAIN ROUTING LOGIC (Guarding Protected Destinations) ---
    switch (path) {
        case '/':
            // Landing: If already verified, go to sanctuary.
            if (isVerified) {
                window.location.href = '/sanctuary';
                return;
            }
            break;

        case '/sanctuary':
        case '/profile/calibrate':
            // Guarded Destinations: Requires fresh session verification.
            if (!isVerified) {
                // If key exists but session data is gone, force re-verification.
                if (hasCallsign) {
                    window.location.href = '/login';
                    return;
                }
                // If no key at all, force creation.
                window.location.href = '/forge';
                return;
            }
            break;

        case '/login':
             // Anti-White Screen Delay for Input Auto-Fill UX
            setTimeout(() => {
                try {
                    const history = localStorage.getItem('callsign_history');
                    if (history) document.getElementById('callsignInput').value = history;
                } catch (e) {
                    console.warn('Router error during auto-fill:', e);
                }
            }, 100);
            break;
            
        case '/forge':
             // Creation Guard: If already logged in, skip creation.
            if (hasCallsign) {
                 window.location.href = '/login';
                 return;
            }
            break;

        // Default: Server handles 404
    }
}

// Hook to onload with a micro-delay to prevent storage race condition
window.addEventListener('DOMContentLoaded', router);
window.addEventListener('popstate', router);
