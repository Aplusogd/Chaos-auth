<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>A+ CHAOS | SECURE LOGIN GATE</title>
    <meta name="description" content="Quantum-Resistant Biometric Entry — DREAMS V3 + MBF Ready">
    <!-- CRITICAL FIX: REMOVED CDN -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <!-- V10 LIBRARY -->
    <script src="https://unpkg.com/@simplewebauthn/browser@10.0.0/dist/bundle/index.umd.min.js"></script>
    
    <style>
        /* INJECTED PRODUCTION STYLES */
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;800&display=swap');
        
        body { 
            background-color: #000; 
            color: #00ff41; 
            font-family: 'JetBrains Mono', monospace; 
            touch-action: manipulation;
            overflow: hidden;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 1.5rem;
        }

        .hud-status {
            font-size: 1.8rem;
            font-weight: 800;
            text-align: center;
            text-transform: uppercase;
            text-shadow: 0 0 15px #00ff41;
            margin-bottom: 2rem;
            min-height: 4rem;
            transition: all 0.4s ease;
        }

        .smart-btn {
            width: 100%;
            padding: 1.8rem;
            font-size: 1.3rem;
            font-weight: bold;
            border: 2px solid #00ff41;
            background: linear-gradient(to bottom, #001a00, #000);
            color: #00ff41;
            border-radius: 16px;
            transition: all 0.3s;
            text-transform: uppercase;
            letter-spacing: 3px;
            box-shadow: 0 0 20px rgba(0, 255, 65, 0.3);
        }

        .smart-btn:hover:not(:disabled) {
            transform: translateY(-4px);
            box-shadow: 0 12px 30px rgba(0, 255, 65, 0.5);
            background: linear-gradient(to bottom, #002200, #001100);
        }

        .smart-btn:disabled {
            opacity: 0.4;
            cursor: not-allowed;
            border-color: #333;
            color: #666;
        }

        .status-seal {
            font-size: 11px;
            padding: 6px 12px;
            border-radius: 6px;
            margin: 6px 0;
            display: inline-block;
            min-width: 200px;
        }

        .bg-red-900\/50 { background-color: rgba(127, 29, 29, 0.5); }
        .bg-green-900\/50 { background-color: rgba(21, 128, 61, 0.5); }
        .text-red-400 { color: #f87171; }
        .text-green-400 { color: #34d399; }
        .text-gray-600 { color: #4b5563; }
        .border-red-900 { border-color: #7f1d1d; }
        .border-green-700 { border-color: #047857; }
        .pulse { animation: pulse 2s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.6; } }
    </style>
</head>
<body class="bg-black">

    <div class="w-full max-w-sm text-center mb-10">
        <div class="text-xs text-gray-600 mb-3">A+ CHAOS CORE // V39 QUANTUM SEAL</div>
        <h1 class="text-4xl font-bold tracking-tighter text-white">BIOMETRIC GATE</h1>
    </div>

    <!-- QUANTUM HUD -->
    <div id="hud" class="hud-status pulse">
        INITIALIZING QUANTUM LOCK...
    </div>
    
    <!-- SECURITY STATUS SEALS -->
    <div class="text-center mb-10 space-y-3">
        <div id="check-secure" class="status-seal bg-red-900/50 text-red-400 border border-red-900">
            SECURE CONTEXT: PENDING
        </div>
        <div id="check-platform" class="status-seal bg-red-900/50 text-red-400 border border-red-900">
            AUTHENTICATOR: DETECTING
        </div>
        <div id="check-server" class="status-seal bg-red-900/50 text-red-400 border border-red-900">
            SERVER STATUS: CHECKING
        </div>
    </div>

    <!-- SMART ADAPTIVE BUTTON -->
    <div class="w-full max-w-sm">
        <button id="main-btn" class="smart-btn" disabled onclick="handleMainAction()">
            <i class="fas fa-circle-notch fa-spin mr-3"></i> CHECKING ENVIRONMENT...
        </button>
    </div>

    <!-- TOAST -->
    <div id="toast" class="fixed bottom-6 left-1/2 transform -translate-x-1/2 px-6 py-3 rounded-lg shadow-2xl opacity-0 transition-opacity duration-500 text-sm backdrop-blur"></div>

    <script>
        const { startRegistration, startAuthentication, platformAuthenticatorIsAvailable } = SimpleWebAuthnBrowser;
        const API_BASE = '/api/v1';
        const HEADERS = { 'Content-Type': 'application/json', 'X-APLUS-SECURE': 'TOTEM_V8_BIO' };

        let isRegistered = false;

        function updateHUD(text, color = 'text-green-500') {
            const h = document.getElementById('hud');
            h.innerText = text;
            h.className = `hud-status ${color} pulse`;
        }

        function updateSeal(id, success, msg) {
            const el = document.getElementById(id);
            el.innerHTML = success 
                ? `<i class="fas fa-check-circle mr-2"></i>${msg}`
                : `<i class="fas fa-times-circle mr-2"></i>${msg}`;
            // Use explicit class toggling for production stability
            el.classList.toggle('bg-green-900/50', success);
            el.classList.toggle('text-green-400', success);
            el.classList.toggle('border-green-700', success);
            el.classList.toggle('bg-red-900/50', !success);
            el.classList.toggle('text-red-400', !success);
            el.classList.toggle('border-red-900', !success);
        }

        function showToast(msg, success = false) {
            const t = document.getElementById('toast');
            // Simplified class names for the toast (since we removed the external dependency)
            t.innerText = msg;
            t.style.backgroundColor = success ? '#065f46' : '#991b1b'; 
            t.style.color = '#fff';
            t.style.opacity = 1;
            setTimeout(() => t.style.opacity = 0, 4000);
        }

        function buzz() { if (navigator.vibrate) navigator.vibrate([100, 50, 100]); }

        async function checkEnvironment() {
            const btn = document.getElementById('main-btn');
            let ready = true;

            // 1. Secure Context Check
            if (window.isSecureContext) {
                updateSeal('check-secure', true, 'SECURE CONTEXT: ACTIVE');
            } else {
                updateSeal('check-secure', false, 'HTTPS REQUIRED');
                ready = false;
            }

            // 2. Platform Authenticator Check
            const platformOk = await platformAuthenticatorIsAvailable();
            if (platformOk) {
                updateSeal('check-platform', true, 'AUTHENTICATOR: READY');
            } else {
                updateSeal('check-platform', false, 'NO BIOMETRIC DEVICE');
                ready = false;
            }

            // 3. Server Reachability + Registration Status
            try {
                const statusResp = await fetch(`${API_BASE}/auth/login-options`, { headers: HEADERS });
                
                if (statusResp.ok) {
                    // Server sent options; user is registered.
                    isRegistered = true;
                    updateSeal('check-server', true, 'SERVER: ID FOUND');
                } else {
                    // Server responded with 404/403/other error; likely unregistered state
                    isRegistered = false;
                    updateSeal('check-server', true, 'SERVER: ID SLOT OPEN');
                }
            } catch (e) {
                updateSeal('check-server', false, 'ABYSS UNREACHABLE');
                updateHUD("ABYSS UNREACHABLE", "text-red-500");
                btn.innerText = "RETRY";
                ready = false;
            }

            // Final state transition
            if (ready) {
                updateHUD("CHAOS CORE READY FOR HANDSHAKE", "text-green-400");
                btn.innerHTML = isRegistered 
                    ? '<i class="fas fa-fingerprint mr-3"></i> VERIFY IDENTITY'
                    : '<i class="fas fa-shield-alt mr-3"></i> INITIALIZE DEVICE';
                btn.disabled = false;
            }
            return ready;
        }

        async function handleMainAction() {
            const btn = document.getElementById('main-btn');
            btn.disabled = true;
            buzz();

            if (!isRegistered) {
                await doRegister();
            } else {
                await doLogin();
            }
            btn.disabled = false;
        }

        async function doRegister() {
             updateHUD("SYSTEM LOCKED. ACCESS DENIED.", "text-red-500");
             showToast("Registration is closed. Contact admin for key reset.", false);
        }

        async function doLogin() {
            updateHUD("SCAN BIOMETRIC NOW", "text-white");
            try {
                // A. GET OPTIONS
                const opts = await (await fetch(`${API_BASE}/auth/login-options`, { headers: HEADERS })).json();
                
                // B. SCAN
                const asseResp = await startAuthentication({ publicKey: opts });

                // C. VERIFY (Temporal + Crypto)
                updateHUD("ANALYZING BEHAVIOR...", "text-blue-400");
                const verifyResp = await fetch(`${API_BASE}/auth/login-verify`, {
                    method: 'POST',
                    headers: HEADERS,
                    body: JSON.stringify(asseResp)
                });
                const result = await verifyResp.json();

                // D. SUCCESS & REDIRECT
                if (result.verified) {
                    updateHUD("ACCESS GRANTED", "text-green-500");
                    document.body.style.background = "radial-gradient(circle at center, #002200, #000)";
                    buzz();
                    
                    if (result.token) sessionStorage.setItem('chaos_session', result.token);
                    
                    showToast("Welcome, Agent", true);
                    setTimeout(() => location.href = '/dashboard.html', 1800);
                } else {
                    if (result.error && result.error.includes("TEMPORAL_ANOMALY")) {
                        throw new Error("BEHAVIORAL ANOMALY DETECTED.");
                    } else {
                        throw new Error(result.error || "Verification Failed.");
                    }
                }
            } catch (e) {
                let msg = e.message || "Login timed out or was cancelled.";
                updateHUD("ACCESS DENIED", "text-red-500");
                document.body.style.background = "radial-gradient(circle at center, #220000, #000)";
                showToast(msg, false);
                setTimeout(() => document.body.style.background = "#000", 2000);
            } finally {
                 document.getElementById('main-btn').disabled = false;
            }
        }
        
        // Execute initial checks on load
        window.onload = () => {
            document.getElementById('main-btn').onclick = checkEnvironment;
            // The initial check will fire and set the correct button action after the check.
            checkEnvironment();
            setInterval(checkEnvironment, 15000); // Keep status fresh
        };
    </script>
</body>
</html>
