<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CHAOS | The DNA Lock</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js"></script> 
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap');
        body { background-color: #050505; color: #e5e5e5; font-family: 'JetBrains Mono', monospace; overflow-x: hidden; user-select: none; }
        .abyss-bg { background-image: linear-gradient(rgba(0, 255, 128, 0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0, 255, 128, 0.03) 1px, transparent 1px); background-size: 30px 30px; position: fixed; top: 0; left: 0; right: 0; bottom: 0; z-index: -1; }
        .console-box { background: rgba(10, 10, 10, 0.9); border: 1px solid #333; box-shadow: 0 0 20px rgba(0,0,0,0.8); }
        .star { position: absolute; width: 45px; height: 45px; border-radius: 50%; cursor: pointer; transition: all 0.2s; box-shadow: 0 0 20px currentColor; border: 2px solid white; }
        .star:active { transform: scale(0.8); }
    </style>
</head>
<body class="min-h-screen flex flex-col p-4 md:p-8">
    <div class="abyss-bg"></div>

    <header class="flex justify-between items-center mb-8 border-b border-gray-800 pb-4">
        <div><h1 class="text-2xl md:text-3xl font-bold tracking-widest text-white"><i class="fas fa-fingerprint mr-2 text-green-500"></i>CHAOS <span class="text-xs align-top text-gray-500">V.7</span></h1><p class="text-xs text-gray-500 mt-1">DNA LOCK PROTOCOL</p></div>
        <div class="text-right"><div id="device-id-display" class="text-[10px] text-gray-600">SCANNING HARDWARE...</div></div>
    </header>

    <main class="grid grid-cols-1 lg:grid-cols-12 gap-6 flex-grow relative">
        <!-- SECRET PATTERN OVERLAY -->
        <div id="captcha-layer" class="absolute inset-0 z-40 bg-black/95 flex flex-col items-center justify-center hidden">
            <h2 class="text-2xl font-bold text-white mb-2">ENTER STAR SIGN</h2>
            <p class="text-gray-400 mb-8 text-sm">Pattern Required. <span class="text-red-500">Hint: R -> B -> G -> R</span></p>
            <div id="star-field" class="relative w-full max-w-lg h-96 border border-gray-800 bg-gray-900 rounded-lg overflow-hidden"></div>
            <p id="captcha-msg" class="mt-4 text-blue-400 h-6 animate-pulse">Awaiting Input...</p>
        </div>

        <div class="lg:col-span-8 flex flex-col gap-6">
            <div class="console-box rounded-lg p-4 h-64 md:h-96 overflow-y-auto font-mono text-xs flex flex-col-reverse" id="console"><div class="text-gray-600">> System Ready.</div></div>
        </div>

        <div class="lg:col-span-4 flex flex-col gap-6">
            <div class="console-box rounded-lg p-6 relative overflow-hidden">
                <h2 class="text-xl font-bold mb-2 text-blue-500">DEVICE STATUS</h2>
                <div id="auth-state" class="text-xs text-gray-400 mb-6">UNVERIFIED</div>
                <button id="btn-init" class="w-full py-4 bg-blue-900/30 border border-blue-500/50 hover:bg-blue-900/50 text-blue-400 font-bold rounded transition"><i class="fas fa-unlock"></i> START VERIFICATION</button>
            </div>
        </div>
    </main>

    <script>
        const log = (msg, type='info') => {
            const consoleEl = document.getElementById('console');
            const div = document.createElement('div');
            div.className = 'mb-1 ' + (type === 'error' ? 'text-red-500' : type === 'success' ? 'text-green-500' : 'text-gray-400');
            div.innerHTML = `<span class="opacity-50">[${new Date().toLocaleTimeString()}]</span> ${msg}`;
            consoleEl.insertBefore(div, consoleEl.firstChild);
        };

        let currentNonce = null;
        let userSequence = []; 
        const HEADERS = { 'Content-Type': 'application/json', 'X-APLUS-SECURE': 'TOTEM_V4_ACCESS' };

        // --- 1. DEVICE FINGERPRINTING (THE DNA) ---
        function getDeviceFingerprint() {
            const rawData = [
                navigator.userAgent,
                navigator.language,
                screen.colorDepth,
                new Date().getTimezoneOffset(),
                navigator.hardwareConcurrency,
                navigator.deviceMemory || 'unknown',
                screen.width + 'x' + screen.height
            ].join('||');
            return CryptoJS.SHA256(rawData).toString();
        }

        const myDeviceHash = getDeviceFingerprint();
        document.getElementById('device-id-display').innerText = "DEVICE DNA: " + myDeviceHash.substring(0, 16) + "...";

        // --- 2. INITIATE ---
        document.getElementById('btn-init').addEventListener('click', async () => {
            log("Scanning Device DNA...", "info");
            document.getElementById('captcha-layer').classList.remove('hidden');
            try {
                const res = await fetch('/api/v1/challenge', { headers: HEADERS });
                const data = await res.json();
                if (data.pulse) {
                    currentNonce = data.pulse;
                    log("Pulse Acquired.", "info");
                    renderStars();
                }
            } catch(e) { log("Server Offline.", "error"); }
        });

        // --- 3. RENDER STARS ---
        const COLORS = ['red', 'blue', 'green', 'yellow'];
        function renderStars() {
            const field = document.getElementById('star-field');
            field.innerHTML = '';
            userSequence = [];
            for(let i=0; i<5; i++) {
                const color = COLORS[Math.floor(Math.random() * COLORS.length)];
                const star = document.createElement('div');
                star.className = `star bg-${color}-500`;
                star.style.left = Math.random() * 80 + 10 + '%';
                star.style.top = Math.random() * 80 + 10 + '%';
                star.onclick = () => {
                    userSequence.push(color);
                    star.style.opacity = '0';
                    star.style.pointerEvents = 'none';
                    if (userSequence.length === 4) {
                        document.getElementById('captcha-layer').classList.add('hidden');
                        completeHandshake();
                    }
                };
                field.appendChild(star);
                setInterval(() => { star.style.transform = `translate(${Math.random()*4-2}px, ${Math.random()*4-2}px)`; }, 100);
            }
        }

        // --- 4. VERIFY & REDIRECT ---
        async function completeHandshake() {
            const echo = CryptoJS.SHA256(currentNonce + "TOTEM_PRIME_DIRECTIVE").toString();
            try {
                const res = await fetch('/api/v1/verify', {
                    method: 'POST',
                    headers: HEADERS, 
                    body: JSON.stringify({ 
                        nonce: currentNonce, 
                        echo: echo, 
                        solution: userSequence,
                        deviceHash: myDeviceHash // <--- Sending the "Card"
                    })
                });
                
                const data = await res.json();
                
                if (data.valid) {
                    log("✅ DNA MATCH CONFIRMED.", "success");
                    log("✅ PIN ACCEPTED.", "success");
                    
                    // STORE TOKEN AND REDIRECT
                    sessionStorage.setItem('chaos_session', data.session);
                    sessionStorage.setItem('chaos_dna', myDeviceHash);
                    
                    // Redirect to Dashboard using full URL for safety
                    setTimeout(() => {
                        window.location.href = window.location.origin + '/dashboard';
                    }, 1000);

                } else {
                    log("❌ ACCESS DENIED: " + data.error, "error");
                }
            } catch(e) { log("Handshake Error", "error"); }
        }
    </script>
</body>
</html>
