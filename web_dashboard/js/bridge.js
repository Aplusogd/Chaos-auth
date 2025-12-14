/**
 * CHAOS V25 BRIDGE: SERAPHIM COMMAND
 * ----------------------------------------------------
 * Core logic for connecting the Overthere.ai dashboard (Web)
 * to the Seraphim hardware (AtomS3) via the Web Serial API.
 * Manages the Heartbeat, Lockdowns, and Physical Consent Gates.
 * ----------------------------------------------------
 */

// --- GLOBAL STATE ---
let seraphimPort;
let seraphimReader;
let seraphimWriter;
let keepAliveTimer;
let consentResolver = null; // Used to await physical button press
let isLinked = false;
let lastHeartbeatTime = Date.now();

// --- UI REFERENCES (Ensure these IDs exist in dashboard.html) ---
const UI_STATUS = document.getElementById('sentry-status');
const UI_THREAT = document.getElementById('threat-alert');
const UI_CARD = document.getElementById('seraphim-card');


// =========================================================
// === 1. INITIAL HANDSHAKE & CONNECTION ===
// =========================================================

async function connectSeraphim() {
    if (isLinked) return console.log("Seraphim already active.");
    
    try {
        UI_STATUS.innerText = "PROMPTING USER...";
        
        // Request USB Device (Espressif Systems/M5Stack Vendor ID)
        seraphimPort = await navigator.serial.requestPort({ filters: [{ usbVendorId: 0x303a }] });
        await seraphimPort.open({ baudRate: 115200 });

        // Setup Streams
        const encoder = new TextEncoderStream();
        encoder.readable.pipeTo(seraphimPort.writable);
        seraphimWriter = encoder.writable.getWriter();
        
        const decoder = new TextDecoderStream();
        seraphimPort.readable.pipeTo(decoder.writable);
        seraphimReader = decoder.readable.getReader();

        // Start communication loops
        readLoop();
        startHeartbeat();

        isLinked = true;
        UI_STATUS.innerText = "🟢 ACTIVE";
        UI_THREAT.innerText = "MONITORING RF...";
        UI_CARD.style.borderLeft = '5px solid green';
        
        console.log("CHAOS SOUL LINK ESTABLISHED");
        
    } catch (err) {
        UI_STATUS.innerText = "🔴 FAILED";
        UI_THREAT.innerText = "PLUG IN ATOM S3";
        UI_CARD.style.borderLeft = '5px solid red';
        console.error("Connection Failed:", err);
    }
}


// =========================================================
// === 2. HEARTBEAT & DEAD MAN'S SWITCH ===
// =========================================================

function startHeartbeat() {
    // Ping Atom every 1 second
    keepAliveTimer = setInterval(async () => {
        if(seraphimWriter) {
            await seraphimWriter.write("PING\n");
        }
    }, 1000); 
    
    // Safety Check: If Atom is silent for 3.5 seconds, lock.
    setInterval(checkHeartbeat, 3500); 
}

function checkHeartbeat() {
    if (isLinked && Date.now() - lastHeartbeatTime > 3500) {
        // Seraphim is unplugged or crashed. Must terminate session.
        emergencyLock("CONNECTION SEVERED (TIMEOUT)");
    }
}


// =========================================================
// === 3. DATA PARSER & LOCKDOWN LOGIC ===
// =========================================================

async function readLoop() {
    try {
        while (true) {
            const { value, done } = await seraphimReader.read();
            if (done) break;
            if (value) parseSeraphim(value);
        }
    } catch (error) {
        console.error("Read Loop Error:", error);
        emergencyLock("COMMUNICATION ERROR");
    }
}

function parseSeraphim(data) {
    const msg = data.trim();
    
    // 1. PONG/HEARTBEAT (Signal that the Sentry is alive)
    if (msg.includes("PONG:")) {
        lastHeartbeatTime = Date.now();
        UI_STATUS.style.color = 'lightgreen';
        UI_STATUS.innerText = "🟢 ACTIVE";
        UI_THREAT.innerText = "CLEAN";
    }
    
    // 2. LOCKDOWN SIGNAL (RF Threat detected in the room)
    if (msg.includes("LOCK:")) {
        const threat = msg.split(":")[1];
        UI_THREAT.innerText = `🔴 ${threat}`;
        emergencyLock(`RF THREAT: ${threat}`);
    }

    // 3. CONSENT RESOLUTION (Physical Button Press)
    if (msg.includes("AUTHORIZED")) {
        if (consentResolver) consentResolver(true); // RESOLVE SUCCESS
        consentResolver = null;
    }
    if (msg.includes("DENIED:UNSAFE_ENV")) {
        if (consentResolver) consentResolver(false); // RESOLVE FAILURE
        consentResolver = null;
    }
}


// =========================================================
// === 4. PUBLIC FACING GATES & LOCKDOWN ===
// =========================================================

// Called by Wallet Lock and File Lock buttons in dashboard.html
async function requestSecureAction(actionType) {
    if (!isLinked) {
        alert("SECURITY PROTOCOL: Seraphim hardware connection required.");
        return false;
    }
    
    UI_THREAT.innerText = `CONFIRMING ${actionType.toUpperCase()}... (PRESS ATOM)`;
    
    // 1. Send CONSENT command (Atom enters Blue Mode)
    await seraphimWriter.write("CONSENT\n");
    
    // 2. Wait for physical confirmation (resolved in parseSeraphim)
    const authorized = await new Promise(resolve => {
        consentResolver = resolve;
    });
    
    UI_THREAT.innerText = "CLEAN"; // Reset visual
    
    if (authorized) {
        alert(`SUCCESS! ${actionType.toUpperCase()} GATED BY PHYSICAL KEY.`);
        return true;
    } else {
        alert(`ACTION BLOCKED! ${actionType.toUpperCase()} DENIED BY SERAPHIM.`);
        return false;
    }
}


function emergencyLock(reason) {
    isLinked = false;
    clearInterval(keepAliveTimer);
    if(seraphimReader) seraphimReader.cancel();
    
    // VISUAL LOCKDOWN (Takes over the whole screen)
    document.body.innerHTML = `
        <div style="background:#000; color:red; height:100vh; display:flex; 
             flex-direction:column; justify-content:center; align-items:center; 
             font-family:monospace; text-align:center;">
            <h1>🚫 PROTOCOL OMEGA ACTIVATED</h1>
            <h2>THREAT: ${reason}</h2>
            <p>Your Seraphim detected a hostile environment or the link was broken.</p>
            <button onclick="window.location.reload()" style="padding:20px; font-size:20px; background:red; color:white; border:1px solid white; cursor:pointer;">REBOOT DASHBOARD</button>
        </div>
    `;
}

// =========================================================
// === BINDINGS (Exposed to dashboard.html) ===
// =========================================================

// Bind the Connect Button
document.getElementById('connect-seraphim-btn').onclick = connectSeraphim;

// Bind the Secure Gate Buttons
document.getElementById('wallet-transfer-btn').onclick = async () => {
    const success = await requestSecureAction("WALLET TRANSFER");
    if (success) { /* PLACE WALLET EXECUTION CODE HERE */ }
};

document.getElementById('file-transfer-btn').onclick = async () => {
    const success = await requestSecureAction("FILE TRANSFER");
    if (success) { /* PLACE FILE TRANSFER EXECUTION CODE HERE */ }
};
