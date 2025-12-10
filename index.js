// --- ADD THIS TO index.js IF MISSING ---

// PUBLIC GUEST REGISTRATION (Auto-Mint Sandbox Key)
app.post('/api/auth/guest-register', (req, res) => {
    const { name, entropy } = req.body;
    
    // 1. CHAOS VERIFICATION (Simple Bot Check)
    // In a real app, we check entropy quality. 
    if (!entropy || entropy < 0.1) return res.status(400).json({ error: "BOT DETECTED" });

    // 2. MINT GUEST KEY
    const newApiKey = "sk_test_" + crypto.randomBytes(8).toString('hex');
    
    // 3. STORE IN VAULT (Sandbox Scope)
    const keyData = { 
        key: newApiKey, 
        client: name, 
        scope: "sandbox", // Limited access
        created: Date.now(), 
        device: req.headers['user-agent'] // Bind to device fingerprint roughly
    };
    
    KeyVault.set(newApiKey, keyData);
    LiveWire.broadcast('SYSTEM', `NEW GUEST REGISTERED: ${name}`);
    
    res.json({ success: true, key: newApiKey, scope: "sandbox" });
});
