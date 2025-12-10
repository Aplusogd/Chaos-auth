// --- UPGRADED SENTINEL VERIFICATION (With Reputation Ramp) ---
app.post('/api/v1/sentinel/verify', (req, res) => {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey || !KeyVault.has(apiKey)) return res.status(401).json({ error: "INVALID_KEY" });

    const keyData = KeyVault.get(apiKey);
    
    // --- 1. CALCULATE REPUTATION AGE ---
    const now = Date.now();
    const ageDays = (now - keyData.created) / (1000 * 60 * 60 * 24);
    
    let rank = "NEWBORN";
    let limit = 10; // Requests per minute (Example)

    if (keyData.scope === 'full-access') {
        rank = "GOD_MODE";
        limit = 999999;
    } else {
        if (ageDays >= 30) { rank = "IMMORTAL"; limit = 9999; }
        else if (ageDays >= 14) { rank = "VETERAN"; limit = 300; }
        else if (ageDays >= 3) { rank = "SURVIVOR"; limit = 60; }
    }

    // --- 2. RATE LIMIT CHECK (Based on Rank) ---
    if (!RateLimit.has(apiKey)) RateLimit.set(apiKey, []);
    let usage = RateLimit.get(apiKey).filter(t => t > now - 60000); // Last minute

    if (usage.length >= limit) {
        LiveWire.broadcast('BLOCK', { reason: 'RATE_LIMIT', rank: rank });
        return res.status(429).json({ error: "RATE_LIMIT_EXCEEDED", rank, retryAfter: "60s" });
    }

    usage.push(now);
    RateLimit.set(apiKey, usage);
    
    // --- 3. SUCCESS ---
    LiveWire.broadcast('TRAFFIC', { status: 'VERIFIED', project: keyData.client, rank: rank });
    res.json({ 
        valid: true, 
        trustScore: 100, 
        rank: rank, 
        daysAlive: ageDays.toFixed(2),
        limit: limit + "/min"
    });
});
