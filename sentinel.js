/**
 * A+ SENTINEL SDK (V1.0)
 * "The Invisible Captcha"
 * Analyzes Kinetic Entropy of user input to distinguish Humans from Bots.
 */

const Sentinel = {
    buffer: [],
    score: 100, // Starts at 100 (Human), drops if robotic
    lastY: 0,
    lastT: 0,

    init: () => {
        window.addEventListener('scroll', Sentinel.analyze);
        console.log(">>> [SENTINEL] WATCHING SCROLL PATTERNS");
    },

    analyze: (e) => {
        const now = Date.now();
        const y = window.scrollY;
        
        // 1. Calculate Velocity (Pixels per ms)
        const dt = now - Sentinel.lastT;
        const dy = y - Sentinel.lastY;
        
        if (dt > 0 && Math.abs(dy) > 0) {
            const velocity = Math.abs(dy / dt);
            
            // 2. Add to Rolling Buffer (Keep last 20 movements)
            Sentinel.buffer.push(velocity);
            if(Sentinel.buffer.length > 20) Sentinel.buffer.shift();
            
            // 3. Calculate Entropy (Variance)
            const variance = Sentinel.calculateVariance(Sentinel.buffer);
            
            // 4. Judgment Logic
            // Bots have variance near 0 (Perfect speed).
            // Humans have variance > 0.5 (Messy speed).
            if(Sentinel.buffer.length > 10) {
                if(variance < 0.05) {
                    Sentinel.score = Math.max(0, Sentinel.score - 5); // ROBOTIC
                } else {
                    Sentinel.score = Math.min(100, Sentinel.score + 1); // HUMAN
                }
            }

            // 5. Broadcast for UI (Demo purposes)
            window.dispatchEvent(new CustomEvent('sentinel-update', { 
                detail: { score: Sentinel.score, variance: variance, velocity: velocity }
            }));
        }

        Sentinel.lastY = y;
        Sentinel.lastT = now;
    },

    calculateVariance: (arr) => {
        const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
        return arr.reduce((sq, n) => sq + Math.pow(n - mean, 2), 0) / arr.length;
    }
};

Sentinel.init();
