class ChaosID {
    constructor(callsign) {
        this.callsign = callsign.toUpperCase();
        this.isAdmin = (this.callsign === "APLUS-OGD-ADMIN");
        this.pool = [];
        this.lastMove = Date.now();
        this.botScore = 0; // Nightmare Score
        this._initSentinel();
    }

    _initSentinel() {
        const gather = (e) => {
            const now = performance.now();
            const delta = now - this.lastMove;
            
            // BOT DETECTION: If movement timing is too "perfect" or repetitive
            if (delta < 5) this.botScore += 0.1; 
            else this.botScore = Math.max(0, this.botScore - 0.05);

            const noise = (e.clientX ^ e.clientY) ^ now;
            if(this.pool.length < 1024) this.pool.push(Math.floor(noise) % 256);
            this.lastMove = now;
        };
        window.addEventListener('mousemove', gather);
    }

    extractEntropy() {
        // If the Sentinel detects bot-like precision, it poisons the entropy
        if(this.botScore > 20) {
            console.error("NIGHTMARE_LOCKOUT: Non-human patterns detected.");
            return null;
        }
        if(this.pool.length < 32) return null;
        return this.pool.splice(0, 16).reduce((a, b) => a ^ b);
    }

    async generateProof(action) {
        const entropy = this.extractEntropy();
        if(!entropy) return "ERR_NIGHTMARE";
        return `${this.callsign}-${action}-${entropy.toString(16).toUpperCase()}`;
    }
}
