class ChaosEngine {
    constructor(callsign) {
        this.callsign = callsign.toUpperCase();
        this.isAdmin = (this.callsign === "APLUS-OGD-ADMIN");
        this.fingerprint = btoa(navigator.userAgent).substring(0, 8).toUpperCase();
        this.entropy = [];
        this._initReputation();
        this._captureEntropy();
    }

    _initReputation() {
        // Retrieve or Initialize Trust Score
        let score = localStorage.getItem('CHAOS_TRUST_SCORE');
        if (!score) {
            score = this.isAdmin ? 100 : 50; // Master starts at 100, Users at 50
            localStorage.setItem('CHAOS_TRUST_SCORE', score);
        }
        this.trustScore = parseInt(score);
    }

    _captureEntropy() {
        window.addEventListener('mousemove', (e) => {
            if(this.entropy.length < 200) this.entropy.push(e.clientX ^ e.clientY);
        });
    }

    generateProof(action) {
        if (this.trustScore < 20) return "DENIED: LOW_TRUST";
        
        const random = Math.floor(Math.random() * 16777215).toString(16).toUpperCase();
        const token = `${this.callsign}-${action}-${random}`;
        
        // Reward: Successful generation increases trust slightly
        if (!this.isAdmin) this.updateTrust(1); 
        
        return token;
    }

    updateTrust(delta) {
        this.trustScore = Math.min(100, Math.max(0, this.trustScore + delta));
        localStorage.setItem('CHAOS_TRUST_SCORE', this.trustScore);
        return this.trustScore;
    }
}
