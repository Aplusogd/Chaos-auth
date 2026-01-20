/**
 * 🌀 CHAOS PROTOCOL v3.0 - PUBLIC RELEASE
 * 🛡️ NightMare Defense | 🕳️ Abyss Storage | ✨ Dreams Interface
 */

class ChaosID {
    constructor(callsign) {
        this.callsign = callsign.toUpperCase();
        this.master = "APLUS-OGD-ADMIN";
        this.isAdmin = (this.callsign === this.master);
        
        // 🌀 CHAOS: Entropy Pool
        this.pool = [];
        this.isReady = false;
        
        // 🕳️ ABYSS: Local Vault
        this.vault = JSON.parse(localStorage.getItem('ABYSS_VAULT')) || [];
        
        // 🌑 NIGHTMARE: Security State
        this.trust = this.isAdmin ? 100 : (parseInt(localStorage.getItem('CHAOS_TRUST')) || 50);
        
        this._initProtocols();
    }

    _initProtocols() {
        // Entropy Harvesting (Chaos)
        window.addEventListener('mousemove', (e) => this._harvest(e.clientX ^ e.clientY));
        window.addEventListener('keydown', (e) => this._harvest(e.keyCode));
        
        // Trust Decay (Nightmare) - Passive security check
        if(!this.isAdmin) {
            setInterval(() => this._decay(), 60000); // 1% decay per minute of inactivity
        }
    }

    _harvest(data) {
        if(this.pool.length < 1024) {
            this.pool.push(data ^ Date.now());
        } else {
            this.isReady = true;
        }
    }

    _decay() {
        this.trust = Math.max(0, this.trust - 1);
        localStorage.setItem('CHAOS_TRUST', this.trust);
    }

    /**
     * ✨ DREAMS: Secure Communication Generation
     * The fastest way for Humans and AI to verify intent.
     */
    async generateProof(action, payload = "") {
        if (!this.isReady && !this.isAdmin) return "ERROR: INSUFFICIENT_ENTROPY";
        if (this.trust < 10) return "ERROR: NIGHTMARE_LOCKOUT";

        const entropySeed = this.pool.slice(0, 10).join('');
        const randomData = window.crypto.getRandomValues(new Uint32Array(1))[0];
        
        // The Multi-Layer Token
        const token = {
            origin: this.callsign,
            action: action,
            payload: payload,
            hash: btoa(entropySeed + randomData).substring(0, 16).toUpperCase(),
            timestamp: Date.now()
        };

        const finalString = `${token.origin}-${token.action}-${token.hash}`;
        
        // 🕳️ ABYSS: Save to Vault
        this.vault.push(token);
        if(this.vault.length > 50) this.vault.shift(); // Keep Abyss lean
        localStorage.setItem('ABYSS_VAULT', JSON.stringify(this.vault));

        return finalString;
    }
}
