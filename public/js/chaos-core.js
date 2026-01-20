/**
 * 🌀 CHAOS PROTOCOL v4.0 - OVERTHERE.AI EDITION
 * 🛡️ NightMare Defense | 🕳️ Abyss Storage | ✨ Dreams Interface
 */

class ChaosID {
    constructor(callsign) {
        this.callsign = callsign.toUpperCase();
        // 🦅 MASTER IDENTITY LOCK
        this.master = "APLUS-OGD-ADMIN"; 
        this.isAdmin = (this.callsign === this.master);
        
        this.pool = [];
        this.isReady = false;
        this.vault = JSON.parse(localStorage.getItem('ABYSS_VAULT')) || [];
        this.trust = this.isAdmin ? 100 : (parseInt(localStorage.getItem('CHAOS_TRUST')) || 50);
        
        this._initProtocols();
    }

    _initProtocols() {
        window.addEventListener('mousemove', (e) => this._harvest(e.clientX ^ e.clientY));
        window.addEventListener('keydown', (e) => this._harvest(e.keyCode));
        
        if(!this.isAdmin) {
            // Passive Reputation Decay for non-admins
            setInterval(() => this._decay(), 300000); // 5-minute intervals
        }
    }

    _harvest(data) {
        if(this.pool.length < 512) this.pool.push(data ^ Date.now());
        else this.isReady = true;
    }

    _decay() {
        this.trust = Math.max(0, this.trust - 1);
        localStorage.setItem('CHAOS_TRUST', this.trust);
    }

    async generateProof(action) {
        if (!this.isReady && !this.isAdmin) return "WAITING_FOR_ENTROPY";
        const sig = btoa(this.pool.slice(0, 5).join('')).substring(0, 12).toUpperCase();
        const token = `${this.callsign}-${action}-${sig}`;
        
        // Log to Abyss
        this.vault.push({ t: Date.now(), a: action, i: token });
        if(this.vault.length > 20) this.vault.shift();
        localStorage.setItem('ABYSS_VAULT', JSON.stringify(this.vault));
        
        return token;
    }
}
