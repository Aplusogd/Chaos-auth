/**
 * CHAOS BIO-ENGINE V261
 * Advanced Behavioral Biometrics Library
 */

class ChaosBioEngine {
    constructor() {
        this.sensorData = [];
        this.hasGyro = false;
        
        // Setup Motion Sensors (Requires Permission on iOS)
        if (typeof DeviceMotionEvent !== 'undefined') {
            this.hasGyro = true;
        }
    }

    // 1. IOS PERMISSION HANDLER (Critical!)
    async requestMotionAccess() {
        if (typeof DeviceMotionEvent !== 'undefined' && typeof DeviceMotionEvent.requestPermission === 'function') {
            try {
                const response = await DeviceMotionEvent.requestPermission();
                return response === 'granted';
            } catch (e) { return false; }
        }
        return true; // Android/Desktop usually allows by default
    }

    startMotionCapture() {
        this.sensorData = [];
        if (this.hasGyro) {
            window.addEventListener('devicemotion', this._handleMotion);
        }
    }

    stopMotionCapture() {
        if (this.hasGyro) {
            window.removeEventListener('devicemotion', this._handleMotion);
        }
        return this.sensorData;
    }

    _handleMotion = (e) => {
        // Capture simple acceleration to detect "Hand Wobble"
        if(e.accelerationIncludingGravity) {
            this.sensorData.push({
                t: Date.now(),
                x: e.accelerationIncludingGravity.x || 0,
                y: e.accelerationIncludingGravity.y || 0,
                z: e.accelerationIncludingGravity.z || 0
            });
        }
    }

    // 2. NEURO-TREMOR DETECTOR (8-12Hz)
    analyzeTremor(path) {
        if (path.length < 10) return 0;
        
        // Calculate velocity changes (jitter)
        let jitters = 0;
        for(let i=1; i<path.length-1; i++) {
            const dx1 = path[i].x - path[i-1].x;
            const dx2 = path[i+1].x - path[i].x;
            // If direction changes rapidly, it's a jitter
            if(Math.sign(dx1) !== Math.sign(dx2)) jitters++;
        }
        
        const duration = (path[path.length-1].t - path[0].t) / 1000;
        const freq = jitters / (2 * duration);
        
        // Human range is typically 4-12Hz. Bots are 0 or >20.
        // Return 1.0 (Human) or 0.0 (Bot)
        if(freq > 3 && freq < 15) return 1.0; 
        if(freq === 0) return 0.0; // Perfect smooth line = Bot
        return 0.5; // Uncertain
    }

    // 3. TWO-THIRDS POWER LAW (Biological Motion)
    analyzeBiologicalMotion(path) {
        if (path.length < 10) return 0;
        let humanScore = 0;
        let validPoints = 0;

        for (let i = 2; i < path.length - 2; i++) {
            const p1 = path[i-1];
            const p2 = path[i];
            const p3 = path[i+1];

            // Velocity
            const dt = (p2.t - p1.t) || 16;
            const dist = Math.hypot(p2.x - p1.x, p2.y - p1.y);
            const velocity = dist / dt;

            // Curvature (Approximate using 3 points)
            // k = 2 * det(p1p2, p2p3) / dist^3
            // Simplified: We just check if Slower Speed correlates with Sharper Turn
            
            // Calculate Angle Change
            const angle1 = Math.atan2(p2.y - p1.y, p2.x - p1.x);
            const angle2 = Math.atan2(p3.y - p2.y, p3.x - p2.x);
            const angleDiff = Math.abs(angle1 - angle2);

            // Biological Rule: High Angle Change should mean Low Velocity
            // If Angle is High (>0.5 rad) and Velocity is High, it's fake.
            if (angleDiff > 0.1) {
                if (velocity < 1.5) humanScore++; // Good: Slowed down for turn
                else humanScore -= 2; // Bad: High speed turn (Robotic)
            } else {
                // Straight line
                if (velocity > 0.5) humanScore++; // Good: Sped up for straight
            }
            validPoints++;
        }

        return Math.max(0, Math.min(100, (humanScore / validPoints) * 100));
    }

    // 4. DEVICE WOBBLE CHECK
    analyzeGrip(touchTime) {
        if(this.sensorData.length === 0) return 0.5; // No data (Desktop?) -> Neutral
        
        // Find motion data close to the touch event
        const nearbyMotion = this.sensorData.filter(m => Math.abs(m.t - touchTime) < 100);
        
        if(nearbyMotion.length === 0) return 0.5;

        // Calculate Variance (Wobble)
        const variance = nearbyMotion.reduce((acc, val) => acc + Math.abs(val.z - 9.8), 0) / nearbyMotion.length;

        // Humans wobble (variance > 0.05). Phones on tables/bots are steady (< 0.01).
        if(variance > 0.02) return 1.0; // Holding phone
        return 0.2; // Phone on table or Bot
    }
}
