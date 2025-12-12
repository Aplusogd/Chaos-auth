/**
 * CHAOS BIO-ENGINE V262 (DNA EDITION)
 * Advanced Behavioral Profiling
 */

class ChaosBioEngine {
    constructor() {
        this.sensorData = [];
        this.hasGyro = false;
        if (typeof DeviceMotionEvent !== 'undefined') this.hasGyro = true;
    }

    // ... (Previous Motion Sensor Code remains the same) ...
    async requestMotionAccess() { /* ... Same as V261 ... */ return true; }
    startMotionCapture() { /* ... Same as V261 ... */ }
    stopMotionCapture() { /* ... Same as V261 ... */ }
    analyzeTremor(path) { /* ... Same as V261 ... */ return 1.0; }
    analyzeBiologicalMotion(path) { /* ... Same as V261 ... */ return 80; }
    analyzeGrip(t) { /* ... Same as V261 ... */ return 1.0; }

    // --- NEW: BEHAVIORAL DNA EXTRACTION ---

    /**
     * EXTRACT DNA
     * Creates a unique signature of HOW the user draws.
     */
    extractDNA(path) {
        if (path.length < 10) return null;

        // 1. WINDING DIRECTION (Clockwise vs Counter-Clockwise)
        // Calculated using the "Shoelace Formula" (Signed Area)
        let sum = 0;
        for (let i = 0; i < path.length - 1; i++) {
            sum += (path[i+1].x - path[i].x) * (path[i+1].y + path[i].y);
        }
        // sum > 0 = Counter-Clockwise, sum < 0 = Clockwise
        const direction = sum > 0 ? 1 : -1;

        // 2. VELOCITY PROFILE (Acceleration Heatmap)
        // We measure speed at 3 checkpoints: Start (10%), Middle (50%), End (90%)
        const speeds = [];
        for (let i = 1; i < path.length; i++) {
            const dt = path[i].t - path[i-1].t || 16;
            const dist = Math.hypot(path[i].x - path[i-1].x, path[i].y - path[i-1].y);
            speeds.push(dist / dt);
        }
        
        const p10 = speeds[Math.floor(speeds.length * 0.1)] || 0;
        const p50 = speeds[Math.floor(speeds.length * 0.5)] || 0;
        const p90 = speeds[Math.floor(speeds.length * 0.9)] || 0;

        // 3. SHARPNESS (Cornering Habit)
        // Do they round corners or stop? (Average Change in Angle)
        let angleChange = 0;
        for (let i = 1; i < path.length - 1; i++) {
            const a1 = Math.atan2(path[i].y - path[i-1].y, path[i].x - path[i-1].x);
            const a2 = Math.atan2(path[i+1].y - path[i].y, path[i+1].x - path[i].x);
            angleChange += Math.abs(a1 - a2);
        }
        const sharpness = angleChange / path.length;

        return {
            direction: direction, 
            velocity: [p10, p50, p90],
            sharpness: sharpness
        };
    }

    /**
     * COMPARE DNA
     * Returns a match score (0-100) between two profiles.
     */
    compareDNA(masterDNA, loginDNA) {
        if (!masterDNA || !loginDNA) return 0;

        // 1. DIRECTION CHECK (Critical Fail)
        // If you calibrated Clockwise but drew Counter-Clockwise, it's NOT you.
        if (masterDNA.direction !== loginDNA.direction) {
            console.warn("⛔ DNA MISMATCH: Wrong Winding Direction");
            return 0; // Instant Fail
        }

        // 2. VELOCITY MATCH
        // Compare the rhythm (Start/Mid/End speeds)
        let speedScore = 0;
        for(let i=0; i<3; i++) {
            const ratio = Math.min(masterDNA.velocity[i], loginDNA.velocity[i]) / Math.max(masterDNA.velocity[i], loginDNA.velocity[i]);
            speedScore += ratio || 0;
        }
        speedScore /= 3; // Normalize 0-1

        // 3. SHARPNESS MATCH
        const sharpRatio = Math.min(masterDNA.sharpness, loginDNA.sharpness) / Math.max(masterDNA.sharpness, loginDNA.sharpness);

        // WEIGHTED TOTAL
        // Velocity (Rhythm) is 60%, Sharpness (Style) is 40%
        return Math.floor((speedScore * 0.6 + sharpRatio * 0.4) * 100);
    }
}
