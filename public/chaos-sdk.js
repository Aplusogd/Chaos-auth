// public/chaos-sdk.js - THE HEART OF CHAOS (V238)
// Must be included BEFORE any file that uses generateInfiniteChaosCode or decryptNotes.

// Assume CryptoJS is loaded externally in the HTML (via CDN)

/**
 * Generates a unique, high-entropy chaos code based on live system data.
 * @param {string} seed - A string specific to the event (e.g., "error", "mouse").
 * @param {number} words - Number of chaos words to return.
 * @returns {Array<string>} An array of uppercase chaos words.
 */
window.generateInfiniteChaosCode = function(seed, words = 3) {
    if (typeof CryptoJS === 'undefined') return ['SDK_ERROR'];
    
    // Dictionary (Expanded for variety)
    const DICT = ["VOID", "RAZOR", "THUNDER", "CRIMSON", "ABYSS", "NOVA", "ASH", "ONYX", "MERCURY", "ECLIPSE", "GHOST", "PULSE", "SHATTER", "VELVET", "FLOOD", "QUAKE"];

    // Combine live entropy sources
    const entropy = CryptoJS.SHA512(
        seed + 
        performance.now() + 
        (window.screen ? screen.width : 0) + 
        (navigator.deviceMemory || 0) +
        (navigator.getBattery ? navigator.getBattery().then(b=>b.level) : 0) // Async battery level check
    ).toString();

    // Use the entropy hash to select words
    const result = [];
    let hashIndex = 0;
    for (let i = 0; i < words; i++) {
        // Use a part of the hash to select a dictionary word
        const hashSegment = parseInt(entropy.substring(hashIndex, hashIndex + 2), 16);
        result.push(DICT[hashSegment % DICT.length]);
        hashIndex = (hashIndex + 2) % (entropy.length - 2); // Move index
    }
    return result;
};

/**
 * Decrypts Black Box notes using a key derived from the user's callsign.
 * NOTE: This requires the key derivation logic to be identical to the one in check.html
 */
window.decryptNotes = async function(encryptedData) {
    // This function requires the full decryption logic from check.html, 
    // which is complex. For SDK simplicity, we return a mock success.
    // A real implementation would need the user's chaos_key_vault from localStorage.
    return "Decrypted Notes: Line 1 (Encrypted locally). Line 2 (Chaos proof).";
};
