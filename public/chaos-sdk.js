// public/chaos-sdk.js - THE HEART OF CHAOS (V238)

// --- FUNCTION DEFINITIONS (Must be defined globally for other files to use) ---
window.generateInfiniteChaosCode = function(seed, words = 3) {
    if (typeof CryptoJS === 'undefined') return ['SDK_ERROR'];
    
    // Dictionary and entropy generation logic (as previously provided)
    const DICT = ["VOID", "RAZOR", "THUNDER", "CRIMSON", "ABYSS", "NOVA", "ASH", "ONYX", "MERCURY", "ECLIPSE", "GHOST", "PULSE", "SHATTER", "VELVET", "FLOOD", "QUAKE"];

    // Use SHA512 hash of entropy sources to select words
    const entropy = CryptoJS.SHA512(
        seed + 
        performance.now() + 
        (window.screen ? screen.width : 0) + 
        (navigator.deviceMemory || 0)
    ).toString();

    const result = [];
    let hashIndex = 0;
    for (let i = 0; i < words; i++) {
        const hashSegment = parseInt(entropy.substring(hashIndex, hashIndex + 2), 16);
        result.push(DICT[hashSegment % DICT.length]);
        hashIndex = (hashIndex + 2) % (entropy.length - 2); 
    }
    return result;
};

// Placeholder for decryption needed by abyss-search.html
window.decryptNotes = async function(encryptedData) {
    return "Decrypted Notes: Line 1. Line 2 (Mock Decryption Success).";
};
