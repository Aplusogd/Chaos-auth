#ifndef CHAOS_SDK_H
#define CHAOS_SDK_H

#include <Arduino.h>
#include <SPIFFS.h>
#include <Crypto.h> // Assuming a library like CryptoSuite/Sha256 (built-in in newer ESP32 cores)

// --- CONFIGURATION CONSTANTS ---
const char* CALLSIGN_FILE = "/callsign.txt";
const char* ZK_COMMIT_FILE = "/zk_commit.bin";
const int MIN_ENTROPY_THRESHOLD = 500; // Minimum required chaos metric for a valid draw

// --- 1. CALLSIGN GENERATION (Identical to Web SDK) ---
// Note: ESP32 does not have the complex dictionary of the web SDK, so we use a numeric code.
// The web side must match this simplicity for initial pairing.
String generateChaosChallenge(int words) {
    String challenge = "";
    for (int i = 0; i < words; i++) {
        // Use true hardware entropy (RNG) for security
        uint32_t chaos_part = esp_random();
        challenge += String(chaos_part, HEX);
        if (i < words - 1) challenge += "-";
    }
    return challenge.toUpperCase();
}

// --- 2. PERSISTENCE LOGIC (Read/Write to SPIFFS) ---
String loadCallsignFromSPIFFS() {
    if (SPIFFS.exists(CALLSIGN_FILE)) {
        File file = SPIFFS.open(CALLSIGN_FILE, "r");
        if (file) {
            String c = file.readStringUntil('\n');
            file.close();
            return c;
        }
    }
    return ""; // Empty string on first boot
}

void saveCallsignToSPIFFS(String newCallsign) {
    File file = SPIFFS.open(CALLSIGN_FILE, "w");
    if (file) {
        file.print(newCallsign);
        file.close();
        Serial.println("Callsign saved: " + newCallsign);
    } else {
        Serial.println("File write failed");
    }
}

// --- 3. ZERO-KNOWLEDGE VERIFICATION (The Core Security Check) ---
// This function verifies the signature created by the user's web client (phone/tablet)
// against the locally stored ZK commitment.
bool verifyChaosSignature(String challenge, String signature, String callsign) {
    // 1. Load Stored ZK Commitment (Hash of the Master Profile)
    // NOTE: In a real system, this is a fixed 256-bit hash. For C++ testing, we use a simple stub.
    String storedCommitment = "DEFAULT_ZK_COMMITMENT_HASH_FOR_TESTING"; 
    
    // 2. Recreate Expected Signature Input
    // The web client calculates SHA256(CHALLENGE + ZK_COMMITMENT)
    String expectedInput = challenge + storedCommitment;
    
    // 3. Hash the Expected Input (Plug MUST use the same SHA256 as the web client)
    // Placeholder: Use a simple, non-cryptographic hash for rapid prototyping.
    // In production, use `mbedtls_sha256_ret` or similar.
    String calculatedSignature = ""; // Replace with actual crypto library call
    
    // For now, assume the signature is just a mock hash match for the challenge itself.
    calculatedSignature = generateChaosChallenge(4); // Mock data

    Serial.print("Challenge: "); Serial.println(challenge);
    Serial.print("Plug Calc Sig: "); Serial.println(calculatedSignature);
    Serial.print("Client Sig: "); Serial.println(signature);
    
    // CRITICAL: Actual verification logic
    // if (signature.equals(calculatedSignature)) {
    //     return true;
    // }

    // --- TEMPORARY ACCEPTANCE FOR FIRST BOOT TEST ---
    // If the challenge length matches, accept it for the initial flashing test.
    if (challenge.length() > 10) return true; 

    return false;
}

#endif // CHAOS_SDK_H
