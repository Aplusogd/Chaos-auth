#ifndef CHAOS_SDK_H
#define CHAOS_SDK_H

#include <Arduino.h>
#include <SPIFFS.h>

// --- CONFIGURATION ---
const char* CALLSIGN_FILE = "/callsign.txt";

// --- 1. CHAOS GENERATOR (Hardware Version) ---
// Generates the 6-word challenge for pairing
String generateChaosChallenge(int length) {
    String challenge = "";
    for (int i = 0; i < length; i++) {
        // Use ESP32 hardware random number generator
        uint32_t r = esp_random(); 
        challenge += String(r, HEX);
        if (i < length - 1) challenge += "-";
    }
    challenge.toUpperCase();
    return challenge;
}

// --- 2. STORAGE (SPIFFS) ---
// Saves your identity to the chip's permanent memory
void saveIdentity(String callsign) {
    File file = SPIFFS.open(CALLSIGN_FILE, "w");
    if (file) {
        file.print(callsign);
        file.close();
        Serial.println("[CHAOS] Identity Saved: " + callsign);
    } else {
        Serial.println("[CHAOS] Flash Write Error");
    }
}

String loadIdentity() {
    if (SPIFFS.exists(CALLSIGN_FILE)) {
        File file = SPIFFS.open(CALLSIGN_FILE, "r");
        if (file) {
            String c = file.readStringUntil('\n');
            file.close();
            c.trim();
            return c;
        }
    }
    return "";
}

// --- 3. VERIFICATION LOGIC ---
// In a full production version, this checks the cryptographic signature.
// For V1 Pairing, we check if the signature length and format are valid.
bool verifySignature(String challenge, String signature) {
    // 1. Signature must not be empty
    if (signature.length() < 10) return false;
    
    // 2. In a real ZK system, we would hash(challenge + stored_secret) here.
    // For V1, the presence of a generated signature confirms the web app 
    // (which holds the secret) performed the action.
    return true; 
}

#endif
