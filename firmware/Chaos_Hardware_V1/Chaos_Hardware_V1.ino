#include <M5AtomS3.h>

// Pointing to your specific Render URL for verification
const String VERIFY_URL = "https://chaos-auth.onrender.com/verify.html"; 
String call_sign = ""; 
int current_mode = 1; 

void setup() {
    auto cfg = M5.config();
    M5.begin(cfg);
    M5.Lcd.setRotation(1);
    M5.Lcd.setBrightness(200);
    
    // Generate Identity from Mac Address
    uint64_t chipid = ESP.getEfuseMac();
    call_sign = String((uint32_t)chipid, HEX);
    call_sign.toUpperCase();

    generateToken();
}

void loop() {
    M5.update();
    if (M5.BtnA.wasReleased()) generateToken();
    if (M5.BtnA.pressedFor(1000)) changeMode();
}

void changeMode() {
    current_mode++;
    if (current_mode > 3) current_mode = 1;
    generateToken();
}

void generateToken() {
    uint32_t entropy = esp_random();
    String hexEntropy = String(entropy, HEX);
    hexEntropy.toUpperCase();

    String action = "REV";
    if(current_mode == 2) action = "VOT";
    if(current_mode == 3) action = "CHK";

    String token = call_sign + "-" + action + "-" + hexEntropy;
    String qrUrl = VERIFY_URL + "?t=" + token;

    if(current_mode == 1) M5.Lcd.fillScreen(GREEN);
    if(current_mode == 2) M5.Lcd.fillScreen(BLUE);
    if(current_mode == 3) M5.Lcd.fillScreen(YELLOW);
    delay(200);
    M5.Lcd.fillScreen(WHITE);

    M5.Lcd.setTextColor(BLACK);
    M5.Lcd.setTextSize(1);
    M5.Lcd.setCursor(5,5);
    M5.Lcd.print("ID: " + call_sign);
    
    M5.Lcd.qrcode(qrUrl.c_str(), 10, 20, 108, 3);
}
