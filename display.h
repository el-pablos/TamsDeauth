#ifndef DISPLAY_H
#define DISPLAY_H

#include <Arduino.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include "config.h"

// ============================================================
// TamsDeauth v1.0.0 — SSD1306 OLED Display & Menu System
//
// 128×64 I2C display at address 0x3C.
// Handles: boot logo, main menu, scan-result listing,
// action/info screens, OLED timeout, TinyJoyPad minigame,
// and framebuffer capture for web virtual-display streaming.
//
// ScanResult / scanResults[] / scanResultCount are defined in
// config.h / attacks.h and extern'd here.
// ============================================================

// Display hardware constants
#define OLED_ADDR          0x3C
#define OLED_WIDTH         128
#define OLED_HEIGHT        64
#define OLED_BUFFER_SIZE   (OLED_WIDTH * OLED_HEIGHT / 8)  // 1024 bytes

// Layout
#define MENU_HEADER_Y      0
#define MENU_ITEM_START_Y  10
#define MENU_LINE_HEIGHT   10
#define MENU_VISIBLE_ITEMS 5

// --- Display object (global, used by main sketch + webserver) ---
Adafruit_SSD1306 display(OLED_WIDTH, OLED_HEIGHT, &Wire, -1);

// Framebuffer mirror for virtual-display HTTP streaming
uint8_t oledBuffer[OLED_BUFFER_SIZE];

// Virtual button from web interface (-1 = none; 1=up,2=right,3=down,4=left,5=confirm,6=back)
extern int8_t virtualButton;

// --- Scan results (defined in attacks.h) ---
extern ScanResult scanResults[];
extern int scanResultCount;

// ============================================================
// Menu item definitions — extracted from firmware strings.
// Order matches the original OLED main menu.
// ============================================================

enum MenuItemID {
  MENU_SCAN_NETWORK = 0,
  MENU_SELECT_NETWORK,
  MENU_STATION,
  MENU_TARGET,
  MENU_DEAUTH,
  MENU_DEAUTH_ALL,
  MENU_PRECISE_DEAUTH,
  MENU_TRUE_DEAUTH,
  MENU_EVIL_TWIN,
  MENU_ROGUE_AP,
  MENU_BEACON_SPAM,
  MENU_HIDE_SOFTAP,
  MENU_DDOS_ROUTER,
  MENU_COUNT_STATIONS,
  MENU_OBSERVE_STATIONS,
  MENU_DEAUTH_MONITOR,
  MENU_VIEW_LOGS,
  MENU_TINYJOYPAD,
  MENU_RESTART,
  MENU_COUNT
};

static const char* menuLabels[] = {
  "Scan Network",
  "Select Network",
  "Station",
  "Target",
  "Deauth",
  "Deauth All",
  "Precise Deauth",
  "True Deauth",
  "Evil-Twin",
  "Rogue AP",
  "Beacon Spam",
  "Hide SoftAP",
  "DDoS Router",
  "Count Stations",
  "Observe Stations",
  "Deauth Monitor",
  "View logs",
  "TinyJoyPad",
  "Restart"
};

static const char* menuDescriptions[] = {
  "Select a target network",
  "",
  "",
  "Select target",
  "Disconnect target(s) from clients",
  "Disconnect all visible targets",
  "Send specialized deauth packet",
  "Send deauth packet in real-time",
  "Start an Evil Twin attack on target",
  "Start a Rogue Access Point",
  "Start Beacon Spam",
  "Hide TamsDeauth SSID",
  "Overload router CPU with packets",
  "Count clients on selected target",
  "Count clients on all targets",
  "Detect deauth attacks",
  "Open activity log",
  "Play minigames",
  "Restart the device"
};

// --- Menu navigation state ---
int  menuIndex     = 0;
int  menuTop       = 0;     // scroll offset
int  currentScreen = 0;     // 0=main menu, 1=scan results, 2=action
bool displayOn     = true;
uint32_t lastDisplayActivity = 0;

// Action screen state
String   actionMessage = "";
bool     inActionScreen = false;
uint32_t actionStartTime = 0;

// Attack screen live data (updated by handleAttacks)
const char* attackScreenName = "";
uint32_t*   attackScreenCounter = nullptr;

// TinyJoyPad minigame state
bool     inGame = false;
int      gameScore = 0;
uint8_t  playerX = 64, playerY = 32;
uint8_t  targetX = 32, targetY = 16;
uint8_t  gameDir = 0; // 0=right,1=down,2=left,3=up
uint32_t lastGameUpdate = 0;

// Forward declaration — implemented in main .ino
extern void handleMenuConfirm();

// ============================================================
// Boot logo — TamsDeauth branding with version string
// ============================================================
void drawBootLogo() {
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);

  display.setTextSize(2);
  display.setCursor(10, 4);
  display.println(F("TamsDeauth"));

  display.setTextSize(1);
  display.setCursor(35, 24);
  display.println(F("v1.0.0"));

  display.setCursor(45, 36);
  display.println(F("TamsDeauth"));

  display.drawLine(10, 48, 118, 48, SSD1306_WHITE);

  display.setCursor(12, 53);
  display.println(F("WiFi Pentesting Tool"));

  display.display();
  delay(1500);
}

// ============================================================
// Capture OLED framebuffer into oledBuffer for virtual display
// ============================================================
void captureOledBuffer() {
  memcpy(oledBuffer, display.getBuffer(), OLED_BUFFER_SIZE);
}

// ============================================================
// Main menu renderer — 5 items visible, scrollable
// ============================================================
void drawMainMenu() {
  display.clearDisplay();

  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, MENU_HEADER_Y);
  display.println(F("MAIN MENU"));
  display.drawLine(0, 9, 127, 9, SSD1306_WHITE);

  int maxTop = MENU_COUNT - MENU_VISIBLE_ITEMS;
  if (maxTop < 0) maxTop = 0;
  if (menuTop > maxTop) menuTop = maxTop;
  if (menuTop < 0) menuTop = 0;

  for (int i = 0; i < MENU_VISIBLE_ITEMS && (menuTop + i) < MENU_COUNT; i++) {
    int idx = menuTop + i;
    int y = MENU_ITEM_START_Y + (i * MENU_LINE_HEIGHT);

    if (idx == menuIndex) {
      display.fillRect(0, y - 1, 127, MENU_LINE_HEIGHT, SSD1306_WHITE);
      display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
    } else {
      display.setTextColor(SSD1306_WHITE);
    }
    display.setCursor(2, y);
    display.print(menuLabels[idx]);
  }

  // Scroll indicators
  display.setTextColor(SSD1306_WHITE);
  if (menuTop > 0) { display.setCursor(122, 10); display.write(0x18); }
  if (menuTop < maxTop) { display.setCursor(122, 52); display.write(0x19); }

  // Target info footer
  display.setCursor(0, 56);
  if (strlen(cfg.target_ssid) > 0) {
    display.print(F("T:"));
    display.print(cfg.target_ssid);
  } else {
    display.print(F("No target selected"));
  }

  display.display();
}

// ============================================================
// Scan results list (for "Select Network")
// ============================================================
void drawScanResults() {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.println(F("-- SCAN NETWORK --"));

  if (scanResultCount == 0) {
    display.setCursor(0, 20);
    display.println(F("No networks found"));
    display.setCursor(0, 36);
    display.println(F("Run Scan first"));
    display.display();
    return;
  }

  int visible = MENU_VISIBLE_ITEMS;
  int maxTop = scanResultCount - visible;
  if (maxTop < 0) maxTop = 0;
  if (menuTop > maxTop) menuTop = maxTop;
  if (menuIndex >= scanResultCount) menuIndex = scanResultCount - 1;
  if (menuIndex < 0) menuIndex = 0;

  for (int i = 0; i < visible && (menuTop + i) < scanResultCount; i++) {
    int idx = menuTop + i;
    int y = MENU_ITEM_START_Y + (i * MENU_LINE_HEIGHT);

    if (idx == menuIndex) {
      display.fillRect(0, y - 1, 127, MENU_LINE_HEIGHT, SSD1306_WHITE);
      display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
    } else {
      display.setTextColor(SSD1306_WHITE);
    }
    display.setCursor(2, y);
    char tmp[20];
    strncpy(tmp, scanResults[idx].ssid, 16);
    tmp[16] = '\0';
    display.print(tmp);

    display.setCursor(108, y);
    display.print(scanResults[idx].channel);
  }

  display.display();
}

// ============================================================
// Action / info screen with word-wrapped message
// ============================================================
void drawActionScreen(const String& msg) {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);

  int col = 0, row = 0;
  display.setCursor(0, 0);
  for (unsigned i = 0; i < msg.length(); i++) {
    if (msg[i] == '\n' || col >= 21) {
      col = 0; row++;
      if (row >= 6) break;
      display.setCursor(0, row * 9);
      if (msg[i] == '\n') continue;
    }
    display.print(msg[i]);
    col++;
  }

  display.setCursor(0, 57);
  display.println(F("Press BACK to exit"));
  display.display();
}

// ============================================================
// Attack running screen with live packet counter
// ============================================================
void drawAttackScreen(const char* name, uint32_t count) {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);

  display.setCursor(0, 0);
  display.println(name);

  display.setCursor(0, 14);
  display.print(F("Packets: "));
  display.println(count);

  display.setCursor(0, 26);
  display.print(F("Target: "));
  if (strlen(cfg.target_ssid) > 0)
    display.println(cfg.target_ssid);
  else
    display.println(F("All"));

  display.setCursor(0, 38);
  display.print(F("CH: "));
  display.println(cfg.target_ch ? cfg.target_ch : 1);

  display.setCursor(0, 57);
  display.println(F("BACK to stop"));
  display.display();
}

// ============================================================
// TinyJoyPad minigame — simple dot-chase
// ============================================================
void drawGame() {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);

  display.drawPixel(playerX, playerY, SSD1306_WHITE);
  display.drawCircle(targetX, targetY, 2, SSD1306_WHITE);

  display.setCursor(0, 0);
  display.print(F("Score:"));
  display.print(gameScore);

  display.setCursor(95, 0);
  display.print(F("BACK=exit"));
  display.display();
}

void updateGame() {
  // Check if player caught target
  if (abs((int)playerX - (int)targetX) < 4 &&
      abs((int)playerY - (int)targetY) < 4) {
    gameScore++;
    targetX = random(4, 124);
    targetY = random(4, 60);
  }
}

// ============================================================
// Wake display from sleep
// ============================================================
void wakeDisplay() {
  if (!displayOn) {
    displayOn = true;
    display.ssd1306_command(SSD1306_DISPLAYON);
  }
  lastDisplayActivity = millis();
}

// ============================================================
// OLED bridge helpers — used by attacks.h / sniffer.h
// ============================================================
void updateOLED(int line, const char* text) {
  wakeDisplay();
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, line * 12);
  display.print(text);
  display.display();
  lastDisplayActivity = millis();
}

void updateOLEDStatus(const char* status) {
  Serial.printf("[OLED] %s\n", status);
}

// ============================================================
// Main display update — called from loop()
// ============================================================
void updateDisplay() {
  // OLED timeout — sleep after idle
  if (displayOn && cfg.OLED_Timeout > 0 &&
      millis() - lastDisplayActivity > cfg.OLED_Timeout) {
    display.clearDisplay();
    display.display();
    display.ssd1306_command(SSD1306_DISPLAYOFF);
    displayOn = false;
    return;
  }
  if (!displayOn) return;

  if (inGame) {
    if (millis() - lastGameUpdate > 100) {
      updateGame();
      drawGame();
      lastGameUpdate = millis();
    }
    return;
  }

  if (inActionScreen) {
    // Action screens can show live attack counters
    if (attackScreenCounter != nullptr) {
      drawAttackScreen(attackScreenName, *attackScreenCounter);
    }
    return;
  }

  if (currentScreen == 0) {
    drawMainMenu();
  } else if (currentScreen == 1) {
    drawScanResults();
  }
}

// ============================================================
// Menu navigation handlers
// ============================================================
void menuUp() {
  wakeDisplay();
  if (inGame) { playerY = max(0, playerY - 3); return; }
  if (inActionScreen) return;

  if (currentScreen == 0) {
    menuIndex--;
    if (menuIndex < 0) menuIndex = MENU_COUNT - 1;
    if (menuIndex < menuTop) menuTop = menuIndex;
    else if (menuIndex >= menuTop + MENU_VISIBLE_ITEMS)
      menuTop = menuIndex - MENU_VISIBLE_ITEMS + 1;
  } else if (currentScreen == 1) {
    if (scanResultCount > 0) {
      menuIndex--;
      if (menuIndex < 0) menuIndex = scanResultCount - 1;
      if (menuIndex < menuTop) menuTop = menuIndex;
      else if (menuIndex >= menuTop + MENU_VISIBLE_ITEMS)
        menuTop = menuIndex - MENU_VISIBLE_ITEMS + 1;
    }
  }
}

void menuDown() {
  wakeDisplay();
  if (inGame) { playerY = min(63, playerY + 3); return; }
  if (inActionScreen) return;

  if (currentScreen == 0) {
    menuIndex++;
    if (menuIndex >= MENU_COUNT) menuIndex = 0;
    if (menuIndex >= menuTop + MENU_VISIBLE_ITEMS)
      menuTop = menuIndex - MENU_VISIBLE_ITEMS + 1;
    else if (menuIndex < menuTop) menuTop = 0;
  } else if (currentScreen == 1) {
    if (scanResultCount > 0) {
      menuIndex++;
      if (menuIndex >= scanResultCount) menuIndex = 0;
      if (menuIndex >= menuTop + MENU_VISIBLE_ITEMS)
        menuTop = menuIndex - MENU_VISIBLE_ITEMS + 1;
    }
  }
}

void menuConfirm() {
  wakeDisplay();
  if (inGame) {
    // In game, confirm does nothing special
    return;
  }
  if (inActionScreen) return;
  handleMenuConfirm();
}

void menuBack() {
  wakeDisplay();
  if (inGame) {
    inGame = false;
    gameScore = 0;
    currentScreen = 0;
    return;
  }
  if (inActionScreen) {
    inActionScreen = false;
    attackScreenCounter = nullptr;
    currentScreen = 0;
    return;
  }
  if (currentScreen == 1) {
    currentScreen = 0;
    menuIndex = MENU_SELECT_NETWORK;
    return;
  }
  // In main menu — BACK could turn display off
}

// Show an action/info screen
void showActionScreen(const String& msg) {
  actionMessage = msg;
  inActionScreen = true;
  actionStartTime = millis();
  attackScreenCounter = nullptr;
  drawActionScreen(msg);
}

// Show an attack running screen with live counter
void showAttackScreen(const char* name, uint32_t* counter) {
  inActionScreen = true;
  attackScreenName = name;
  attackScreenCounter = counter;
  actionStartTime = millis();
}

// ============================================================
// Initialise OLED hardware
// ============================================================
bool initDisplay() {
  Wire.begin();  // SDA=GPIO4, SCL=GPIO5
  if (!display.begin(SSD1306_SWITCHCAPVCC, OLED_ADDR)) {
    Serial.println(F("[OLED] SSD1306 init FAILED"));
    return false;
  }
  display.clearDisplay();
  display.display();
  display.setTextColor(SSD1306_WHITE);
  displayOn = true;
  lastDisplayActivity = millis();
  Serial.println(F("[OLED] SSD1306 initialized (128x64 @ 0x3C)"));
  return true;
}

#endif // DISPLAY_H
