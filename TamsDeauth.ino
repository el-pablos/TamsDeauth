/*
 * ================================================================
 *  TamsDeauth v3.8.1 Clone — Main Arduino ESP8266 Sketch
 *  ^~3.8.1~^  Codename: TamsDeauth
 *
 *  A 1:1 functional reconstruction of the TamsDeauth WiFi
 *  pentesting firmware for ESP8266 (4 MB flash).
 *
 *  Hardware:
 *    ESP8266 (NodeMCU / Wemos D1 Mini)   — 4 MB flash
 *    SSD1306 OLED 128×64                 — I²C addr 0x3C
 *    Button UP      = GPIO 14 (D5)       — INPUT_PULLUP
 *    Button DOWN    = GPIO 12 (D6)       — INPUT_PULLUP
 *    Button CONFIRM = GPIO 13 (D7)       — INPUT_PULLUP
 *    Button BACK    = GPIO 0  (D3/FLASH) — INPUT_PULLUP
 *    LED (optional) = GPIO 2  (D4)       — Active LOW
 *
 *  Developer: Tams
 *  Inspired  : WiFi deauther projects +  EvilTwin
 *
 *  Build     : Arduino ESP8266 core 3.x
 *  Libraries : ESP8266WiFi, ESP8266WebServer, LittleFS, EEPROM,
 *              DNSServer, ESP8266HTTPUpdateServer, Adafruit_SSD1306,
 *              Adafruit_GFX, Wire, Hash
 *
 *  Default AP: SSID "TamsDeauth"  Password "deauther"  IP 192.168.4.1
 * ================================================================
 */

// ======================== Includes =============================

#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <LittleFS.h>
#include <EEPROM.h>
#include <DNSServer.h>
#include <ESP8266HTTPUpdateServer.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <Wire.h>
#include <Hash.h>          // SHA1 for self-destruct verification
#include <WiFiUdp.h>

// Low-level SDK access (wifi_send_pkt_freedom, wifi_set_channel, etc.)
extern "C" {
#include "user_interface.h"
}

// --- Local project headers (include order matters) ---
#include "config.h"        // EEPROM config struct, cfg, configKeys
#include "display.h"       // SSD1306 OLED, menu system, oledBuffer
#include "attacks.h"       // Deauth, beacon spam, evil-twin, rogue AP
#include "sniffer.h"       // Promiscuous-mode packet sniffer
#include "espnow_ctrl.h"   // ESP-NOW remote control
#include "filesystem.h"    // LittleFS file browser & helpers
#include "localization.h"  // Multi-language UI strings
#include "webserver.h"     // HTTP routes, captive portal, OTA

// ======================== Pin Map ==============================

#define PIN_UP        14   // D5 — navigate up
#define PIN_DOWN      12   // D6 — navigate down
#define PIN_CONFIRM   13   // D7 — select / confirm
#define PIN_BACK      0    // D3 — back / cancel (also FLASH)
#define PIN_LED       2    // D4 — status LED (active LOW)

// ======================== Globals ==============================

// Virtual button from web interface (extern'd in display.h)
// Values: -1=none, 1=up, 2=right/confirm, 3=down, 4=left/back,
//         5=select, 6=back-alt
int8_t virtualButton = -1;

// --- Button debounce state ---
// Each button tracks raw pin level, debounced stable level,
// press start time, and whether long-press already fired.
struct ButtonState {
  uint8_t  pin;
  bool     lastRaw;         // last raw digitalRead()
  bool     stable;          // debounced state
  uint32_t lastDebounce;    // last transition timestamp
  uint32_t pressStart;      // when pressed (stable LOW)
  bool     longPressFired;  // long-press event already sent?
};

ButtonState buttons[4] = {
  { PIN_UP,      HIGH, HIGH, 0, 0, false },
  { PIN_DOWN,    HIGH, HIGH, 0, 0, false },
  { PIN_CONFIRM, HIGH, HIGH, 0, 0, false },
  { PIN_BACK,    HIGH, HIGH, 0, 0, false },
};

#define DEBOUNCE_MS    50    // debounce window
#define LONGPRESS_MS   500   // long-press threshold

// --- Trial mode ---
// 10-minute trial timer; can be disabled with fullVersion flag.
#define TRIAL_DURATION_MS  (10UL * 60UL * 1000UL)
bool     fullVersion   = false;   // set true for full (paid) version
uint32_t bootTime      = 0;
bool     trialExpired  = false;

// --- Deep-sleep / power-save ---
uint32_t lastActivityTime = 0;

// --- SoftAP visibility ---
bool softAPHidden = false;

// --- Self-destruct ---
bool deviceDisabled = false;

// Firmware secret for integrity verification
#define FIRMWARE_SECRET "NC_v381_TamsDeauth_"

// --- LED blink state ---
uint32_t lastBlinkTime = 0;
bool     ledState      = false;

// ==================== Forward Declarations =====================

void handleButtons();
void handleVirtualButton();
void handleMenuConfirm();
void hideSoftAP();
void showSoftAP();
void doReboot();
void checkTrial();
bool verifySelfDestruct();
void checkDeepSleep();
void scanNetworks(bool deepScan = false);
void updateLED();

// ================================================================
//  SETUP — initialisation sequence
// ================================================================
void setup() {
  // --- Serial (debug output) ---
  Serial.begin(115200);
  delay(200);
  Serial.println();
  Serial.println(F("================================"));
  Serial.println(F("  TamsDeauth v3.8.1 Clone"));
  Serial.println(F("  ^~3.8.1~^  TamsDeauth"));
  Serial.println(F("   — ESP8266 WiFi Pentest"));
  Serial.println(F("================================"));
  Serial.println();

  // --- I²C + OLED display ---
  bool dispOK = initDisplay();
  if (dispOK) {
    drawBootLogo();   // Show TamsDeauth logo for ~1.5 s
  }

  // --- EEPROM ---
  EEPROM.begin(EEPROM_SIZE);
  Serial.println(F("[EEPROM] Initialised (4096 bytes)"));

  // --- LittleFS (web files, logs, captive portal templates) ---
  if (!LittleFS.begin()) {
    Serial.println(F("[FS] LittleFS mount FAILED"));
    if (dispOK) showActionScreen("FS ERROR!\nLittleFS mount\nfailed.");
    delay(2000);
  } else {
    Serial.println(F("[FS] LittleFS mounted OK"));
    FSInfo info;
    LittleFS.info(info);
    Serial.printf("[FS] %u KB used / %u KB total\n",
                  (unsigned)(info.usedBytes / 1024),
                  (unsigned)(info.totalBytes / 1024));
  }

  // --- Load configuration from EEPROM ---
  loadConfig();

  // --- Self-destruct / integrity verification ---
  // Verifies SHA1 hash of critical firmware identifier + config magic.
  // If tampered, disables the device permanently.
  if (!verifySelfDestruct()) {
    deviceDisabled = true;
    Serial.println(F("[SECURITY] *** SELF-DESTRUCT TRIGGERED ***"));
    Serial.println(F("[SECURITY] Unauthorized modification detected!"));
    if (dispOK) {
      display.clearDisplay();
      display.setTextSize(1);
      display.setTextColor(SSD1306_WHITE);
      display.setCursor(0, 8);
      display.println(F("This TamsDeauth"));
      display.println(F("device is disabled"));
      display.println(F("due to unauthorized"));
      display.println(F("modification."));
      display.display();
    }
    // Halt — device is permanently disabled
    while (true) {
      delay(1000);
    }
  }
  Serial.println(F("[SECURITY] Integrity check passed"));

  // --- WiFi Access Point ---
  // Default SSID "TamsDeauth", password "deauther", IP 192.168.4.1
  WiFi.mode(WIFI_AP_STA);   // AP for clients + STA for scanning

  IPAddress apIP(192, 168, 4, 1);
  IPAddress apGateway(192, 168, 4, 1);
  IPAddress apSubnet(255, 255, 255, 0);
  WiFi.softAPConfig(apIP, apGateway, apSubnet);
  WiFi.softAP(cfg.AP_SSID, cfg.AP_Password);

  Serial.printf("[WIFI] AP started: \"%s\" @ %s\n",
                cfg.AP_SSID, WiFi.softAPIP().toString().c_str());
  Serial.printf("[WIFI] Password: %s\n", cfg.AP_Password);

  // --- Web server (all HTTP routes) ---
  setupWebServer();
  Serial.println(F("[WEB] HTTP server started on port 80"));

  // --- DNS server (captive portal redirect) ---
  // All DNS queries resolve to 192.168.4.1 so that any URL the
  // victim types lands on the TamsDeauth web interface.
  dnsServer.setErrorReplyCode(DNSReplyCode::NoError);
  dnsServer.start(53, "*", apIP);
  dnsServerActive = true;
  Serial.println(F("[DNS] Captive portal DNS started on port 53"));

  // --- ESP-NOW (remote control between devices) ---
  if (initEspNow()) {
    Serial.println(F("[ESPNOW] Initialised"));
  } else {
    Serial.println(F("[ESPNOW] Init failed — continuing without ESP-NOW"));
  }

  // --- Button pins (INPUT_PULLUP) ---
  pinMode(PIN_UP,      INPUT_PULLUP);
  pinMode(PIN_DOWN,    INPUT_PULLUP);
  pinMode(PIN_CONFIRM, INPUT_PULLUP);
  pinMode(PIN_BACK,    INPUT_PULLUP);
  pinMode(PIN_LED,     OUTPUT);
  digitalWrite(PIN_LED, HIGH);  // LED off (active LOW)

  // --- Auto-resume previous attack (if enabled) ---
  if (cfg.Resume_Active && cfg.Attack_Mode != ATTACK_NONE) {
    Serial.printf("[RESUME] Resuming attack mode %d\n", cfg.Attack_Mode);
    switch (cfg.Attack_Mode) {
      case ATTACK_DEAUTH:         startDeauthAttack();      break;
      case ATTACK_DEAUTH_ALL:     startDeauthAllAttack();   break;
      case ATTACK_PRECISE_DEAUTH: startPreciseDeauth();     break;
      case ATTACK_TRUE_DEAUTH:    startTrueDeauth();        break;
      case ATTACK_BEACON_SPAM:    startBeaconSpam();        break;
      case ATTACK_EVIL_TWIN:      startEvilTwin();
                                  captivePortalActive = true; break;
      case ATTACK_ROGUE_AP:       startRogueAP();
                                  captivePortalActive = true; break;
      case ATTACK_DDOS_ROUTER:    startDDoSRouter();        break;
    }
  }

  // --- Trial timer start ---
  bootTime = millis();
  lastActivityTime = millis();
  if (!fullVersion) {
    Serial.println(F("[TRIAL] Trial mode active — 10 minute limit"));
  }

  // --- Show MAIN MENU ---
  currentScreen = 0;   // main menu
  menuIndex = 0;
  menuTop = 0;
  updateDisplay();

  Serial.println(F("[BOOT] Setup complete. Ready."));
  Serial.println(F("------------------------------------------------"));
}

// ================================================================
//  LOOP — main event dispatcher
// ================================================================
void loop() {
  // 1. Handle web server client requests
  server.handleClient();

  // 2. Handle DNS server (captive portal)
  if (dnsServerActive) {
    dnsServer.processNextRequest();
  }

  // 3. Handle physical buttons (debounce + long-press)
  handleButtons();

  // 4. Handle virtual buttons from web interface
  handleVirtualButton();

  // 5. Update OLED display (menu, attack screens, game)
  updateDisplay();

  // 6. Handle active attacks (deauth, beacon spam, DDoS, etc.)
  handleAttacks();

  // 7. Update sniffer channel-hopping
  updateChannelHop();

  // 8. Check trial timer (10-minute limit)
  checkTrial();

  // 9. Check auto deep-sleep / power-save
  checkDeepSleep();

  // 10. Update LED indicator
  updateLED();
}

// ================================================================
//  BUTTON HANDLING
//
//  Reads 4 physical buttons with 50 ms debounce.
//  Short press: UP/DOWN navigate, CONFIRM selects, BACK goes back.
//  Long press (500 ms+): UP/DOWN repeat (wrapping navigation).
//  Also processes virtual buttons from the web interface.
// ================================================================
void handleButtons() {
  uint32_t now = millis();

  for (int i = 0; i < 4; i++) {
    bool raw = digitalRead(buttons[i].pin);

    // --- Debounce: track raw transitions ---
    if (raw != buttons[i].lastRaw) {
      buttons[i].lastRaw = raw;
      buttons[i].lastDebounce = now;
    }

    // --- Apply stable state after debounce window ---
    if (now - buttons[i].lastDebounce > DEBOUNCE_MS) {
      if (raw != buttons[i].stable) {
        buttons[i].stable = raw;

        if (raw == LOW) {
          // --- Button pressed (falling edge) ---
          buttons[i].pressStart = now;
          buttons[i].longPressFired = false;
        } else {
          // --- Button released (rising edge) ---
          uint32_t pressDuration = now - buttons[i].pressStart;
          if (!buttons[i].longPressFired && pressDuration > 50) {
            // Short press action
            lastActivityTime = now;
            switch (i) {
              case 0: menuUp();      break;  // UP
              case 1: menuDown();    break;  // DOWN
              case 2: menuConfirm(); break;  // CONFIRM
              case 3:
                // BACK — stop attacks if exiting attack screen
                if (inActionScreen && attackScreenCounter != nullptr) {
                  stopAllAttacks();
                  captivePortalActive = false;
                }
                menuBack();
                break;  // BACK
            }
          }
        }
      }
    }

    // --- Long press: repeat navigation for UP/DOWN ---
    if (buttons[i].stable == LOW && !buttons[i].longPressFired) {
      if (now - buttons[i].pressStart > LONGPRESS_MS) {
        buttons[i].longPressFired = true;
        lastActivityTime = now;
        switch (i) {
          case 0: menuUp();   break;  // UP — repeat
          case 1: menuDown(); break;  // DOWN — repeat
          // CONFIRM and BACK do not repeat on long press
        }
      }
    }
  }
}

// ================================================================
//  VIRTUAL BUTTON — from web virtual display interface
//
//  Processes a pending virtual button press (set by the
//  /virtualdisplay?btn=X HTTP endpoint in webserver.h).
// ================================================================
void handleVirtualButton() {
  if (virtualButton < 0) return;

  lastActivityTime = millis();

  switch (virtualButton) {
    case 1: menuUp();      break;  // UP
    case 2: menuConfirm(); break;  // RIGHT = confirm
    case 3: menuDown();    break;  // DOWN
    case 4:
      if (inActionScreen && attackScreenCounter != nullptr) {
        stopAllAttacks();
        captivePortalActive = false;
      }
      menuBack();
      break;  // LEFT = back
    case 5: menuConfirm(); break;  // SELECT = confirm
    case 6: menuBack();    break;  // BACK
  }

  virtualButton = -1;  // consume
}

// ================================================================
//  MENU CONFIRM — execute the selected menu item's action
//
//  Called from display.h's menuConfirm() via extern declaration.
//  Handles all 19 main-menu items + scan-result selection.
// ================================================================
void handleMenuConfirm() {
  // --- Scan result selection (Select Network screen) ---
  if (currentScreen == 1) {
    if (scanResultCount > 0 && menuIndex < scanResultCount) {
      // Set the selected network as target
      strncpy(cfg.target_ssid, scanResults[menuIndex].ssid, MAX_SSID_LEN);
      memcpy(cfg.target_bssid, scanResults[menuIndex].bssid, 6);
      cfg.target_ch = scanResults[menuIndex].channel;
      strncpy(cfg.CurrentTarget, scanResults[menuIndex].ssid, MAX_SSID_LEN);
      saveConfig();

      // Sync sniffer target for station observation
      setSnifferTarget(cfg.target_bssid, cfg.target_ch);

      Serial.printf("[MENU] Target set: %s  CH:%u  BSSID:%s\n",
                    cfg.target_ssid, cfg.target_ch,
                    formatMAC(cfg.target_bssid).c_str());
      showActionScreen("Target set:\n" + String(cfg.target_ssid) +
                       "\nCH:" + String(cfg.target_ch) +
                       "\n\nPress BACK");
    }
    return;
  }

  // --- Main menu actions ---
  if (currentScreen != 0) return;

  switch (menuIndex) {

    // ---- Scan Network ----
    case MENU_SCAN_NETWORK:
      scanNetworks(false);
      showActionScreen("Scan complete.\n" + String(scanResultCount) +
                       " networks found.\n\nPress BACK");
      break;

    // ---- Select Network (show scan results) ----
    case MENU_SELECT_NETWORK:
      if (scanResultCount == 0) {
        showActionScreen("No networks found.\nRun Scan first.\n\nPress BACK");
      } else {
        currentScreen = 1;   // switch to scan results view
        menuIndex = 0;
        menuTop = 0;
      }
      break;

    // ---- Station (submenu placeholder) ----
    case MENU_STATION:
      showActionScreen("Station Menu:\n1. Count Stations\n2. Observe\n\nUse menu items\nbelow.\n\nPress BACK");
      break;

    // ---- Target (show current target info) ----
    case MENU_TARGET:
      if (strlen(cfg.target_ssid) > 0) {
        showActionScreen("Current Target:\n" + String(cfg.target_ssid) +
                         "\nCH:" + String(cfg.target_ch) +
                         "\n" + formatMAC(cfg.target_bssid) +
                         "\n\nPress BACK");
      } else {
        showActionScreen("No target\nselected.\n\nSelect a network\nfirst.\n\nPress BACK");
      }
      break;

    // ---- Deauth (targeted) ----
    case MENU_DEAUTH:
      if (cfg.target_ch == 0) {
        showActionScreen("No target is\nselected.\n\nPress BACK");
      } else {
        startDeauthAttack();
        showAttackScreen("Deauth", &deauthPacketCount);
      }
      break;

    // ---- Deauth All ----
    case MENU_DEAUTH_ALL:
      startDeauthAllAttack();
      showAttackScreen("DDoS-ing router\nDeauth All", &deauthPacketCount);
      break;

    // ---- Precise Deauth ----
    case MENU_PRECISE_DEAUTH:
      if (cfg.target_ch == 0) {
        showActionScreen("No target is\nselected.\n\nPress BACK");
      } else {
        startPreciseDeauth();
        showAttackScreen("Precise Deauth", &deauthPacketCount);
      }
      break;

    // ---- True Deauth (channel-hopping) ----
    case MENU_TRUE_DEAUTH:
      startTrueDeauth();
      showAttackScreen("True Deauth", &deauthPacketCount);
      break;

    // ---- Evil-Twin ----
    case MENU_EVIL_TWIN:
      if (strlen(cfg.target_ssid) == 0) {
        showActionScreen("No target is\nselected.\n\nPress BACK");
      } else {
        startEvilTwin();
        captivePortalActive = true;
        showActionScreen("Evil-Twin started\non " + String(cfg.target_ssid) +
                         "\n\nCaptive portal\nactive.\n\nPress BACK");
      }
      break;

    // ---- Rogue AP ----
    case MENU_ROGUE_AP:
      startRogueAP();
      captivePortalActive = true;
      showActionScreen("Rogue AP started:\n" +
                       String(strlen(cfg.roguehotspotname) > 0 ?
                              cfg.roguehotspotname : cfg.Rogue_SSID) +
                       "\n\nCaptive portal\nactive.\n\nPress BACK");
      break;

    // ---- Beacon Spam ----
    case MENU_BEACON_SPAM:
      startBeaconSpam();
      showAttackScreen("Beacon Spam", &beaconSpamCount);
      break;

    // ---- Hide SoftAP ----
    case MENU_HIDE_SOFTAP:
      if (softAPHidden) {
        showSoftAP();
        showActionScreen("SoftAP visible.\n\nPress BACK");
      } else {
        hideSoftAP();
        showActionScreen("SoftAP hidden.\n\nPress BACK");
      }
      break;

    // ---- DDoS Router ----
    case MENU_DDOS_ROUTER:
      if (cfg.target_ch == 0) {
        showActionScreen("No target is\nselected.\n\nPress BACK");
      } else {
        startDDoSRouter();
        showAttackScreen("DDoS-ing router", &ddosPacketCount);
      }
      break;

    // ---- Count Stations ----
    case MENU_COUNT_STATIONS:
      if (cfg.target_ch == 0) {
        showActionScreen("No target is\nselected.\n\nPress BACK");
      } else {
        clearStations();
        setSnifferTarget(cfg.target_bssid, cfg.target_ch);
        startSniffer(SNIFF_STATION);
        showActionScreen("Counting stations...\n\nTarget: " +
                         String(cfg.target_ssid) + "\n\nPress BACK\nto stop.");
      }
      break;

    // ---- Observe Stations ----
    case MENU_OBSERVE_STATIONS:
      clearStations();
      startSniffer(SNIFF_ALL);
      showActionScreen("Observing stations...\n\nAll channels\n\nPress BACK\nto stop.");
      break;

    // ---- Deauth Monitor ----
    case MENU_DEAUTH_MONITOR:
      startSniffer(SNIFF_DEAUTH);
      showActionScreen("Deauth Monitor\nactive.\n\nDetecting deauth\nattacks...\n\nPress BACK\nto stop.");
      break;

    // ---- View logs ----
    case MENU_VIEW_LOGS: {
      String logs = readFileContent("/log.txt");
      if (logs.length() == 0) logs = "No logs yet.";
      // Truncate to fit display
      if (logs.length() > 500) logs = logs.substring(0, 500);
      showActionScreen(logs);
      break;
    }

    // ---- TinyJoyPad (minigame) ----
    case MENU_TINYJOYPAD:
      inGame = true;
      gameScore = 0;
      playerX = 64;
      playerY = 32;
      targetX = random(4, 124);
      targetY = random(4, 60);
      Serial.println(F("[GAME] TinyJoyPad started"));
      break;

    // ---- Restart ----
    case MENU_RESTART:
      showActionScreen("Restarting...\n\nPlease wait.");
      delay(1000);
      doReboot();
      break;

    default:
      break;
  }
}

// ================================================================
//  WiFi AP HIDE / SHOW
//
//  Hides or reveals the TamsDeauth SoftAP SSID.
//  extern'd in espnow_ctrl.h, called from web and ESP-NOW.
// ================================================================
void hideSoftAP() {
  if (softAPHidden) return;
  softAPHidden = true;
  WiFi.softAPdisconnect(false);
  delay(100);
  // Re-create AP with hidden=1 (SSID not broadcast in beacons)
  WiFi.softAP(cfg.AP_SSID, cfg.AP_Password, 1, 1);
  Serial.println(F("[WIFI] SoftAP hidden"));
}

void showSoftAP() {
  if (!softAPHidden) return;
  softAPHidden = false;
  WiFi.softAPdisconnect(false);
  delay(100);
  // Re-create AP with hidden=0 (SSID broadcast normally)
  WiFi.softAP(cfg.AP_SSID, cfg.AP_Password, 1, 0);
  Serial.println(F("[WIFI] SoftAP visible"));
}

// ================================================================
//  REBOOT
//
//  Cleanly stop attacks, save config, and restart the ESP8266.
//  extern'd in espnow_ctrl.h.
// ================================================================
void doReboot() {
  Serial.println(F("[SYSTEM] Rebooting..."));
  stopAllAttacks();
  captivePortalActive = false;
  saveConfig();
  delay(500);
  ESP.restart();
}

// ================================================================
//  WiFi SCAN — populate scanResults[] array
//
//  Performs a synchronous WiFi scan and fills the global
//  scanResults array (defined in attacks.h, displayed by
//  display.h's drawScanResults()).
// ================================================================
void scanNetworks(bool deepScan) {
  showActionScreen("Scanning...");

  // Ensure AP+STA mode for scanning
  WiFi.mode(WIFI_AP_STA);
  delay(50);

  Serial.printf("[SCAN] Starting %s scan...\n", deepScan ? "deep" : "normal");

  // scanNetworks(async=false, show_hidden=deepScan)
  int n = WiFi.scanNetworks(false, deepScan);
  scanResultCount = 0;

  if (n <= 0) {
    Serial.println(F("[SCAN] No networks found"));
    return;
  }

  for (int i = 0; i < n && scanResultCount < MAX_SCAN_RESULTS; i++) {
    String ssid = WiFi.SSID(i);
    strncpy(scanResults[scanResultCount].ssid, ssid.c_str(), MAX_SSID_LEN);
    scanResults[scanResultCount].ssid[MAX_SSID_LEN] = '\0';

    memcpy(scanResults[scanResultCount].bssid, WiFi.BSSID(i), 6);
    scanResults[scanResultCount].channel = WiFi.channel(i);
    scanResults[scanResultCount].rssi = WiFi.RSSI(i);
    scanResults[scanResultCount].hidden = (ssid.length() == 0);

    Serial.printf("  [%d] %-32s  CH:%2u  RSSI:%4d  %s\n",
                  scanResultCount,
                  scanResults[scanResultCount].ssid,
                  scanResults[scanResultCount].channel,
                  scanResults[scanResultCount].rssi,
                  formatMAC(scanResults[scanResultCount].bssid).c_str());

    scanResultCount++;
  }

  // Free scan memory
  WiFi.scanDelete();

  Serial.printf("[SCAN] Complete — %d networks stored\n", scanResultCount);
}

// ================================================================
//  TRIAL MODE — 10-minute usage limit
//
//  After TRIAL_DURATION_MS (10 minutes), all attacks are
//  stopped and a trial-expired message is shown on OLED.
//  Can be disabled by setting fullVersion = true.
// ================================================================
void checkTrial() {
  if (fullVersion || trialExpired) return;

  uint32_t elapsed = millis() - bootTime;
  if (elapsed > TRIAL_DURATION_MS) {
    trialExpired = true;
    Serial.println(F("[TRIAL] *** Trial expired — 10 minute limit reached ***"));

    // Stop all active attacks
    stopAllAttacks();
    captivePortalActive = false;

    // Show trial expired message on OLED
    display.clearDisplay();
    display.setTextSize(1);
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(0, 5);
    display.println(F("Trial version."));
    display.setCursor(0, 16);
    display.println(F("Usage time limited"));
    display.setCursor(0, 26);
    display.println(F("to 10 minutes."));
    display.setCursor(0, 40);
    display.println(F("Trial expired!"));
    display.setCursor(0, 54);
    display.println(F("github.com/"));
    display.setCursor(0, 58);
    display.print(F("/TamsDeauth"));
    display.display();

    // Keep serving web interface so user sees the message
    while (true) {
      server.handleClient();
      if (dnsServerActive) dnsServer.processNextRequest();
      delay(100);
    }
  }
}

// ================================================================
//  SELF-DESTRUCT VERIFICATION
//
//  On boot, computes SHA1 hash of a firmware secret string +
//  config magic number.  The hash is stored in EEPROM on first
//  boot and compared on subsequent boots.  If the hash does not
//  match (firmware patched, EEPROM tampered, or magic changed),
//  the device is permanently disabled.
//
//  Message: "This TamsDeauth device is disabled due to
//            unauthorized modification."
// ================================================================
bool verifySelfDestruct() {
  // Build hash input from firmware secret + config magic
  String hashInput = String(FIRMWARE_SECRET);
  hashInput += "_";
  hashInput += String((uint32_t)cfg.magic);
  String computedHash = SHA1(hashInput);

  Serial.printf("[SECURITY] Computed hash: %s\n", computedHash.c_str());

  // Read stored hash from EEPROM (stored at offset 4080, 40 bytes)
  EEPROM.begin(EEPROM_SIZE);
  char storedHash[41];
  bool hasStored = false;
  for (int i = 0; i < 40; i++) {
    storedHash[i] = (char)EEPROM.read(4080 + i);
    if (storedHash[i] != 0 && storedHash[i] != (char)0xFF) {
      hasStored = true;
    }
  }
  storedHash[40] = '\0';

  if (!hasStored) {
    // First boot — store the computed hash
    Serial.println(F("[SECURITY] First boot — storing config hash"));
    for (int i = 0; i < 40 && i < (int)computedHash.length(); i++) {
      EEPROM.write(4080 + i, computedHash[i]);
    }
    EEPROM.commit();
    EEPROM.end();
    return true;   // OK on first boot
  }

  // Compare computed hash against stored hash
  bool match = (computedHash.equals(String(storedHash)));
  EEPROM.end();

  if (!match) {
    Serial.println(F("[SECURITY] *** HASH MISMATCH ***"));
    Serial.printf("[SECURITY] Expected: %s\n", storedHash);
    Serial.printf("[SECURITY] Got:      %s\n", computedHash.c_str());
    Serial.println(F("[SECURITY] This TamsDeauth device is disabled due to"));
    Serial.println(F("[SECURITY] unauthorized modification."));
    return false;
  }

  Serial.println(F("[SECURITY] Config integrity verified — OK"));
  return true;
}

// ================================================================
//  AUTO DEEP-SLEEP / POWER-SAVE
//
//  If Powersave_Active is enabled, the ESP8266 enters deep-sleep
//  after 5 minutes of inactivity (no button presses).  It wakes
//  after 10 seconds and reboots (setup() runs again).  If
//  Resume_Active is also set, the previous attack resumes.
// ================================================================
void checkDeepSleep() {
  if (!cfg.Powersave_Active) return;
  if (trialExpired) return;

  // 5 minutes of no activity → enter deep sleep
  if (millis() - lastActivityTime > 300000UL) {
    Serial.println(F("[POWERSAVE] Entering deep sleep (5 min idle)..."));

    // Clean up before sleeping
    stopAllAttacks();
    captivePortalActive = false;
    saveConfig();

    // Turn off display
    display.clearDisplay();
    display.display();
    display.ssd1306_command(SSD1306_DISPLAYOFF);
    digitalWrite(PIN_LED, HIGH);

    // Deep sleep for 10 seconds, then wake (reboot)
    ESP.deepSleep(10e6);  // 10 seconds in microseconds
    // Execution never reaches here — device reboots on wake
  }
}

// ================================================================
//  LED INDICATOR
//
//  Blinks the status LED when any attack is active.
//  Steady off when idle.  Controlled by cfg.LED_Active.
// ================================================================
void updateLED() {
  if (!cfg.LED_Active) {
    digitalWrite(PIN_LED, HIGH);  // LED off
    return;
  }

  // Check if any attack is running
  bool anyActive = deauthActive || deauthAllActive ||
                   preciseDeauthActive || trueDeauthActive ||
                   evilTwinActive || rogueAPActive ||
                   beaconSpamActive || ddosActive;

  if (anyActive) {
    // Blink at ~5 Hz
    if (millis() - lastBlinkTime > 100) {
      ledState = !ledState;
      digitalWrite(PIN_LED, ledState ? LOW : HIGH);
      lastBlinkTime = millis();
    }
  } else {
    digitalWrite(PIN_LED, HIGH);  // off when idle
  }
}

// ================================================================
//  End of TamsDeauth.ino
// ================================================================
