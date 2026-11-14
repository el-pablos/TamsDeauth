#ifndef CONFIG_H
#define CONFIG_H

#include <Arduino.h>
#include <EEPROM.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// ============================================================
// TamsDeauth Clone v3.8.1 — Configuration & EEPROM Persistence
//
// All settings persist in EEPROM (4096 bytes).  The TamsDeauthConfig
// struct is written raw; a magic sentinel validates first-boot vs.
// existing data.
//
// This header is included first in the chain.  It defines:
//   • TamsDeauthConfig cfg            — global config struct
//   • char currentLanguage[8]        — synced from cfg.Language
//   • String configKeys[]            — key names for web settings
//   • int numConfigKeys              — count of above
//   • loadConfig() / saveConfig()    — EEPROM I/O
//   • setConfigString(k, v)          — set field by string key
// ============================================================

#define EEPROM_SIZE          4096
#define EEPROM_CONFIG_ADDR   0
#define CONFIG_MAGIC         0x4E455448U   // "NETH" — first-boot sentinel

// Field size limits
#define MAX_SSID_LEN     32
#define MAX_PASS_LEN     64
#define MAX_MAC_LEN      18
#define MAX_MAC_LIST     16
#define MAX_PATTERN_LEN  32
#define MAX_SCAN_RESULTS 32

// --- Scan result struct (shared by display.h and attacks.h) ---
struct ScanResult {
  char    ssid[MAX_SSID_LEN + 1];
  uint8_t bssid[6];
  uint8_t channel;
  int8_t  rssi;
  bool    hidden;
};

// --- Attack mode enum (stored as int in cfg.Attack_Mode) ---
enum AttackMode : int {
  ATTACK_NONE = 0,
  ATTACK_DEAUTH,
  ATTACK_DEAUTH_ALL,
  ATTACK_PRECISE_DEAUTH,
  ATTACK_TRUE_DEAUTH,
  ATTACK_EVIL_TWIN,
  ATTACK_ROGUE_AP,
  ATTACK_BEACON_SPAM,
  ATTACK_DDOS_ROUTER,
  ATTACK_DEAUTH_MONITOR,
  ATTACK_ROUTER_GUARD
};

// --- Deauth sub-mode enum ---
enum DeauthMode : int {
  DEAUTH_MODE_NORMAL  = 0,
  DEAUTH_MODE_PRECISE = 1,
  DEAUTH_MODE_TRUE    = 2
};

// --- Router guard behaviour ---
enum GuardBehavior : int {
  GUARD_OFF       = 0,
  GUARD_WHITELIST = 1,
  GUARD_BLACKLIST = 2
};

// ============================================================
// Main configuration structure — persisted in EEPROM.
// Field order must stay stable across versions.
// ============================================================
struct TamsDeauthConfig {
  // Access Point (SoftAP) credentials
  char     AP_SSID[MAX_SSID_LEN + 1];        // default "TamsDeauth"
  char     AP_Password[MAX_PASS_LEN + 1];    // default "deauther"
  char     Rogue_SSID[MAX_SSID_LEN + 1];
  char     roguehotspotname[MAX_SSID_LEN + 1];

  // WiFi Extender / Repeater
  char     Extender_SSID[MAX_SSID_LEN + 1];
  char     Extender_Password[MAX_PASS_LEN + 1];
  uint32_t Extender_Timeout;
  uint8_t  Extender_Status;

  // Extended (uplink repeater)
  char     Extended_SSID[MAX_SSID_LEN + 1];
  char     Extended_Password[MAX_PASS_LEN + 1];

  // Internet passthrough
  char     Internet_SSID[MAX_SSID_LEN + 1];
  char     Internet_Password[MAX_PASS_LEN + 1];

  // Attack configuration
  int      Attack_Mode;
  int      Deauth_Mode;
  int      Etwin_Path;       // 0=default, 1-5=template
  int      Rogue_Path;       // 0=default, 1-5=template

  // Target selection
  char     target_ssid[MAX_SSID_LEN + 1];
  uint8_t  target_bssid[6];
  uint8_t  target_ch;        // 0=none, 1-13
  char     CurrentTarget[MAX_SSID_LEN + 1];

  // Router guard
  int      guard_behavior;
  char     mac_list[MAX_MAC_LIST][MAX_MAC_LEN];

  // Display / UI
  char     Language[8];      // "en" or "id"
  uint32_t OLED_Timeout;     // display sleep (ms)
  uint32_t OLED_Interval;    // virtual display refresh (ms)

  // Feature toggles
  bool     LED_Active;
  bool     Resume_Active;
  bool     Powersave_Active;

  // Security
  char     Pattern_Lock[MAX_PATTERN_LEN];

  // Network identity
  char     customMAC[MAX_MAC_LEN];
  char     peerAddress[MAX_MAC_LEN];

  // Timing
  uint32_t deauthDelay;      // ms between deauth bursts
  uint32_t scanduration;     // WiFi scan duration (ms)

  // Integrity
  uint32_t magic;
};

// Global config instance — named "cfg" throughout the codebase
TamsDeauthConfig cfg;

// Current language (synced from cfg.Language; extern'd in localization.h)
char currentLanguage[8] = "en";

// ------------------------------------------------------------
// Config key names for web settings form iteration.
// webserver.h iterates configKeys[] / numConfigKeys.
// ------------------------------------------------------------
const char* configKeyNames[] = {
  "AP_SSID",            "AP_Password",       "Rogue_SSID",
  "roguehotspotname",
  "Extender_SSID",      "Extender_Password", "Extender_Timeout",
  "Extender_Status",
  "Extended_SSID",      "Extended_Password",
  "Internet_SSID",      "Internet_Password",
  "Attack_Mode",        "Deauth_Mode",       "Etwin_Path",
  "Rogue_Path",
  "target_ssid",        "target_bssid",      "target_ch",
  "CurrentTarget",
  "guard_behavior",     "Language",          "OLED_Timeout",
  "OLED_Interval",
  "LED_Active",         "Resume_Active",     "Powersave_Active",
  "Pattern_Lock",       "customMAC",         "peerAddress",
  "deauthDelay",        "scanduration"
};
const int numConfigKeyNames = sizeof(configKeyNames) / sizeof(configKeyNames[0]);

// String array for web form iteration
String configKeys[numConfigKeyNames];
const int numConfigKeys = numConfigKeyNames;

void initConfigKeys() {
  for (int i = 0; i < numConfigKeyNames; i++)
    configKeys[i] = String(configKeyNames[i]);
}

// ------------------------------------------------------------
// Factory defaults
// ------------------------------------------------------------
void setDefaultConfig() {
  memset(&cfg, 0, sizeof(cfg));

  strncpy(cfg.AP_SSID,          "TamsDeauth",        MAX_SSID_LEN);
  strncpy(cfg.AP_Password,      "deauther",         MAX_PASS_LEN);
  strncpy(cfg.Rogue_SSID,       "TamsDeauth_ROGUE",  MAX_SSID_LEN);
  strncpy(cfg.roguehotspotname, "FreeWiFi",         MAX_SSID_LEN);

  strncpy(cfg.Extender_SSID,    "TamsDeauth_Extender", MAX_SSID_LEN);
  strncpy(cfg.Extender_Password,"deauther",         MAX_PASS_LEN);
  cfg.Extender_Timeout = 30000;
  cfg.Extender_Status  = 0;

  cfg.Attack_Mode = ATTACK_NONE;
  cfg.Deauth_Mode = DEAUTH_MODE_NORMAL;
  cfg.Etwin_Path  = 0;
  cfg.Rogue_Path  = 0;

  cfg.target_ch      = 0;
  cfg.guard_behavior = GUARD_OFF;

  strncpy(cfg.Language,    "en", 7);
  cfg.OLED_Timeout  = 10000;
  cfg.OLED_Interval = 100;

  cfg.LED_Active       = true;
  cfg.Resume_Active    = false;
  cfg.Powersave_Active = false;

  strncpy(cfg.customMAC,   "00:00:00:00:00:00", MAX_MAC_LEN);
  strncpy(cfg.peerAddress, "FF:FF:FF:FF:FF:FF", MAX_MAC_LEN);

  cfg.deauthDelay  = 50;
  cfg.scanduration = 3000;

  cfg.magic = CONFIG_MAGIC;
}

// ------------------------------------------------------------
// Load configuration from EEPROM into cfg.
// If magic mismatches, write defaults.
// ------------------------------------------------------------
void loadConfig() {
  EEPROM.begin(EEPROM_SIZE);

  uint8_t* p = (uint8_t*)&cfg;
  for (size_t i = 0; i < sizeof(TamsDeauthConfig); i++)
    p[i] = EEPROM.read(EEPROM_CONFIG_ADDR + i);

  if (cfg.magic != CONFIG_MAGIC) {
    Serial.println(F("[CONFIG] First boot or corrupted — loading defaults"));
    setDefaultConfig();
    saveConfig();
  }

  // Sanitise critical fields
  if (strlen(cfg.AP_SSID) == 0 || strlen(cfg.AP_SSID) > MAX_SSID_LEN)
    strncpy(cfg.AP_SSID, "TamsDeauth", MAX_SSID_LEN);
  if (strlen(cfg.AP_Password) < 8)
    strncpy(cfg.AP_Password, "deauther", MAX_PASS_LEN);
  if (cfg.OLED_Timeout == 0)  cfg.OLED_Timeout  = 10000;
  if (cfg.OLED_Interval == 0) cfg.OLED_Interval = 100;
  if (cfg.deauthDelay == 0)   cfg.deauthDelay   = 50;
  if (cfg.scanduration == 0)  cfg.scanduration  = 3000;

  // Sync currentLanguage for localization.h
  strncpy(currentLanguage, cfg.Language, 7);
  currentLanguage[7] = '\0';

  initConfigKeys();

  Serial.println(F("[CONFIG] Configuration loaded"));
  Serial.printf("[CONFIG] AP:%s | Lang:%s | OLED:%u ms | Scan:%u ms\n",
                cfg.AP_SSID, cfg.Language,
                (unsigned)cfg.OLED_Timeout, (unsigned)cfg.scanduration);

  EEPROM.end();
}

// ------------------------------------------------------------
// Save cfg to EEPROM with commit.
// ------------------------------------------------------------
void saveConfig() {
  EEPROM.begin(EEPROM_SIZE);
  cfg.magic = CONFIG_MAGIC;

  uint8_t* p = (uint8_t*)&cfg;
  for (size_t i = 0; i < sizeof(TamsDeauthConfig); i++)
    EEPROM.write(EEPROM_CONFIG_ADDR + i, p[i]);
  EEPROM.commit();

  strncpy(currentLanguage, cfg.Language, 7);
  currentLanguage[7] = '\0';

  Serial.println(F("[CONFIG] Configuration saved"));
  EEPROM.end();
}

// ------------------------------------------------------------
// Parse "AA:BB:CC:DD:EE:FF" into 6 bytes.  Returns true on success.
// ------------------------------------------------------------
bool parseMAC(const String& macStr, uint8_t* mac) {
  if (macStr.length() < 17) return false;
  int idx = 0, pos = 0;
  while (idx < 6 && pos < (int)macStr.length()) {
    String byteStr;
    while (pos < (int)macStr.length() &&
           macStr[pos] != ':' && macStr[pos] != '-') {
      byteStr += macStr[pos++];
    }
    mac[idx++] = (uint8_t)strtol(byteStr.c_str(), NULL, 16);
    if (pos < (int)macStr.length()) pos++;
  }
  return (idx == 6);
}

// Format 6 bytes into "AA:BB:CC:DD:EE:FF"
String formatMAC(const uint8_t* mac) {
  char buf[18];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}

// ------------------------------------------------------------
// Set a config field by string key (used by web settings form).
// Signature: void setConfigString(const String& key, const String& value)
// as expected by webserver.h.
// ------------------------------------------------------------
void setConfigString(const String& key, const String& value) {
  if      (key == "AP_SSID")            strncpy(cfg.AP_SSID, value.c_str(), MAX_SSID_LEN);
  else if (key == "AP_Password")        strncpy(cfg.AP_Password, value.c_str(), MAX_PASS_LEN);
  else if (key == "Rogue_SSID")         strncpy(cfg.Rogue_SSID, value.c_str(), MAX_SSID_LEN);
  else if (key == "roguehotspotname")   strncpy(cfg.roguehotspotname, value.c_str(), MAX_SSID_LEN);
  else if (key == "Extender_SSID")      strncpy(cfg.Extender_SSID, value.c_str(), MAX_SSID_LEN);
  else if (key == "Extender_Password")  strncpy(cfg.Extender_Password, value.c_str(), MAX_PASS_LEN);
  else if (key == "Extender_Timeout")   cfg.Extender_Timeout = value.toInt();
  else if (key == "Extender_Status")    cfg.Extender_Status = value.toInt();
  else if (key == "Extended_SSID")      strncpy(cfg.Extended_SSID, value.c_str(), MAX_SSID_LEN);
  else if (key == "Extended_Password")  strncpy(cfg.Extended_Password, value.c_str(), MAX_PASS_LEN);
  else if (key == "Internet_SSID")      strncpy(cfg.Internet_SSID, value.c_str(), MAX_SSID_LEN);
  else if (key == "Internet_Password")  strncpy(cfg.Internet_Password, value.c_str(), MAX_PASS_LEN);
  else if (key == "Attack_Mode")        cfg.Attack_Mode = value.toInt();
  else if (key == "Deauth_Mode")        cfg.Deauth_Mode = value.toInt();
  else if (key == "Etwin_Path")         cfg.Etwin_Path = value.toInt();
  else if (key == "Rogue_Path")         cfg.Rogue_Path = value.toInt();
  else if (key == "target_ssid")        strncpy(cfg.target_ssid, value.c_str(), MAX_SSID_LEN);
  else if (key == "target_bssid")       parseMAC(value, cfg.target_bssid);
  else if (key == "target_ch")          cfg.target_ch = value.toInt();
  else if (key == "CurrentTarget")      strncpy(cfg.CurrentTarget, value.c_str(), MAX_SSID_LEN);
  else if (key == "guard_behavior")     cfg.guard_behavior = value.toInt();
  else if (key == "Language")           { strncpy(cfg.Language, value.c_str(), 7);
                                          cfg.Language[7] = '\0'; }
  else if (key == "OLED_Timeout")       cfg.OLED_Timeout = value.toInt();
  else if (key == "OLED_Interval")      cfg.OLED_Interval = value.toInt();
  else if (key == "LED_Active")         cfg.LED_Active = (value == "1" || value == "true");
  else if (key == "Resume_Active")      cfg.Resume_Active = (value == "1" || value == "true");
  else if (key == "Powersave_Active")   cfg.Powersave_Active = (value == "1" || value == "true");
  else if (key == "Pattern_Lock")       strncpy(cfg.Pattern_Lock, value.c_str(), MAX_PATTERN_LEN - 1);
  else if (key == "customMAC")          strncpy(cfg.customMAC, value.c_str(), MAX_MAC_LEN);
  else if (key == "peerAddress")        strncpy(cfg.peerAddress, value.c_str(), MAX_MAC_LEN);
  else if (key == "deauthDelay")        cfg.deauthDelay = value.toInt();
  else if (key == "scanduration")       cfg.scanduration = value.toInt();
}

// ------------------------------------------------------------
// Get a config field by string key (returns String).
// ------------------------------------------------------------
String getConfigString(const String& key) {
  if      (key == "AP_SSID")          return String(cfg.AP_SSID);
  else if (key == "AP_Password")      return String(cfg.AP_Password);
  else if (key == "Rogue_SSID")       return String(cfg.Rogue_SSID);
  else if (key == "roguehotspotname") return String(cfg.roguehotspotname);
  else if (key == "Extender_SSID")    return String(cfg.Extender_SSID);
  else if (key == "Extender_Password")return String(cfg.Extender_Password);
  else if (key == "Extender_Timeout") return String(cfg.Extender_Timeout);
  else if (key == "Extender_Status")  return String(cfg.Extender_Status);
  else if (key == "Extended_SSID")    return String(cfg.Extended_SSID);
  else if (key == "Extended_Password")return String(cfg.Extended_Password);
  else if (key == "Internet_SSID")    return String(cfg.Internet_SSID);
  else if (key == "Internet_Password")return String(cfg.Internet_Password);
  else if (key == "Attack_Mode")      return String(cfg.Attack_Mode);
  else if (key == "Deauth_Mode")      return String(cfg.Deauth_Mode);
  else if (key == "Etwin_Path")       return String(cfg.Etwin_Path);
  else if (key == "Rogue_Path")       return String(cfg.Rogue_Path);
  else if (key == "target_ssid")      return String(cfg.target_ssid);
  else if (key == "target_bssid")     return formatMAC(cfg.target_bssid);
  else if (key == "target_ch")        return String(cfg.target_ch);
  else if (key == "CurrentTarget")    return String(cfg.CurrentTarget);
  else if (key == "guard_behavior")   return String(cfg.guard_behavior);
  else if (key == "Language")         return String(cfg.Language);
  else if (key == "OLED_Timeout")     return String(cfg.OLED_Timeout);
  else if (key == "OLED_Interval")    return String(cfg.OLED_Interval);
  else if (key == "LED_Active")       return String(cfg.LED_Active ? "1" : "0");
  else if (key == "Resume_Active")    return String(cfg.Resume_Active ? "1" : "0");
  else if (key == "Powersave_Active") return String(cfg.Powersave_Active ? "1" : "0");
  else if (key == "Pattern_Lock")     return String(cfg.Pattern_Lock);
  else if (key == "customMAC")        return String(cfg.customMAC);
  else if (key == "peerAddress")      return String(cfg.peerAddress);
  else if (key == "deauthDelay")      return String(cfg.deauthDelay);
  else if (key == "scanduration")     return String(cfg.scanduration);
  return "";
}

#endif // CONFIG_H
