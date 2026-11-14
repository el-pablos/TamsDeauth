#ifndef SNIFFER_H
#define SNIFFER_H

#include <Arduino.h>
#include <ESP8266WiFi.h>
#include "user_interface.h"
#include "espconn.h"
// beacon.h not available in all ESP8266 core versions; skip safely

// ============================================================
// TamsDeauth - Packet Sniffer & Station Counter
// Uses ESP8266 promiscuous mode for 802.11 frame capture
// ============================================================

// Sniffer modes
enum SnifferMode {
  SNIFF_NONE = 0,
  SNIFF_ALL,      // Capture all packets
  SNIFF_PROBE,    // Capture probe requests only
  SNIFF_DEAUTH,   // Detect deauth frames (deauthmon)
  SNIFF_STATION,  // Observe stations (count stations on target)
};

// 802.11 frame types
#define FRAME_TYPE_MANAGEMENT 0x00
#define FRAME_TYPE_CONTROL    0x01
#define FRAME_TYPE_DATA       0x02

// Management subtypes
#define SUBTYPE_BEACON        0x08
#define SUBTYPE_PROBE_REQ     0x04
#define SUBTYPE_PROBE_RESP    0x05
#define SUBTYPE_DEAUTH        0x0C
#define SUBTYPE_DISASSOC      0x0A
#define SUBTYPE_ASSOC_REQ     0x00
#define SUBTYPE_ASSOC_RESP    0x01
#define SUBTYPE_AUTH          0x0B

// WiFi packet header structure (ESP8266 specific)
struct wifi_rx_packet_t {
  struct {
    uint16_t rssi;
    uint8_t rate;
    uint8_t sig_mode;
    uint16_t mcs;
    uint8_t cwb;
    uint16_t padding;
    uint8_t ampdu;
    uint8_t stbc;
    uint8_t not_sounding;
    uint8_t order;
    uint8_t ndp;
    uint8_t aggregation;
    uint8_t timestamp;
    uint8_t fec;
    uint16_t sgi;
    uint8_t rxend_state;
    uint8_t ampdu_spat;
    uint16_t agg_len;
    uint8_t agg_snr;
    uint8_t noise_floor;
  } rx_ctrl;
  uint8_t data[];
} __attribute__((packed));

// Simplified 802.11 MAC header
struct wifi_ieee80211_mac_hdr_t {
  uint8_t frame_ctrl[2];
  uint8_t duration[2];
  uint8_t addr1[6];  // DA / BSSID
  uint8_t addr2[6];  // SA / BSSID
  uint8_t addr3[6];  // BSSID / SA
  uint8_t seq_ctrl[2];
} __attribute__((packed));

// Station info for counting
#define MAX_STATIONS 32
struct StationInfo {
  uint8_t mac[6];
  uint8_t channel;
  int16_t rssi;
  uint32_t packet_count;
  uint32_t last_seen;
  bool active;
};

// Global state
volatile SnifferMode currentSniffMode = SNIFF_NONE;
volatile uint32_t sniffPacketCount = 0;
volatile uint32_t sniffPacketsPerSec = 0;
volatile uint32_t sniffLastPacketTime = 0;
volatile uint32_t sniffDeauthCount = 0;
volatile uint32_t sniffProbeCount = 0;
volatile uint32_t sniffBeaconCount = 0;

// Station list
StationInfo stationList[MAX_STATIONS];
int stationCount = 0;

// Target AP info for station counting
uint8_t targetAP_bssid[6] = {0};
uint8_t targetAP_channel = 0;

// Channel hopping state
uint8_t currentChannel = 1;
uint32_t lastChannelHop = 0;
#define CHANNEL_HOP_INTERVAL 200 // ms

// Deauth detection log
#define MAX_DEAUTH_LOG 20
struct DeauthLog {
  uint8_t src[6];
  uint8_t dst[6];
  uint8_t channel;
  int16_t rssi;
  uint32_t timestamp;
};
DeauthLog deauthLog[MAX_DEAUTH_LOG];
int deauthLogIndex = 0;

// ---- Promiscuous callback ----
static void ICACHE_FLASH_ATTR snifferCallback(uint8_t *buf, uint16_t len) {
  if (currentSniffMode == SNIFF_NONE) return;
  
  sniffPacketCount++;
  sniffLastPacketTime = millis();
  
  // Parse the packet header
  if (len < sizeof(wifi_rx_packet_t)) return;
  
  wifi_rx_packet_t* pkt = (wifi_rx_packet_t*)buf;
  int16_t rssi = pkt->rx_ctrl.rssi;
  
  // Get the IEEE 802.11 frame
  uint8_t* frame = pkt->data;
  int frame_len = len - sizeof(wifi_rx_packet_t);
  
  if (frame_len < 2) return;
  
  uint8_t frame_type = (frame[0] >> 2) & 0x03;
  uint8_t frame_subtype = (frame[0] >> 4) & 0x0F;
  
  if (frame_type == FRAME_TYPE_MANAGEMENT) {
    if (frame_subtype == SUBTYPE_BEACON) {
      sniffBeaconCount++;
    } else if (frame_subtype == SUBTYPE_PROBE_REQ) {
      sniffProbeCount++;
    } else if (frame_subtype == SUBTYPE_DEAUTH || frame_subtype == SUBTYPE_DISASSOC) {
      sniffDeauthCount++;
      
      // Log deauth
      if (frame_len >= sizeof(wifi_ieee80211_mac_hdr_t)) {
        wifi_ieee80211_mac_hdr_t* mac = (wifi_ieee80211_mac_hdr_t*)frame;
        DeauthLog* entry = &deauthLog[deauthLogIndex % MAX_DEAUTH_LOG];
        memcpy(entry->src, mac->addr2, 6);
        memcpy(entry->dst, mac->addr1, 6);
        entry->channel = wifi_get_channel();
        entry->rssi = rssi;
        entry->timestamp = millis();
        deauthLogIndex++;
      }
    }
    
    // Station observation mode
    if (currentSniffMode == SNIFF_STATION && targetAP_bssid[0] != 0) {
      if (frame_len >= sizeof(wifi_ieee80211_mac_hdr_t)) {
        wifi_ieee80211_mac_hdr_t* mac = (wifi_ieee80211_mac_hdr_t*)frame;
        
        // Check if this packet involves our target AP
        bool matchTarget = (memcmp(mac->addr1, targetAP_bssid, 6) == 0 ||
                           memcmp(mac->addr2, targetAP_bssid, 6) == 0 ||
                           memcmp(mac->addr3, targetAP_bssid, 6) == 0);
        
        if (matchTarget) {
          // Extract station MAC (the one that's not the AP and not broadcast)
          uint8_t* sta_mac = NULL;
          if (memcmp(mac->addr1, targetAP_bssid, 6) != 0 && 
              memcmp(mac->addr1, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) != 0) {
            sta_mac = mac->addr1;
          } else if (memcmp(mac->addr2, targetAP_bssid, 6) != 0 &&
                     memcmp(mac->addr2, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) != 0) {
            sta_mac = mac->addr2;
          }
          
          if (sta_mac) {
            // Add or update station
            bool found = false;
            for (int i = 0; i < stationCount; i++) {
              if (stationList[i].active && memcmp(stationList[i].mac, sta_mac, 6) == 0) {
                stationList[i].packet_count++;
                stationList[i].last_seen = millis();
                stationList[i].rssi = rssi;
                found = true;
                break;
              }
            }
            if (!found && stationCount < MAX_STATIONS) {
              memcpy(stationList[stationCount].mac, sta_mac, 6);
              stationList[stationCount].channel = wifi_get_channel();
              stationList[stationCount].rssi = rssi;
              stationList[stationCount].packet_count = 1;
              stationList[stationCount].last_seen = millis();
              stationList[stationCount].active = true;
              stationCount++;
            }
          }
        }
      }
    }
  }
}

// ---- Sniffer control functions ----

void startSniffer(SnifferMode mode) {
  if (currentSniffMode != SNIFF_NONE) {
    // Already running, stop first
    wifi_set_opmode_current(STATION_MODE);
    wifi_set_promiscuous(false);
    delay(100);
  }
  
  currentSniffMode = mode;
  sniffPacketCount = 0;
  sniffDeauthCount = 0;
  sniffProbeCount = 0;
  sniffBeaconCount = 0;
  
  // Disconnect from any AP
  WiFi.disconnect();
  delay(100);
  
  // Set to station mode for promiscuous
  wifi_set_opmode_current(STATION_MODE);
  
  // Set channel to target or channel 1
  if (targetAP_channel > 0) {
    wifi_set_channel(targetAP_channel);
    currentChannel = targetAP_channel;
  } else {
    wifi_set_channel(1);
    currentChannel = 1;
  }
  
  // Enable promiscuous mode
  wifi_set_promiscuous_rx_cb(snifferCallback);
  wifi_set_promiscuous(true);
  
  Serial.printf("[ SNIFF ] Mode %d started on channel %d\n", mode, currentChannel);
}

void stopSniffer() {
  if (currentSniffMode != SNIFF_NONE) {
    wifi_set_promiscuous(false);
    wifi_set_promiscuous_rx_cb(NULL);
    currentSniffMode = SNIFF_NONE;
    Serial.println("[ SYSTEM ] SNIFFER STOPPED");
  }
}

// Channel hopping for broad monitoring
void updateChannelHop() {
  if (currentSniffMode == SNIFF_NONE) return;
  
  // Only hop if in deauth monitor or all-packet mode
  if (currentSniffMode == SNIFF_DEAUTH || currentSniffMode == SNIFF_ALL) {
    if (millis() - lastChannelHop > CHANNEL_HOP_INTERVAL) {
      currentChannel++;
      if (currentChannel > 13) currentChannel = 1;
      wifi_set_channel(currentChannel);
      lastChannelHop = millis();
    }
  }
  
  // Calculate packets per second
  static uint32_t lastCount = 0;
  static uint32_t lastCalc = 0;
  if (millis() - lastCalc >= 1000) {
    sniffPacketsPerSec = sniffPacketCount - lastCount;
    lastCount = sniffPacketCount;
    lastCalc = millis();
  }
}

// Clear station list
void clearStations() {
  stationCount = 0;
  memset(stationList, 0, sizeof(stationList));
}

// Set target AP for station observation
void setSnifferTarget(const uint8_t* bssid, uint8_t channel) {
  memcpy(targetAP_bssid, bssid, 6);
  targetAP_channel = channel;
}

// Get station list as HTML table rows
String getStationListHTML() {
  String html = "";
  for (int i = 0; i < stationCount; i++) {
    if (!stationList[i].active) continue;
    if (millis() - stationList[i].last_seen > 30000) continue; // skip stale
    
    html += "<tr>";
    // BSSID
    html += "<td>";
    for (int j = 0; j < 6; j++) {
      if (j > 0) html += ":";
      html += String(stationList[i].mac[j], HEX);
    }
    html += "</td>";
    // Data packets
    html += "<td>" + String(stationList[i].packet_count) + "</td>";
    // Select checkbox
    html += "<td><input type='checkbox' class='row-checkbox' name='mac_" + String(i) + "' value='";
    for (int j = 0; j < 6; j++) {
      if (j > 0) html += ":";
      html += String(stationList[i].mac[j], HEX);
    }
    html += "'></td>";
    html += "<td><button class='delete-btn'>Delete</button></td>";
    html += "</tr>\n";
  }
  return html;
}

// Get deauth log as text
String getDeauthLogText() {
  String text = "";
  int count = (deauthLogIndex < MAX_DEAUTH_LOG) ? deauthLogIndex : MAX_DEAUTH_LOG;
  for (int i = 0; i < count; i++) {
    DeauthLog* entry = &deauthLog[i];
    text += "[Deauth] ";
    for (int j = 0; j < 6; j++) {
      if (j > 0) text += ":";
      text += String(entry->src[j], HEX);
    }
    text += " -> ";
    for (int j = 0; j < 6; j++) {
      if (j > 0) text += ":";
      text += String(entry->dst[j], HEX);
    }
    text += " CH:" + String(entry->channel) + " RSSI:" + String(entry->rssi) + "\n";
  }
  return text;
}

#endif // SNIFFER_H
