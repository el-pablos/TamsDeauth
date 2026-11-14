#ifndef ESPNOW_CTRL_H
#define ESPNOW_CTRL_H

#include <Arduino.h>
#include <ESP8266WiFi.h>
extern "C" {
  #include <espnow.h>
}

// ============================================================
// TamsDeauth - ESP-NOW Remote Control
// Allows remote triggering of attacks via ESP-NOW protocol
// Commands match original: ESPNOW_QC=xxx
// ============================================================

// ESP-NOW command IDs
#define ESPNOW_CMD_TARGET_SYNC   1
#define ESPNOW_CMD_DEAUTH_ON     2
#define ESPNOW_CMD_DEAUTH_OFF    3
#define ESPNOW_CMD_DEAUTHALL_ON  4
#define ESPNOW_CMD_DEAUTHALL_OFF 5
#define ESPNOW_CMD_ROGUEAP_START 6
#define ESPNOW_CMD_SOFTAP_HIDE   7
#define ESPNOW_CMD_SOFTAP_SHOW   8
#define ESPNOW_CMD_REBOOT        9
#define ESPNOW_CMD_PAUSE         10
#define ESPNOW_CMD_CANCEL        11
#define ESPNOW_CMD_PING          12
#define ESPNOW_CMD_PONG          13

// ESPNOW_QC command strings for web interface
#define QC_TARGET_SYNC   "target_sync"
#define QC_DEAUTH_ON     "deauth_on"
#define QC_DEAUTH_OFF    "deauth_off"
#define QC_DEAUTHALL_ON  "deauthall_on"
#define QC_DEAUTHALL_OFF "deauthall_off"
#define QC_ROGUEAP_START "rogueap_start"
#define QC_SOFTAP_HIDE   "softap_hide"
#define QC_SOFTAP_SHOW   "softap_show"
#define QC_REBOOT        "reboot"

// Message structure for ESP-NOW communication
#define ESPNOW_MSG_LEN 32
struct EspNowMsg {
  uint8_t cmd;
  uint8_t target_bssid[6];
  uint8_t target_ch;
  uint8_t padding[24];
} __attribute__((packed));

// Peer info
uint8_t espnowPeer[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; // broadcast
bool espnowInitialized = false;
bool espnowPeerAdded = false;

// Forward declarations from attacks.h
extern void startDeauthAttack();
extern void stopDeauthAttack();
extern void startDeauthAllAttack();
extern void stopDeauthAllAttack();
extern void startRogueAP();
extern void stopAllAttacks();

// Forward declarations from main
extern void hideSoftAP();
extern void showSoftAP();
extern void doReboot();

// ESP-NOW receive callback
static void espnowRecvCallback(uint8_t *mac_addr, uint8_t *data, uint8_t len) {
  if (len < 1) return;
  
  Serial.printf("[ESP-NOW] Received from %02X:%02X:%02X:%02X:%02X:%02X, cmd=%d\n",
    mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5], data[0]);
  
  uint8_t cmd = data[0];
  
  switch (cmd) {
    case ESPNOW_CMD_TARGET_SYNC:
      // Sync target from remote device
      if (len >= sizeof(EspNowMsg)) {
        EspNowMsg* msg = (EspNowMsg*)data;
        // Update target BSSID and channel
        // setTarget(msg->target_bssid, msg->target_ch);
        Serial.println("[ESP-NOW] Target sync received");
      }
      break;
    case ESPNOW_CMD_DEAUTH_ON:
      Serial.println("[ESP-NOW] Starting deauth");
      startDeauthAttack();
      break;
    case ESPNOW_CMD_DEAUTH_OFF:
      Serial.println("[ESP-NOW] Stopping deauth");
      stopDeauthAttack();
      break;
    case ESPNOW_CMD_DEAUTHALL_ON:
      Serial.println("[ESP-NOW] Starting deauth all");
      startDeauthAllAttack();
      break;
    case ESPNOW_CMD_DEAUTHALL_OFF:
      Serial.println("[ESP-NOW] Stopping deauth all");
      stopDeauthAllAttack();
      break;
    case ESPNOW_CMD_ROGUEAP_START:
      Serial.println("[ESP-NOW] Starting rogue AP");
      startRogueAP();
      break;
    case ESPNOW_CMD_SOFTAP_HIDE:
      Serial.println("[ESP-NOW] Hiding softAP");
      hideSoftAP();
      break;
    case ESPNOW_CMD_SOFTAP_SHOW:
      Serial.println("[ESP-NOW] Showing softAP");
      showSoftAP();
      break;
    case ESPNOW_CMD_REBOOT:
      Serial.println("[ESP-NOW] Rebooting");
      doReboot();
      break;
    case ESPNOW_CMD_PING:
      // Respond with pong
      {
        uint8_t pong = ESPNOW_CMD_PONG;
        esp_now_send(espnowPeer, &pong, 1);
      }
      break;
    default:
      Serial.printf("[ESP-NOW] Unknown command: %d\n", cmd);
  }
}

// ESP-NOW send callback
static void espnowSendCallback(uint8_t *mac_addr, uint8_t status) {
  // Status: 0 = success
}

// Initialize ESP-NOW
bool initEspNow() {
  if (esp_now_init() != 0) {
    Serial.println("[ESP-NOW] Init failed");
    return false;
  }
  
  esp_now_set_self_role(ESP_NOW_ROLE_COMBO);
  esp_now_register_recv_cb(espnowRecvCallback);
  esp_now_register_send_cb(espnowSendCallback);
  
  // Add broadcast peer
  if (esp_now_add_peer(espnowPeer, ESP_NOW_ROLE_COMBO, 1, NULL, 0) == 0) {
    espnowPeerAdded = true;
    Serial.println("[ESP-NOW] Broadcast peer added");
  }
  
  espnowInitialized = true;
  Serial.println("[ESP-NOW] Initialized");
  return true;
}

// Send ESP-NOW command
void sendEspNowCommand(uint8_t cmd, const uint8_t* bssid = NULL, uint8_t ch = 0) {
  if (!espnowInitialized) return;
  
  EspNowMsg msg;
  memset(&msg, 0, sizeof(msg));
  msg.cmd = cmd;
  if (bssid) memcpy(msg.target_bssid, bssid, 6);
  msg.target_ch = ch;
  
  esp_now_send(espnowPeer, (uint8_t*)&msg, sizeof(msg));
}

// Process ESPNOW_QC web command
String processEspNowQC(const String& qcCommand) {
  String response = "";
  
  if (qcCommand == QC_TARGET_SYNC) {
    sendEspNowCommand(ESPNOW_CMD_TARGET_SYNC);
    response = "TARGET SET OK!";
  } else if (qcCommand == QC_DEAUTH_ON) {
    sendEspNowCommand(ESPNOW_CMD_DEAUTH_ON);
    startDeauthAttack();
    response = "DEAUTH ON";
  } else if (qcCommand == QC_DEAUTH_OFF) {
    sendEspNowCommand(ESPNOW_CMD_DEAUTH_OFF);
    stopDeauthAttack();
    response = "DEAUTH OFF";
  } else if (qcCommand == QC_DEAUTHALL_ON) {
    sendEspNowCommand(ESPNOW_CMD_DEAUTHALL_ON);
    startDeauthAllAttack();
    response = "DEAUTHALL ON";
  } else if (qcCommand == QC_DEAUTHALL_OFF) {
    sendEspNowCommand(ESPNOW_CMD_DEAUTHALL_OFF);
    stopDeauthAllAttack();
    response = "DEAUTHALL OFF";
  } else if (qcCommand == QC_ROGUEAP_START) {
    sendEspNowCommand(ESPNOW_CMD_ROGUEAP_START);
    startRogueAP();
    response = "ROGUEAP START";
  } else if (qcCommand == QC_SOFTAP_HIDE) {
    sendEspNowCommand(ESPNOW_CMD_SOFTAP_HIDE);
    hideSoftAP();
    response = "AP HIDDEN";
  } else if (qcCommand == QC_SOFTAP_SHOW) {
    sendEspNowCommand(ESPNOW_CMD_SOFTAP_SHOW);
    showSoftAP();
    response = "AP VISIBLE";
  } else if (qcCommand == QC_REBOOT) {
    sendEspNowCommand(ESPNOW_CMD_REBOOT);
    response = "REBOOTING";
    delay(500);
    ESP.restart();
  } else {
    response = "UNKNOWN COMMAND";
  }
  
  Serial.printf("[ESPNOW_QC] %s => %s\n", qcCommand.c_str(), response.c_str());
  return response;
}

// Add a specific peer by MAC
bool addEspNowPeer(const uint8_t* mac) {
  if (!espnowInitialized) return false;
  return (esp_now_add_peer((uint8_t*)mac, ESP_NOW_ROLE_COMBO, 1, NULL, 0) == 0);
}

// Deinit ESP-NOW
void deinitEspNow() {
  if (espnowInitialized) {
    esp_now_deinit();
    espnowInitialized = false;
    espnowPeerAdded = false;
  }
}

#endif // ESPNOW_CTRL_H
