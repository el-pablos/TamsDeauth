#ifndef FILESYSTEM_H
#define FILESYSTEM_H

#include <Arduino.h>
#include <LittleFS.h>
#include <ESP8266WebServer.h>

// ============================================================
// TamsDeauth - LittleFS File System Browser
// Provides /fsbrowser route for file upload/download/delete
// and /filecontent for reading/writing file contents
// ============================================================

extern ESP8266WebServer server;

// Format bytes to human readable
String formatBytes(size_t bytes) {
  if (bytes < 1024) return String(bytes) + " B";
  else if (bytes < (1024 * 1024)) return String(bytes / 1024.0) + " KB";
  else return String(bytes / 1024.0 / 1024.0) + " MB";
}

// Get file size
size_t getFileSize(const String& path) {
  File f = LittleFS.open(path, "r");
  if (!f) return 0;
  size_t size = f.size();
  f.close();
  return size;
}

// Check if file exists
bool fileExists(const String& path) {
  return LittleFS.exists(path);
}

// Read file content as string
String readFileContent(const String& path) {
  File f = LittleFS.open(path, "r");
  if (!f) return "";
  String content = f.readString();
  f.close();
  return content;
}

// Write string to file
bool writeFileContent(const String& path, const String& content) {
  File f = LittleFS.open(path, "w");
  if (!f) return false;
  f.print(content);
  f.close();
  return true;
}

// Delete file
bool deleteFile(const String& path) {
  return LittleFS.remove(path);
}

// File system browser HTML page
// Generates the file manager interface
String getFsBrowserHTML() {
  String html = "<!DOCTYPE html><html><head>";
  html += "<meta charset='UTF-8'>";
  html += "<meta name='viewport' content='width=device-width, initial-scale=1'>";
  html += "<title>File Manager</title>";
  html += "<link rel='stylesheet' href='TamsDeauth.css'>";
  html += "<style>";
  html += "body { background: #1a1a2e; color: #eee; font-family: Arial; margin: 20px; }";
  html += "table { width: 100%; border-collapse: collapse; }";
  html += "th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #333; }";
  html += "th { background: #16213e; color: #7db5ff; }";
  html += "button { background: #0e5cc2; color: white; border: none; padding: 5px 10px; ";
  html += "border-radius: 3px; cursor: pointer; font-size: 11px; }";
  html += "button:hover { background: #1a6ee0; }";
  html += ".upload-area { margin: 20px 0; padding: 15px; background: #16213e; border-radius: 5px; }";
  html += "input[type=file] { color: white; }";
  html += "h1 { color: #7db5ff; }";
  html += "</style></head><body>";
  html += "<h1>File Manager</h1>";
  
  // Upload form
  html += "<div class='upload-area'>";
  html += "<form method='post' action='/fsbrowser' enctype='multipart/form-data'>";
  html += "<input type='file' name='upload' multiple>";
  html += "<button type='submit'>UPLOAD</button>";
  html += "</form>";
  html += "</div>";
  
  // File info
  FSInfo fs_info;
  LittleFS.info(fs_info);
  html += "<p>Used: " + formatBytes(fs_info.usedBytes) + " / " + formatBytes(fs_info.totalBytes) + "</p>";
  
  // File table
  html += "<table><thead><tr><th>NAME</th><th>SIZE</th><th style='width:0%;'>SELECT</th></tr></thead><tbody>";
  
  Dir dir = LittleFS.openDir("/");
  while (dir.next()) {
    String name = dir.fileName();
    size_t size = dir.fileSize();
    html += "<tr>";
    html += "<td>" + name + "</td>";
    html += "<td>" + formatBytes(size) + "</td>";
    html += "<td>";
    // Select button (for assigning to etwin/rogue templates)
    html += "<form style='display:inline;' method='post' action='/?file=" + name + "'>";
    html += "<button type='submit'>SELECT</button>";
    html += "</form>";
    // Delete button
    html += "<form style='display:inline;' method='post' action='/delete?file=" + name + "'>";
    html += "<button type='submit' style='background-color:#c20e0e;color:white;'>DELETE</button>";
    html += "</form>";
    html += "</td>";
    html += "</tr>";
  }
  
  html += "</tbody></table>";
  html += "<br><form style='display:inline-block;' method='post' action='/'><button>BACK</button></form>";
  html += "</body></html>";
  return html;
}

// Handle file upload via multipart form
void handleFileUpload() {
  HTTPUpload& upload = server.upload();
  
  if (upload.status == UPLOAD_FILE_START) {
    String filename = upload.filename;
    if (!filename.startsWith("/")) filename = "/" + filename;
    Serial.printf("[FS] Upload start: %s\n", filename.c_str());
    // Open file for writing
    upload.currentName = filename;
    File fsUploadFile = LittleFS.open(filename, "w");
    // Store file handle - ESP8266WebServer handles this internally
  } else if (upload.status == UPLOAD_FILE_WRITE) {
    // Write data
    File fsUploadFile = LittleFS.open(upload.currentName, "a");
    if (fsUploadFile) {
      fsUploadFile.write(upload.buf, upload.currentSize);
      fsUploadFile.close();
    }
  } else if (upload.status == UPLOAD_FILE_END) {
    Serial.printf("[FS] Upload end: %s (%u bytes)\n", upload.currentName.c_str(), upload.totalSize);
  }
}

// Serve a file from LittleFS
bool serveFile(const String& path) {
  String contentType;
  
  if (path.endsWith(".html")) contentType = "text/html";
  else if (path.endsWith(".css")) contentType = "text/css";
  else if (path.endsWith(".js")) contentType = "application/javascript";
  else if (path.endsWith(".json")) contentType = "application/json";
  else if (path.endsWith(".txt")) contentType = "text/plain";
  else if (path.endsWith(".woff2")) contentType = "application/font-woff2";
  else if (path.endsWith(".mp3")) contentType = "audio/mpeg";
  else if (path.endsWith(".ico")) contentType = "image/x-icon";
  else if (path.endsWith(".bin")) contentType = "application/octet-stream";
  else if (path.endsWith(".woff")) contentType = "application/font-woff";
  else if (path.endsWith(".ttf")) contentType = "application/x-font-ttf";
  else if (path.endsWith(".svg")) contentType = "image/svg+xml";
  else if (path.endsWith(".jpg")) contentType = "image/jpeg";
  else if (path.endsWith(".png")) contentType = "image/png";
  else if (path.endsWith(".gif")) contentType = "image/gif";
  else contentType = "application/octet-stream";
  
  String fullPath = path;
  if (!fullPath.startsWith("/")) fullPath = "/" + fullPath;
  
  if (LittleFS.exists(fullPath)) {
    File f = LittleFS.open(fullPath, "r");
    if (f) {
      server.streamFile(f, contentType);
      f.close();
      return true;
    }
  }
  
  // If .gz version exists
  if (LittleFS.exists(fullPath + ".gz")) {
    File f = LittleFS.open(fullPath + ".gz", "r");
    if (f) {
      server.sendHeader("Content-Encoding", "gzip");
      server.streamFile(f, contentType);
      f.close();
      return true;
    }
  }
  
  return false;
}

// Handle /filecontent route - read or write file content
void handleFileContent() {
  if (server.hasArg("file")) {
    String filename = server.arg("file");
    if (!filename.startsWith("/")) filename = "/" + filename;
    
    if (server.method() == HTTP_GET) {
      // Read file content
      String content = readFileContent(filename);
      if (content.length() > 0) {
        server.send(200, "text/plain", content);
      } else {
        server.send(404, "text/plain", "File not found");
      }
    } else if (server.method() == HTTP_POST) {
      // Write file content
      if (server.hasArg("content")) {
        String content = server.arg("content");
        if (writeFileContent(filename, content)) {
          server.send(200, "text/plain", "Saved");
        } else {
          server.send(500, "text/plain", "Write failed");
        }
      }
    }
  } else {
    server.send(400, "text/plain", "Missing file parameter");
  }
}

// Handle /delete route
void handleDelete() {
  if (server.hasArg("file")) {
    String filename = server.arg("file");
    if (!filename.startsWith("/")) filename = "/" + filename;
    
    if (deleteFile(filename)) {
      server.send(200, "text/html", "<script>setTimeout(function(){window.location.href='/fsbrowser';},500);</script>");
    } else {
      server.send(500, "text/plain", "Delete failed");
    }
  } else {
    server.send(400, "text/plain", "Missing file parameter");
  }
}

// Handle /save route - save text file
void handleSave() {
  if (server.hasArg("filename") && server.hasArg("content")) {
    String filename = server.arg("filename");
    String content = server.arg("content");
    if (!filename.startsWith("/")) filename = "/" + filename;
    
    if (writeFileContent(filename, content)) {
      server.send(200, "text/plain", "OK");
    } else {
      server.send(500, "text/plain", "Failed");
    }
  } else {
    server.send(400, "text/plain", "Missing parameters");
  }
}

// Text editor page
String getTextEditorHTML(const String& filename) {
  String html = "<!DOCTYPE html><html><head>";
  html += "<meta charset='UTF-8'>";
  html += "<meta name='viewport' content='width=device-width, initial-scale=1'>";
  html += "<title>Text Editor - " + filename + "</title>";
  html += "<link rel='stylesheet' href='TamsDeauth_minimal.css'>";
  html += "</head><body>";
  html += "<h1>Text Editor</h1>";
  html += "<form method='post' action='/save'>";
  html += "<input type='hidden' name='filename' value='" + filename + "'>";
  html += "<textarea name='content' style='width:100%;height:60vh;font-family:monospace;'>";
  
  if (fileExists(filename)) {
    html += readFileContent(filename);
  }
  
  html += "</textarea><br><br>";
  html += "<button type='submit'>SAVE</button> ";
  html += "<button type='button' onclick='window.location.href=\"/fsbrowser\"'>CANCEL</button>";
  html += "</form>";
  html += "</body></html>";
  return html;
}

#endif // FILESYSTEM_H
