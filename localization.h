#ifndef LOCALIZATION_H
#define LOCALIZATION_H

#include <Arduino.h>

// ============================================================
// TamsDeauth - Localization / Multi-Language Support
// Supports: English (en), Indonesian/Bahasa (id)
// Uses %KEY% placeholder system in HTML templates
// ============================================================

struct LangEntry {
  const char* key;
  const char* en;
  const char* id;
};

// All localization strings found in original firmware
static const LangEntry langTable[] = {
  // Captive portal strings
  {"%PASSWORD%",        "Password",                          "Password"},
  {"%RECONNECTING%",    "Reconnecting...",                   "Menghubungkan ulang..."},
  {"%REC_FAILED%",      "Reconnect failed!",                 "Gagal menghubungkan ulang!"},
  {"%RETRYING%",        "Retrying",                          "Mencoba lagi"},
  {"%LOWSIGNAL%",       "Low signal",                        "Sinyal lemah"},
  {"%PLEASEWAIT%",      "Please wait",                       "Mohon tunggu"},
  {"%INCORRECT%",       "Password incorrect!",               "Password salah!"},
  {"%ERRORHEADER%",     "Error",                             "Error"},
  {"%REENTER%",         "Re-enter password",                 "Masukkan ulang password"},
  {"%REENTER2%",        "Please re-enter password to continue.", "Masukkan password Wi-Fi untuk melanjutkan."},
  {"%SUBMIT%",          "Submit",                            "Kirim"},
  {"%ADDITIONAL%",      "Additional",                        "Tambahan"},
  {"%BACKBUTTON%",      "Back",                              "Kembali"},
  
  // File system strings
  {"%FREESPACE%",       "Free space",                        "Ruang bebas"},
  {"%TOTALSPACE%",      "Total space",                       "Total ruang"},
  {"%LINEBK%",       "",                                  ""},
  {"%NOTIFICATION%",    "Notification",                      "Notifikasi"},
  
  // Menu labels
  {"%SCAN%",            "SCAN",                              "SCAN"},
  {"%DEAUTH%",          "DEAUTH",                            "DEAUTH"},
  {"%CLEAR_ARRAY%",     "CLEAR",                             "BERSIHKAN"},
};

static const int langTableSize = sizeof(langTable) / sizeof(LangEntry);

// Get localized string by key
// lang: "en" or "id"
String getLocalizedString(const String& key, const String& lang) {
  for (int i = 0; i < langTableSize; i++) {
    if (key == langTable[i].key) {
      if (lang == "id" && strlen(langTable[i].id) > 0) {
        return String(langTable[i].id);
      }
      return String(langTable[i].en);
    }
  }
  return key; // Return key itself if not found
}

// Replace all %KEY% placeholders in HTML template with localized strings
String localizeHTML(String html, const String& lang) {
  int pos = 0;
  while (true) {
    int start = html.indexOf('%', pos);
    if (start == -1) break;
    int end = html.indexOf('%', start + 1);
    if (end == -1) break;
    
    String key = html.substring(start, end + 1); // includes both %
    String replacement = getLocalizedString(key, lang);
    
    if (replacement != key) {
      html.replace(key, replacement);
      pos = start + replacement.length();
    } else {
      pos = end + 1;
    }
  }
  return html;
}

// Get current language from config
extern char currentLanguage[8];

String loc(const String& key) {
  return getLocalizedString(key, String(currentLanguage));
}

// Day names
const char* getDayName(int dayOfWeek, bool indonesian) {
  if (indonesian) {
    const char* days[] = {"Minggu","Senin","Selasa","Rabu","Kamis","Jumat","Sabtu"};
    return days[dayOfWeek % 7];
  } else {
    const char* days[] = {"Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"};
    return days[dayOfWeek % 7];
  }
}

// Month names
const char* getMonthName(int month, bool indonesian) {
  if (indonesian) {
    const char* months[] = {"Januari","Februari","Maret","April","Mei","Juni",
                            "Juli","Agustus","September","Oktober","November","Desember"};
    return months[(month - 1) % 12];
  } else {
    const char* months[] = {"January","February","March","April","May","June",
                            "July","August","September","October","November","December"};
    return months[(month - 1) % 12];
  }
}

#endif // LOCALIZATION_H
