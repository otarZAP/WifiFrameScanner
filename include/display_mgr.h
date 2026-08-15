#pragma once
#include <stdint.h>
#include <stdbool.h>

enum DisplayView : uint8_t {
    VIEW_STATUS   = 0,   // channel, frame rate, AP/client counts, LoRa RSSI
    VIEW_NETWORKS = 1,   // scrolling AP list: SSID, enc, RSSI, channel
    VIEW_CLIENTS  = 2,   // scrolling client list: MAC, vendor, probe SSIDs
    VIEW_ACTIVITY = 3,   // live frame type counters
    VIEW_COUNT    = 4,
};

void displayInit();
void displayShowBoot();
void displayCycleView();

// Main refresh — call from loop()
void displayUpdate(DisplayView view,
                   uint8_t channel, bool hopping, bool pcap_mode,
                   uint8_t ap_count, uint8_t client_count,
                   uint32_t frames_total, uint32_t deauth_count,
                   int16_t lora_rssi);

// Flash a one-line alert for a few seconds (new AP, deauth, etc.)
void displayAlert(const char* line1, const char* line2);
