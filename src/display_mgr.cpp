#include "display_mgr.h"
#include "config.h"
#include "net_tracker.h"
#include "frame_capture.h"
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <stdio.h>
#include <string.h>

static Adafruit_SSD1306 g_oled(OLED_WIDTH, OLED_HEIGHT, &Wire, OLED_RST);
static bool     g_ready       = false;
static uint32_t g_alert_ms    = 0;
static char     g_alert_l1[22];
static char     g_alert_l2[22];
static uint32_t g_scroll_ms   = 0;
static uint8_t  g_scroll_idx  = 0;
static const uint32_t ALERT_DUR = 3000;

static void oledReset() {
    pinMode(OLED_RST, OUTPUT);
    digitalWrite(OLED_RST, LOW); delay(10);
    digitalWrite(OLED_RST, HIGH); delay(10);
}

static void header(const char* title, bool pcap) {
    g_oled.fillRect(0, 0, 128, 11, SSD1306_WHITE);
    g_oled.setTextColor(SSD1306_BLACK);
    g_oled.setTextSize(1);
    g_oled.setCursor(2, 2);
    g_oled.print(title);
    if (pcap) {
        g_oled.setCursor(90, 2);
        g_oled.print("[PCAP]");
    }
    g_oled.setTextColor(SSD1306_WHITE);
}

void displayInit() {
    Wire.begin(OLED_SDA, OLED_SCL);
    oledReset();
    if (!g_oled.begin(SSD1306_SWITCHCAPVCC, OLED_ADDR)) {
        Serial.println("[OLED] Init failed");
        return;
    }
    g_oled.clearDisplay();
    g_oled.setTextColor(SSD1306_WHITE);
    g_oled.setTextSize(1);
    g_ready = true;
}

void displayShowBoot() {
    if (!g_ready) return;
    g_oled.clearDisplay();
    g_oled.setTextSize(2);
    g_oled.setCursor(2, 6);
    g_oled.print("SCANNER");
    g_oled.setTextSize(1);
    g_oled.setCursor(2, 30);
    g_oled.print("LoRa WiFi Scanner");
    g_oled.setCursor(2, 44);
    g_oled.print("Starting...");
    g_oled.display();
}

void displayCycleView() {
    // handled in main.cpp
}

void displayAlert(const char* l1, const char* l2) {
    strncpy(g_alert_l1, l1, sizeof(g_alert_l1) - 1);
    strncpy(g_alert_l2, l2, sizeof(g_alert_l2) - 1);
    g_alert_ms = millis();
}

void displayUpdate(DisplayView view,
                   uint8_t channel, bool hopping, bool pcap_mode,
                   uint8_t ap_count, uint8_t client_count,
                   uint32_t frames_total, uint32_t deauth_count,
                   int16_t lora_rssi) {
    if (!g_ready) return;

    // Flash alert if active
    if (g_alert_ms && (millis() - g_alert_ms) < ALERT_DUR) {
        g_oled.clearDisplay();
        g_oled.fillRect(0, 0, 128, 11, SSD1306_WHITE);
        g_oled.setTextColor(SSD1306_BLACK);
        g_oled.setCursor(2, 2); g_oled.print("! ALERT");
        g_oled.setTextColor(SSD1306_WHITE);
        g_oled.setCursor(2, 16); g_oled.print(g_alert_l1);
        g_oled.setCursor(2, 28); g_oled.print(g_alert_l2);
        g_oled.display();
        return;
    }
    g_alert_ms = 0;

    g_oled.clearDisplay();
    const CaptureStats* st = frameCaptureStats();

    // ── Advance scroll index on interval ──
    if (millis() - g_scroll_ms > SCROLL_INTERVAL_MS) {
        g_scroll_ms = millis();
        g_scroll_idx++;
    }

    switch (view) {

    // ── STATUS ──────────────────────────────────────────────────────────
    case VIEW_STATUS:
        header("SCANNER  STATUS", pcap_mode);
        g_oled.setCursor(2, 14);
        g_oled.printf("Ch: %2u  %s", channel, hopping ? "HOP" : "FIXED");
        g_oled.setCursor(2, 24);
        g_oled.printf("APs: %-3u  Clients: %-3u", ap_count, client_count);
        g_oled.setCursor(2, 34);
        g_oled.printf("Frames: %lu", frames_total);
        g_oled.setCursor(2, 44);
        g_oled.printf("Deauths: %lu", deauth_count);
        g_oled.setCursor(2, 54);
        if (lora_rssi != 0)
            g_oled.printf("LoRa: %d dBm", lora_rssi);
        else
            g_oled.print("LoRa: no contact");
        break;

    // ── NETWORKS ────────────────────────────────────────────────────────
    case VIEW_NETWORKS: {
        header("NETWORKS", pcap_mode);
        if (ap_count == 0) {
            g_oled.setCursor(2, 20); g_oled.print("Scanning...");
            break;
        }
        uint8_t start = g_scroll_idx % ap_count;
        uint8_t y = 14;
        for (uint8_t i = 0; i < 3 && y < 64; i++) {
            uint8_t idx = (start + i) % ap_count;
            const ApRecord* ap = netTrackerGetAp(idx);
            if (!ap || !ap->active) continue;
            char line[22];
            snprintf(line, sizeof(line), "%-14.14s %4s",
                     ap->hidden ? "(hidden)" : ap->ssid,
                     encName(ap->enc));
            g_oled.setCursor(2, y); g_oled.print(line);
            y += 10;
            snprintf(line, sizeof(line), " ch%-2u %ddBm", ap->channel, ap->rssi);
            g_oled.setCursor(2, y); g_oled.print(line);
            y += 10;
        }
        break;
    }

    // ── CLIENTS ─────────────────────────────────────────────────────────
    case VIEW_CLIENTS: {
        header("CLIENTS", pcap_mode);
        if (client_count == 0) {
            g_oled.setCursor(2, 20); g_oled.print("No clients yet...");
            break;
        }
        uint8_t start = g_scroll_idx % client_count;
        uint8_t y = 14;
        for (uint8_t i = 0; i < 2 && y < 64; i++) {
            uint8_t idx = (start + i) % client_count;
            const ClientRecord* cl = netTrackerGetClient(idx);
            if (!cl || !cl->active) continue;
            char mac[18];
            snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                     cl->mac[0], cl->mac[1], cl->mac[2],
                     cl->mac[3], cl->mac[4], cl->mac[5]);
            g_oled.setCursor(2, y); g_oled.print(mac);
            y += 10;
            char line[22];
            snprintf(line, sizeof(line), " %-8.8s %3ddBm",
                     cl->vendor, cl->rssi);
            g_oled.setCursor(2, y); g_oled.print(line);
            y += 10;
            if (cl->probe_count > 0) {
                snprintf(line, sizeof(line), " >%.18s", cl->probe_ssids[0]);
                g_oled.setCursor(2, y); g_oled.print(line);
                y += 10;
            }
        }
        break;
    }

    // ── ACTIVITY ────────────────────────────────────────────────────────
    case VIEW_ACTIVITY:
        header("ACTIVITY", pcap_mode);
        g_oled.setCursor(2, 14);
        g_oled.printf("Total:   %lu", st->total);
        g_oled.setCursor(2, 24);
        g_oled.printf("Mgmt:    %lu", st->mgmt);
        g_oled.setCursor(2, 34);
        g_oled.printf("Beacons: %lu", st->beacons);
        g_oled.setCursor(2, 44);
        g_oled.printf("Probes:  %lu", st->probes);
        g_oled.setCursor(2, 54);
        g_oled.printf("Deauths: %lu  Drop:%lu", st->deauths, st->dropped);
        break;

    default: break;
    }

    g_oled.display();
}
