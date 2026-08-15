// =============================================================================
//  WifiFrameScanner — Passive 802.11 Scanner with LoRa Telemetry
//  Heltec WiFi LoRa 32 V4 (ESP32-S3 + SX1262)
//
//  Kismet-style 802.11 passive scanner with:
//    - AP/client/association tracking with IE parsing
//    - Live frame statistics (beacons, probes, deauths, data)
//    - AES-256-EAX encrypted LoRa reporting to a base station
//    - Binary PCAP stream over USB serial → pipe directly to Wireshark
//
//  Modes (switchable at runtime):
//    SCAN mode  (default): channel-hops 1-13, human-readable serial, OLED stats
//    PCAP mode  (BTN_MODE hold 2s): pins to one channel, binary PCAP on serial
//    Fixed ch   (BTN_MODE short): stop hopping, stay on current channel
//
//  Wireshark live capture:
//    python scripts/scanner_pipe.py COM3 | wireshark -k -i -
//
//  Setup:
//    Copy include/secrets.example.h → include/secrets.h
//    pio run -t upload
// =============================================================================

#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <SPI.h>
#include <RadioLib.h>

#include "config.h"
#include "frame_capture.h"
#include "pcap_stream.h"
#include "net_tracker.h"
#include "lora_reporter.h"
#include "display_mgr.h"

// ─── LoRa radio ───────────────────────────────────────────────────────────
static SX1262 radio = new Module(
    LORA_NSS, LORA_DIO1, LORA_RST, LORA_BUSY
);

// ─── Runtime state ────────────────────────────────────────────────────────
static bool        g_pcap_mode   = DEFAULT_PCAP_MODE;
static bool        g_hop_mode    = DEFAULT_HOP_MODE;
static DisplayView g_view        = VIEW_STATUS;
static uint32_t    g_last_disp   = 0;
static uint32_t    g_last_expire = 0;

// ─── Button state ─────────────────────────────────────────────────────────
static uint32_t g_btn_view_down  = 0;
static uint32_t g_btn_mode_down  = 0;
static bool     g_btn_view_held  = false;
static bool     g_btn_mode_held  = false;

// ─── Net tracker callbacks ────────────────────────────────────────────────
static void onNewAp(const ApRecord* ap) {
    char l1[22], l2[22];
    snprintf(l1, sizeof(l1), "NEW AP ch%u %s", ap->channel, encName(ap->enc));
    snprintf(l2, sizeof(l2), "%.21s", ap->hidden ? "(hidden)" : ap->ssid);
    displayAlert(l1, l2);
    loraReporterNewAp(ap);

    Serial.printf("[AP ] %-32s  %02X:%02X:%02X:%02X:%02X:%02X  ch%2u  %s  RSSI:%d%s\n",
        ap->hidden ? "(hidden)" : ap->ssid,
        ap->bssid[0], ap->bssid[1], ap->bssid[2],
        ap->bssid[3], ap->bssid[4], ap->bssid[5],
        ap->channel, encName(ap->enc), ap->rssi,
        ap->wps ? " WPS" : "");
}

static void onDeauth(const DeauthEvent* ev) {
    char l1[22], l2[22];
    snprintf(l1, sizeof(l1), "DEAUTH rsn=%u", ev->reason);
    snprintf(l2, sizeof(l2), "%02X:%02X:%02X", ev->client[0], ev->client[1], ev->client[2]);
    displayAlert(l1, l2);
    loraReporterDeauth(ev);

    Serial.printf("[DTH] BSSID=%02X:%02X:%02X:%02X:%02X:%02X  "
                  "CLI=%02X:%02X:%02X:%02X:%02X:%02X  reason=%u  RSSI:%d\n",
        ev->bssid[0], ev->bssid[1], ev->bssid[2],
        ev->bssid[3], ev->bssid[4], ev->bssid[5],
        ev->client[0], ev->client[1], ev->client[2],
        ev->client[3], ev->client[4], ev->client[5],
        ev->reason, ev->rssi);
}

static void onNewClient(const ClientRecord* cl) {
    loraReporterNewClient(cl);
    Serial.printf("[CLI] %02X:%02X:%02X:%02X:%02X:%02X  vendor=%-8s  probes=%u\n",
        cl->mac[0], cl->mac[1], cl->mac[2],
        cl->mac[3], cl->mac[4], cl->mac[5],
        cl->vendor, cl->probe_count);
}

// ─── PCAP mode entry/exit ─────────────────────────────────────────────────
static void enterPcapMode() {
    g_pcap_mode = true;
    g_hop_mode  = false;
    frameCaptureStopHop();
    // Restart serial at high baud for binary stream
    Serial.flush();
    Serial.end();
    Serial.begin(SERIAL_BAUD_PCAP);
    pcapStreamBegin();
    // Show mode on OLED
    displayAlert("PCAP MODE", "Pipe to Wireshark");
}

static void exitPcapMode() {
    g_pcap_mode = false;
    Serial.flush();
    Serial.end();
    Serial.begin(SERIAL_BAUD_NORMAL);
    Serial.println("[SCANNER] PCAP mode OFF");
    if (g_hop_mode) frameCaptureStartHop();
    displayAlert("SCAN MODE", "Serial: text");
}

// ─── Button handling ──────────────────────────────────────────────────────
static void handleButtons() {
    bool view_now = (digitalRead(BTN_VIEW) == LOW);
    bool mode_now = (digitalRead(BTN_MODE) == LOW);
    uint32_t now  = millis();

    // BTN_VIEW — short press: cycle display view
    if (view_now && !g_btn_view_held) {
        g_btn_view_down = now;
        g_btn_view_held = true;
    } else if (!view_now && g_btn_view_held) {
        g_btn_view_held = false;
        if (now - g_btn_view_down < BTN_LONG_MS) {
            g_view = (DisplayView)((g_view + 1) % VIEW_COUNT);
        }
    }

    // BTN_MODE — short press: toggle channel hop/fixed
    //            long press (2s): toggle PCAP mode
    if (mode_now && !g_btn_mode_held) {
        g_btn_mode_down = now;
        g_btn_mode_held = true;
    } else if (mode_now && g_btn_mode_held) {
        if (now - g_btn_mode_down >= BTN_LONG_MS) {
            // Long press detected — toggle PCAP
            g_btn_mode_held = false;  // reset to prevent re-trigger
            if (!g_pcap_mode) enterPcapMode();
            else              exitPcapMode();
        }
    } else if (!mode_now && g_btn_mode_held) {
        g_btn_mode_held = false;
        uint32_t held = now - g_btn_mode_down;
        if (held < BTN_LONG_MS && !g_pcap_mode) {
            // Short press: toggle hop/fixed
            g_hop_mode = !g_hop_mode;
            if (g_hop_mode) {
                frameCaptureStartHop();
                Serial.println("[SCAN] Channel hop ON");
            } else {
                frameCaptureStopHop();
                Serial.printf("[SCAN] Fixed channel %u\n", frameCaptureChannel());
            }
        }
    }
}

// ─── Serial command handler ───────────────────────────────────────────────
// Simple one-character commands via serial console:
//   'p' — toggle PCAP mode
//   'h' — toggle channel hop
//   '1'-'9','a','b','c','d' — jump to that channel (1-13)
//   's' — print AP/client summary
//   'r' — reset stats
static void handleSerial() {
    if (!Serial.available() || g_pcap_mode) return;  // no text cmds in PCAP mode
    char c = Serial.read();

    if (c == 'p') {
        if (!g_pcap_mode) enterPcapMode();
        else              exitPcapMode();
    } else if (c == 'h') {
        g_hop_mode = !g_hop_mode;
        if (g_hop_mode) frameCaptureStartHop();
        else            frameCaptureStopHop();
        Serial.printf("[SCAN] Hop: %s\n", g_hop_mode ? "ON" : "OFF");
    } else if (c >= '1' && c <= '9') {
        uint8_t ch = c - '0';
        frameCaptureSetFixed(ch);
        g_hop_mode = false;
        Serial.printf("[SCAN] Fixed ch%u\n", ch);
    } else if (c == 'a') { frameCaptureSetFixed(10); g_hop_mode = false; }
    else if (c == 'b')   { frameCaptureSetFixed(11); g_hop_mode = false; }
    else if (c == 'c')   { frameCaptureSetFixed(12); g_hop_mode = false; }
    else if (c == 'd')   { frameCaptureSetFixed(13); g_hop_mode = false; }
    else if (c == 'r') {
        frameCaptureResetStats();
        Serial.println("[SCAN] Stats reset");
    } else if (c == 's') {
        Serial.printf("[SCAN] APs=%u  Clients=%u  Frames=%lu  Deauths=%lu\n",
            netTrackerApCount(), netTrackerClientCount(),
            frameCaptureStats()->total, frameCaptureStats()->deauths);
    }
}

// ─────────────────────────────────────────────────────────────────────────
void setup() {
    Serial.begin(SERIAL_BAUD_NORMAL);
    delay(500);
    Serial.printf("\n[SCANNER] %s  v%s  booting...\n", DEVICE_ID, DEVICE_VERSION);

    pinMode(BTN_VIEW, INPUT_PULLUP);
    pinMode(BTN_MODE, INPUT_PULLUP);

    displayInit();
    displayShowBoot();

    // WiFi in NULL mode first, then switch to promiscuous
    WiFi.mode(WIFI_MODE_NULL);
    esp_wifi_init(nullptr);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_NULL);
    esp_wifi_start();

    netTrackerInit();
    netTrackerSetCallbacks(onNewAp, onDeauth, onNewClient);

    frameCaptureInit();
    frameCaptureStart();
    if (g_hop_mode) frameCaptureStartHop();
    else            frameCaptureSetFixed(DEFAULT_FIXED_CH);

    // LoRa — SPI already started by RadioLib
    loraReporterInit(&radio);

    Serial.println("[SCANNER] Ready");
    Serial.println("[SCANNER] Commands: p=PCAP  h=hop  1-d=channel  s=summary  r=reset");
    Serial.printf( "[SCANNER] Watching ch%u  %s\n",
                   frameCaptureChannel(), g_hop_mode ? "(hopping)" : "(fixed)");
}

// ─────────────────────────────────────────────────────────────────────────
void loop() {
    handleButtons();
    handleSerial();

    // Dequeue and process frames
    RawFrame frame;
    while (frameCaptureDequeue(&frame)) {
        if (g_pcap_mode) {
            pcapStreamWrite(&frame);
        } else {
            netTrackerFeed(frame.data, frame.len, frame.rssi, frame.channel);
        }
    }

    // Periodic tasks
    uint32_t now = millis();

    if (!g_pcap_mode && now - g_last_disp >= DISPLAY_REFRESH_MS) {
        g_last_disp = now;
        const CaptureStats* st = frameCaptureStats();
        displayUpdate(g_view,
                      frameCaptureChannel(), g_hop_mode, false,
                      netTrackerApCount(), netTrackerClientCount(),
                      st->total, st->deauths,
                      loraReporterLastRssi());
    }

    if (now - g_last_expire >= 30000) {
        g_last_expire = now;
        netTrackerExpire();
    }

    loraReporterTick(frameCaptureChannel(), g_hop_mode,
                     netTrackerApCount(), netTrackerClientCount(),
                     frameCaptureStats()->total,
                     frameCaptureStats()->deauths);
}
