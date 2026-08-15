#include "frame_capture.h"
#include "config.h"
#include <Arduino.h>
#include <esp_wifi.h>
#include <esp_event.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/task.h>
#include <string.h>

static QueueHandle_t  g_queue        = nullptr;
static CaptureStats   g_stats        = {};
static volatile uint8_t g_channel    = 1;
static volatile bool  g_hopping      = false;
static uint8_t        g_fixed_ch     = DEFAULT_FIXED_CH;
static TaskHandle_t   g_hop_task     = nullptr;

// ─── IEEE 802.11 frame control helpers ───────────────────────────────────
static inline uint8_t fc_type(const uint8_t* f)    { return (f[0] >> 2) & 0x03; }
static inline uint8_t fc_subtype(const uint8_t* f)  { return (f[0] >> 4) & 0x0F; }

// ─── Promiscuous callback (called in WiFi task context — keep it fast) ────
static void IRAM_ATTR promiscuousCallback(void* buf,
                                          wifi_promiscuous_pkt_type_t type) {
    if (type == WIFI_PKT_MISC) return;

    const wifi_promiscuous_pkt_t* pkt =
        reinterpret_cast<const wifi_promiscuous_pkt_t*>(buf);

    uint16_t frame_len = pkt->rx_ctrl.sig_len;
    if (frame_len < 10) return;  // too short to be useful

    // Update quick stats from FC byte (safe — frame_len >= 10 guaranteed)
    const uint8_t* fc = pkt->payload;
    uint8_t ft  = fc_type(fc);
    uint8_t fst = fc_subtype(fc);

    if (type == WIFI_PKT_MGMT) {
        g_stats.mgmt++;
        if (fst == 0x08)                      g_stats.beacons++;
        else if (fst == 0x04 || fst == 0x05)  g_stats.probes++;
        else if (fst == 0x0C || fst == 0x0A)  g_stats.deauths++;
    } else if (type == WIFI_PKT_DATA) {
        g_stats.data++;
    }
    g_stats.total++;

    // Build a RawFrame and enqueue — drop if full
    RawFrame f;
    f.len          = frame_len > MAX_FRAME_SIZE ? MAX_FRAME_SIZE : frame_len;
    f.orig_len     = frame_len;
    f.rssi         = pkt->rx_ctrl.rssi;
    f.channel      = pkt->rx_ctrl.channel;
    f.timestamp_us = pkt->rx_ctrl.timestamp;
    f.pkt_type     = type;
    memcpy(f.data, pkt->payload, f.len);

    BaseType_t woken = pdFALSE;
    if (xQueueSendFromISR(g_queue, &f, &woken) != pdTRUE) {
        g_stats.dropped++;
    }
    if (woken) portYIELD_FROM_ISR();
}

// ─── Channel hop FreeRTOS task ────────────────────────────────────────────
static void hopTask(void*) {
    uint8_t ch = CHANNEL_MIN;
    while (true) {
        if (g_hopping) {
            esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
            g_channel = ch;
            ch = (ch >= CHANNEL_MAX) ? CHANNEL_MIN : ch + 1;
            vTaskDelay(pdMS_TO_TICKS(CHANNEL_HOP_MS));
        } else {
            esp_wifi_set_channel(g_fixed_ch, WIFI_SECOND_CHAN_NONE);
            g_channel = g_fixed_ch;
            vTaskDelay(pdMS_TO_TICKS(100));
        }
    }
}

// ─── Public API ───────────────────────────────────────────────────────────
void frameCaptureInit() {
    g_queue = xQueueCreate(FRAME_QUEUE_SIZE, sizeof(RawFrame));
    memset(&g_stats, 0, sizeof(g_stats));
}

void frameCaptureStart() {
    // WiFi must be initialised first (called by main before this)
    wifi_promiscuous_filter_t filter = {};
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
    if (CAPTURE_DATA) filter.filter_mask |= WIFI_PROMIS_FILTER_MASK_DATA;
    if (CAPTURE_CTRL) filter.filter_mask |= WIFI_PROMIS_FILTER_MASK_CTRL;

    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(promiscuousCallback);
    esp_wifi_set_promiscuous(true);
    Serial.println("[CAP] Promiscuous mode ON");
}

void frameCaptureStop() {
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    Serial.println("[CAP] Promiscuous mode OFF");
}

bool frameCaptureDequeue(RawFrame* out) {
    return xQueueReceive(g_queue, out, 0) == pdTRUE;
}

uint8_t frameCaptureChannel() { return g_channel; }

void frameCaptureSetChannel(uint8_t ch) {
    if (ch < CHANNEL_MIN || ch > CHANNEL_MAX) return;
    g_fixed_ch = ch;
    g_channel  = ch;
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
}

void frameCaptureStartHop() {
    g_hopping = true;
    if (!g_hop_task) {
        xTaskCreate(hopTask, "hop", 2048, nullptr, 1, &g_hop_task);
    }
}

void frameCaptureStopHop() {
    g_hopping = false;
}

void frameCaptureSetFixed(uint8_t ch) {
    g_fixed_ch = ch;
    g_hopping  = false;
}

const CaptureStats* frameCaptureStats() { return &g_stats; }

void frameCaptureResetStats() { memset(&g_stats, 0, sizeof(g_stats)); }
