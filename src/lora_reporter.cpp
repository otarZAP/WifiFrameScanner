#include "lora_reporter.h"
#include "config.h"
#include "lora_protocol.h"
#include <Arduino.h>
#include <SPI.h>
#include <stdio.h>
#include <string.h>

static SX1262*  g_radio    = nullptr;
static bool     g_ready    = false;
static int16_t  g_last_rssi = 0;
static uint8_t  g_seq      = 0;
static uint32_t g_last_summary_ms = 0;

static void loraTx(uint8_t severity, const char* msg) {
    if (!g_ready || !g_radio) return;

    LoraPacket pkt;
    proto_init(&pkt, NODE_ID, FW_TYPE, DIR_NODE_TO_BASE, severity);
    pkt.seq       = g_seq++;
    pkt.timestamp = (uint32_t)millis();

    uint8_t mlen = (uint8_t)strnlen(msg, PROTO_MAX_PAYLOAD - 1);
    memcpy(pkt.payload, msg, mlen);
    pkt.payload[mlen] = '\0';
    pkt.payload_len   = mlen + 1;

    proto_encrypt_payload(&pkt);
    proto_sign(&pkt);

    size_t total = PROTO_OVERHEAD + pkt.payload_len;
    int state = g_radio->transmit((uint8_t*)&pkt, total);
    if (state != RADIOLIB_ERR_NONE) {
        Serial.printf("[LoRa] TX err %d\n", state);
    }
    g_radio->startReceive();
}

void loraReporterInit(SX1262* radio) {
    g_radio = radio;
    SPI.begin(LORA_SCK, LORA_MISO, LORA_MOSI, LORA_NSS);

    int state = radio->begin(LORA_FREQ, LORA_BW, LORA_SF, LORA_CR,
                             LORA_SYNC, LORA_POWER, 8, 1.6, false);
    if (state != RADIOLIB_ERR_NONE) {
        Serial.printf("[LoRa] Init failed: %d\n", state);
        return;
    }
    g_ready = true;
    Serial.println("[LoRa] Ready");
}

bool    loraReporterReady()    { return g_ready; }
int16_t loraReporterLastRssi() { return g_last_rssi; }

void loraReporterTick(uint8_t channel, bool hopping,
                      uint8_t ap_count, uint8_t client_count,
                      uint32_t frame_total, uint32_t deauth_count) {
    if (!g_ready) return;
    if (millis() - g_last_summary_ms < LORA_SUMMARY_MS) return;
    g_last_summary_ms = millis();

    char buf[PROTO_MAX_PAYLOAD];
    snprintf(buf, sizeof(buf),
             "SCAN ch=%u hop=%d aps=%u cli=%u frm=%lu dth=%lu",
             channel, hopping ? 1 : 0,
             ap_count, client_count,
             frame_total, deauth_count);
    loraTx(SEV_INFO, buf);
}

void loraReporterNewAp(const ApRecord* ap) {
    if (!g_ready) return;
    char buf[PROTO_MAX_PAYLOAD];
    char bssid[18];
    snprintf(bssid, sizeof(bssid), "%02X:%02X:%02X:%02X:%02X:%02X",
             ap->bssid[0], ap->bssid[1], ap->bssid[2],
             ap->bssid[3], ap->bssid[4], ap->bssid[5]);
    snprintf(buf, sizeof(buf),
             "NEWAP ssid=%.20s bssid=%s ch=%u enc=%s rssi=%d%s",
             ap->hidden ? "(hidden)" : ap->ssid,
             bssid, ap->channel, encName(ap->enc), ap->rssi,
             ap->wps ? " WPS" : "");
    loraTx(SEV_MEDIUM, buf);
}

void loraReporterDeauth(const DeauthEvent* ev) {
    if (!g_ready) return;
    char buf[PROTO_MAX_PAYLOAD];
    snprintf(buf, sizeof(buf),
             "DEAUTH bssid=%02X:%02X:%02X:%02X:%02X:%02X "
             "cli=%02X:%02X:%02X:%02X:%02X:%02X rsn=%u",
             ev->bssid[0], ev->bssid[1], ev->bssid[2],
             ev->bssid[3], ev->bssid[4], ev->bssid[5],
             ev->client[0], ev->client[1], ev->client[2],
             ev->client[3], ev->client[4], ev->client[5],
             ev->reason);
    loraTx(SEV_HIGH, buf);
}

void loraReporterNewClient(const ClientRecord* client) {
    if (!g_ready) return;
    char buf[PROTO_MAX_PAYLOAD];
    snprintf(buf, sizeof(buf),
             "CLIENT mac=%02X:%02X:%02X:%02X:%02X:%02X vendor=%s probes=%u",
             client->mac[0], client->mac[1], client->mac[2],
             client->mac[3], client->mac[4], client->mac[5],
             client->vendor, client->probe_count);
    loraTx(SEV_LOW, buf);
}
