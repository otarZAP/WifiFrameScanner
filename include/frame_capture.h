#pragma once
#include <stdint.h>
#include <esp_wifi_types.h>

// Raw captured 802.11 frame as dequeued by the main loop.
struct RawFrame {
    uint8_t  data[512];          // raw 802.11 MAC frame (may be truncated)
    uint16_t len;                // bytes actually stored in data[]
    uint16_t orig_len;           // original frame length before truncation
    int8_t   rssi;               // received signal strength (dBm)
    uint8_t  channel;            // channel frame was received on
    uint32_t timestamp_us;       // rx timestamp from radio (microseconds)
    wifi_promiscuous_pkt_type_t pkt_type;  // MGMT / DATA / MISC
};

// Stats counters — updated in the promiscuous callback.
struct CaptureStats {
    uint32_t total;
    uint32_t mgmt;
    uint32_t data;
    uint32_t dropped;       // queue overflow drops
    uint32_t beacons;
    uint32_t probes;
    uint32_t deauths;
    uint32_t eapol;
};

void     frameCaptureInit();
void     frameCaptureStart();
void     frameCaptureStop();

// Returns true if a frame was dequeued into *out. Non-blocking.
bool     frameCaptureDequeue(RawFrame* out);

uint8_t  frameCaptureChannel();
void     frameCaptureSetChannel(uint8_t ch);

// Channel hopping task control
void     frameCaptureStartHop();    // begin FreeRTOS channel hop task
void     frameCaptureStopHop();     // stop hopping, hold current channel
void     frameCaptureSetFixed(uint8_t ch);  // pin to specific channel

const CaptureStats* frameCaptureStats();
void                frameCaptureResetStats();
