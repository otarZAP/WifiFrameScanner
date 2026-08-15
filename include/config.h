#pragma once

#include "secrets.h"

// ─── Device identity ──────────────────────────────────────────────────────
#define DEVICE_ID       "scanner-001"
#define DEVICE_VERSION  "1.0.0"
#define NODE_ID         0x05        // unique per deployed unit (0x05+)
#define FW_TYPE         0x04        // FW_SCANNER

// ─── Operating mode defaults ──────────────────────────────────────────────
// Modes can be toggled at runtime via buttons or serial commands.
//   SCAN  mode : channel-hopping, human-readable serial output, OLED stats
//   PCAP  mode : pin to one channel, binary PCAP stream on serial (→ Wireshark)
// Start in SCAN mode on every boot.
#define DEFAULT_HOP_MODE   true     // true = channel-hop, false = fixed channel
#define DEFAULT_PCAP_MODE  false    // true = binary PCAP on serial
#define DEFAULT_FIXED_CH   6        // channel used when hop disabled

// ─── Channel hopping ──────────────────────────────────────────────────────
#define CHANNEL_MIN        1
#define CHANNEL_MAX        13
#define CHANNEL_HOP_MS     150      // dwell time per channel (ms)

// ─── Frame capture ────────────────────────────────────────────────────────
#define MAX_FRAME_SIZE     512      // truncation limit per frame (bytes)
#define FRAME_QUEUE_SIZE   32       // FreeRTOS queue depth
// Capture filter masks — OR together as needed
// WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA
#define CAPTURE_MGMT       true     // always capture management frames
#define CAPTURE_DATA       true     // capture data frame headers (payload encrypted)
#define CAPTURE_CTRL       false    // control frames (ACK, RTS, CTS) — very noisy

// ─── Network tracker capacity ─────────────────────────────────────────────
#define MAX_APS            60
#define MAX_CLIENTS        80
#define MAX_ASSOC          80       // client→AP association records
#define AP_EXPIRE_MS       (5 * 60 * 1000)      // drop AP after 5 min silence
#define CLIENT_EXPIRE_MS   (5 * 60 * 1000)

// ─── Serial / PCAP ────────────────────────────────────────────────────────
#define SERIAL_BAUD_NORMAL  115200
#define SERIAL_BAUD_PCAP    921600  // high baud for binary stream
#define PCAP_SNAPLEN        512

// ─── LoRa RF (Heltec V4 SX1262) — must match your LoRa base station ───────
#define LORA_NSS            8
#define LORA_DIO1           14
#define LORA_RST            12
#define LORA_BUSY           13
#define LORA_SCK            9
#define LORA_MOSI           10
#define LORA_MISO           11

#define LORA_FREQ           915.0
#define LORA_BW             125.0
#define LORA_SF             9
#define LORA_CR             5
#define LORA_SYNC           0x12
#define LORA_POWER          17

// ─── LoRa reporting intervals ─────────────────────────────────────────────
#define LORA_SUMMARY_MS     30000   // summary ping every 30 s
#define LORA_NEWAP_DEBOUNCE 5000    // don't re-report same AP within 5 s

// ─── OLED I2C (Heltec V4 onboard) ────────────────────────────────────────
#define OLED_SDA            17
#define OLED_SCL            18
#define OLED_RST            21
#define OLED_ADDR           0x3C
#define OLED_WIDTH          128
#define OLED_HEIGHT         64

// ─── Buttons ──────────────────────────────────────────────────────────────
#define BTN_VIEW            0       // GPIO 0 — short press: cycle display view
#define BTN_MODE            35      // GPIO 35 — short: toggle hop/fixed
                                    //          long (2s): toggle PCAP mode
#define BTN_LONG_MS         2000

// ─── Display ──────────────────────────────────────────────────────────────
#define DISPLAY_REFRESH_MS  1000
#define SCROLL_INTERVAL_MS  2500
