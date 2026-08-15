#pragma once
#include <stdint.h>
#include <stdbool.h>

// ─── Encryption type ──────────────────────────────────────────────────────
enum EncType : uint8_t {
    ENC_OPEN  = 0,
    ENC_WEP   = 1,
    ENC_WPA   = 2,
    ENC_WPA2  = 3,
    ENC_WPA3  = 4,
    ENC_WPA2E = 5,   // WPA2-Enterprise (RADIUS)
    ENC_UNK   = 6,
};

const char* encName(EncType e);

// ─── Access Point record ──────────────────────────────────────────────────
struct ApRecord {
    uint8_t  bssid[6];
    char     ssid[33];       // null-terminated, empty = hidden
    uint8_t  channel;
    int8_t   rssi;
    EncType  enc;
    bool     wps;
    bool     hidden;
    uint32_t first_seen_ms;
    uint32_t last_seen_ms;
    uint16_t beacon_count;
    bool     active;
};

// ─── Client record ────────────────────────────────────────────────────────
#define MAX_PROBE_SSIDS  4
#define SSID_LEN         33

struct ClientRecord {
    uint8_t  mac[6];
    char     vendor[9];          // 8-char OUI vendor prefix + null
    char     probe_ssids[MAX_PROBE_SSIDS][SSID_LEN];
    uint8_t  probe_count;
    uint8_t  assoc_bssid[6];    // zero if not associated
    bool     associated;
    int8_t   rssi;
    uint32_t first_seen_ms;
    uint32_t last_seen_ms;
    bool     active;
};

// ─── Deauth event ─────────────────────────────────────────────────────────
struct DeauthEvent {
    uint8_t  bssid[6];
    uint8_t  client[6];   // FF:FF:FF:FF:FF:FF = broadcast
    uint16_t reason;
    int8_t   rssi;
    uint32_t ts_ms;
};

// ─── Public API ───────────────────────────────────────────────────────────
void netTrackerInit();

// Feed a raw frame — returns true if something interesting was updated.
bool netTrackerFeed(const uint8_t* frame, uint16_t len,
                    int8_t rssi, uint8_t channel);

// Access AP table
uint8_t           netTrackerApCount();
const ApRecord*   netTrackerGetAp(uint8_t idx);   // 0-based, sorted by RSSI
const ApRecord*   netTrackerFindAp(const uint8_t* bssid);

// Access client table
uint8_t              netTrackerClientCount();
const ClientRecord*  netTrackerGetClient(uint8_t idx);

// Deauth ring buffer — last 20 events
uint8_t              netTrackerDeauthCount();
const DeauthEvent*   netTrackerGetDeauth(uint8_t idx);  // 0=oldest

// Expire stale entries
void netTrackerExpire();

// Callbacks fired on significant events
typedef void (*OnNewApCb)     (const ApRecord*);
typedef void (*OnDeauthCb)    (const DeauthEvent*);
typedef void (*OnNewClientCb) (const ClientRecord*);

void netTrackerSetCallbacks(OnNewApCb ap_cb, OnDeauthCb deauth_cb,
                            OnNewClientCb client_cb);
