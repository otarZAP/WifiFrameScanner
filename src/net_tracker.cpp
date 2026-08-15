#include "net_tracker.h"
#include "config.h"
#include <Arduino.h>
#include <string.h>

// ─── Storage ──────────────────────────────────────────────────────────────
static ApRecord     g_aps[MAX_APS]           = {};
static ClientRecord g_clients[MAX_CLIENTS]   = {};
static DeauthEvent  g_deauths[20]            = {};
static uint8_t      g_ap_count    = 0;
static uint8_t      g_client_count= 0;
static uint8_t      g_deauth_head = 0;
static uint8_t      g_deauth_count= 0;

static OnNewApCb     g_ap_cb     = nullptr;
static OnDeauthCb    g_deauth_cb = nullptr;
static OnNewClientCb g_client_cb = nullptr;

void netTrackerSetCallbacks(OnNewApCb a, OnDeauthCb d, OnNewClientCb c) {
    g_ap_cb = a; g_deauth_cb = d; g_client_cb = c;
}

// ─── MAC helpers ──────────────────────────────────────────────────────────
static bool macEq(const uint8_t* a, const uint8_t* b) {
    return memcmp(a, b, 6) == 0;
}
static bool macZero(const uint8_t* m) {
    for (int i = 0; i < 6; i++) if (m[i]) return false;
    return true;
}
static bool macBroadcast(const uint8_t* m) {
    for (int i = 0; i < 6; i++) if (m[i] != 0xFF) return false;
    return true;
}
// Multicast bit: LSB of first octet
static bool macMulticast(const uint8_t* m) { return (m[0] & 0x01) != 0; }

// ─── OUI vendor lookup (abbreviated) ─────────────────────────────────────
static const char* ouiLookup(const uint8_t* mac) {
    uint32_t oui = ((uint32_t)mac[0] << 16) |
                   ((uint32_t)mac[1] << 8)  |
                   (uint32_t)mac[2];
    switch (oui) {
        case 0x000C29: return "VMware";
        case 0x001A11: return "Google";
        case 0x001E58: return "WiQuest";
        case 0x00259C: return "Apple";
        case 0x003065: return "Murata";
        case 0x0050F2: return "Microsoft";
        case 0x00E04C: return "Realtek";
        case 0x18FE34: return "Espressif";
        case 0x2462AB: return "Amazon";
        case 0x3C22FB: return "Apple";
        case 0x4C3275: return "Apple";
        case 0x5CFF35: return "Apple";
        case 0x680571: return "Intel";
        case 0x7C2EBD: return "Samsung";
        case 0x8C8590: return "Apple";
        case 0xA4C138: return "Apple";
        case 0xB8E856: return "Intel";
        case 0xC82A14: return "Apple";
        case 0xD4619D: return "Intel";
        case 0xDCA904: return "Apple";
        case 0xE0B9E5: return "Apple";
        case 0xF0B429: return "Apple";
        default:       return "?";
    }
}

// ─── 802.11 frame control helpers ────────────────────────────────────────
#define FC_TYPE(fc0)     (((fc0) >> 2) & 0x03)
#define FC_SUBTYPE(fc0)  (((fc0) >> 4) & 0x0F)
#define FC_TODS(fc1)     ((fc1) & 0x01)
#define FC_FROMDS(fc1)   (((fc1) >> 1) & 0x01)

// ─── IE tag parser (for Beacon / Probe Response) ──────────────────────────
// pkt points to start of 802.11 MAC header, offset is first byte of IE region.
static void parseIEs(const uint8_t* body, uint16_t body_len,
                     char* ssid_out, uint8_t* ch_out, EncType* enc_out,
                     bool* wps_out) {
    *ssid_out = '\0';
    *ch_out   = 0;
    *enc_out  = ENC_OPEN;
    *wps_out  = false;

    bool has_rsn = false;
    bool has_wpa = false;
    bool has_wep = false;

    uint16_t i = 0;
    while (i + 2 <= body_len) {
        uint8_t tag_num = body[i];
        uint8_t tag_len = body[i + 1];
        if (i + 2 + tag_len > body_len) break;
        const uint8_t* tag_data = body + i + 2;

        switch (tag_num) {
            case 0:   // SSID
                if (tag_len <= 32) {
                    memcpy(ssid_out, tag_data, tag_len);
                    ssid_out[tag_len] = '\0';
                }
                break;

            case 3:   // DS Parameter Set — current channel
                if (tag_len >= 1) *ch_out = tag_data[0];
                break;

            case 48:  // RSN (WPA2 / WPA3)
                has_rsn = true;
                // Check AKM suites for SAE (WPA3)
                if (tag_len >= 8) {
                    // RSN: version(2) + group_cipher(4) + pairwise_count(2) + pairwise[n*4] + akm_count(2) + akm[n*4]
                    uint16_t off = 2 + 4;  // skip version + group cipher
                    if (off + 2 <= tag_len) {
                        uint16_t pair_cnt = tag_data[off] | (tag_data[off+1] << 8);
                        off += 2 + pair_cnt * 4;
                        if (off + 2 <= tag_len) {
                            uint16_t akm_cnt = tag_data[off] | (tag_data[off+1] << 8);
                            off += 2;
                            for (uint16_t k = 0; k < akm_cnt && off + 4 <= tag_len; k++, off += 4) {
                                // SAE: OUI 00:0F:AC, suite 8
                                if (tag_data[off]==0 && tag_data[off+1]==0x0F &&
                                    tag_data[off+2]==0xAC && tag_data[off+3]==8) {
                                    *enc_out = ENC_WPA3;
                                }
                                // Enterprise: suite 1 = 802.1X
                                if (tag_data[off+3] == 1) *enc_out = ENC_WPA2E;
                            }
                        }
                    }
                }
                break;

            case 221: // Vendor specific
                if (tag_len >= 4) {
                    // WPA1: OUI 00:50:F2:01
                    if (tag_data[0]==0 && tag_data[1]==0x50 &&
                        tag_data[2]==0xF2 && tag_data[3]==0x01) {
                        has_wpa = true;
                    }
                    // WPS: OUI 00:50:F2:04
                    if (tag_data[0]==0 && tag_data[1]==0x50 &&
                        tag_data[2]==0xF2 && tag_data[3]==0x04) {
                        *wps_out = true;
                    }
                }
                break;
        }
        i += 2 + tag_len;
    }

    // Resolve encryption priority: WPA3 > WPA2/RSN > WPA1 > WEP > Open
    if (*enc_out == ENC_OPEN || *enc_out == ENC_UNK) {
        if (has_rsn)        *enc_out = ENC_WPA2;
        else if (has_wpa)   *enc_out = ENC_WPA;
    }
}

// ─── AP table helpers ─────────────────────────────────────────────────────
static ApRecord* findAp(const uint8_t* bssid) {
    for (uint8_t i = 0; i < g_ap_count; i++) {
        if (g_aps[i].active && macEq(g_aps[i].bssid, bssid)) return &g_aps[i];
    }
    return nullptr;
}
static ApRecord* allocAp(const uint8_t* bssid) {
    if (g_ap_count < MAX_APS) {
        ApRecord* r = &g_aps[g_ap_count++];
        memset(r, 0, sizeof(*r));
        memcpy(r->bssid, bssid, 6);
        r->active = true;
        r->first_seen_ms = millis();
        return r;
    }
    // Evict oldest
    ApRecord* oldest = &g_aps[0];
    for (uint8_t i = 1; i < MAX_APS; i++) {
        if (g_aps[i].last_seen_ms < oldest->last_seen_ms) oldest = &g_aps[i];
    }
    memset(oldest, 0, sizeof(*oldest));
    memcpy(oldest->bssid, bssid, 6);
    oldest->active = true;
    oldest->first_seen_ms = millis();
    return oldest;
}

// ─── Client table helpers ─────────────────────────────────────────────────
static ClientRecord* findClient(const uint8_t* mac) {
    for (uint8_t i = 0; i < g_client_count; i++) {
        if (g_clients[i].active && macEq(g_clients[i].mac, mac)) return &g_clients[i];
    }
    return nullptr;
}
static ClientRecord* allocClient(const uint8_t* mac) {
    if (g_client_count < MAX_CLIENTS) {
        ClientRecord* r = &g_clients[g_client_count++];
        memset(r, 0, sizeof(*r));
        memcpy(r->mac, mac, 6);
        r->active = true;
        r->first_seen_ms = millis();
        const char* v = ouiLookup(mac);
        strncpy(r->vendor, v, sizeof(r->vendor) - 1);
        return r;
    }
    // Evict oldest
    ClientRecord* oldest = &g_clients[0];
    for (uint8_t i = 1; i < MAX_CLIENTS; i++) {
        if (g_clients[i].last_seen_ms < oldest->last_seen_ms) oldest = &g_clients[i];
    }
    memset(oldest, 0, sizeof(*oldest));
    memcpy(oldest->mac, mac, 6);
    oldest->active = true;
    oldest->first_seen_ms = millis();
    const char* v = ouiLookup(mac);
    strncpy(oldest->vendor, v, sizeof(oldest->vendor) - 1);
    return oldest;
}

// ─── Frame processors ─────────────────────────────────────────────────────
static bool processBeacon(const uint8_t* f, uint16_t len, int8_t rssi, uint8_t ch) {
    if (len < 36) return false;  // header(24) + fixed(12) minimum
    const uint8_t* bssid = f + 16;  // addr3 in beacon = BSSID

    char    ssid[33] = {};
    uint8_t ie_ch    = 0;
    EncType enc      = ENC_OPEN;
    bool    wps      = false;

    // IEs start at offset 24 (MAC header) + 12 (fixed fields)
    parseIEs(f + 36, len - 36, ssid, &ie_ch, &enc, &wps);

    uint8_t beacon_ch = (ie_ch > 0) ? ie_ch : ch;

    bool is_new = false;
    ApRecord* ap = findAp(bssid);
    if (!ap) {
        ap    = allocAp(bssid);
        is_new = true;
    }

    strncpy(ap->ssid, ssid, 32);
    ap->hidden  = (ssid[0] == '\0');
    ap->channel = beacon_ch;
    ap->rssi    = rssi;
    ap->enc     = enc;
    ap->wps     = wps;
    ap->last_seen_ms = millis();
    ap->beacon_count++;

    if (is_new && g_ap_cb) g_ap_cb(ap);
    return is_new;
}

static bool processProbeReq(const uint8_t* f, uint16_t len, int8_t rssi) {
    if (len < 26) return false;
    const uint8_t* src = f + 10;   // addr2 = SA = client MAC
    if (macBroadcast(src) || macMulticast(src) || macZero(src)) return false;

    char ssid[33] = {};
    // IE region starts at offset 24
    if (len > 26) {
        const uint8_t* ies = f + 24;
        uint16_t ies_len = len - 24;
        if (ies_len >= 2 && ies[0] == 0) {  // SSID tag
            uint8_t slen = ies[1];
            if (slen <= 32 && slen + 2 <= ies_len) {
                memcpy(ssid, ies + 2, slen);
                ssid[slen] = '\0';
            }
        }
    }

    bool is_new = false;
    ClientRecord* cl = findClient(src);
    if (!cl) {
        cl     = allocClient(src);
        is_new = true;
    }
    cl->rssi         = rssi;
    cl->last_seen_ms = millis();

    // Store probed SSID if not already recorded
    if (ssid[0] != '\0') {
        bool found = false;
        for (uint8_t i = 0; i < cl->probe_count; i++) {
            if (strncmp(cl->probe_ssids[i], ssid, SSID_LEN) == 0) { found = true; break; }
        }
        if (!found && cl->probe_count < MAX_PROBE_SSIDS) {
            strncpy(cl->probe_ssids[cl->probe_count++], ssid, SSID_LEN - 1);
        }
    }

    if (is_new && g_client_cb) g_client_cb(cl);
    return is_new;
}

static void processDeauth(const uint8_t* f, uint16_t len, int8_t rssi) {
    if (len < 26) return;
    // FC subtype 0x0C = Deauth, 0x0A = Disassoc
    const uint8_t* dst   = f + 4;   // addr1
    const uint8_t* src   = f + 10;  // addr2
    uint16_t reason = 0;
    if (len >= 26) reason = (uint16_t)f[24] | ((uint16_t)f[25] << 8);

    DeauthEvent ev;
    // Determine which is BSSID and which is client
    // addr3 = BSSID in deauth
    memcpy(ev.bssid,  f + 16, 6);
    memcpy(ev.client, macBroadcast(dst) ? src : dst, 6);
    ev.reason = reason;
    ev.rssi   = rssi;
    ev.ts_ms  = millis();

    uint8_t idx = g_deauth_head;
    memcpy(&g_deauths[idx], &ev, sizeof(ev));
    g_deauth_head = (g_deauth_head + 1) % 20;
    if (g_deauth_count < 20) g_deauth_count++;

    if (g_deauth_cb) g_deauth_cb(&ev);
}

static void processDataFrame(const uint8_t* f, uint16_t len, int8_t rssi) {
    if (len < 24) return;
    uint8_t fc1     = f[1];
    bool    toDS    = FC_TODS(fc1);
    bool    fromDS  = FC_FROMDS(fc1);

    // Determine client MAC and AP BSSID from ToDS/FromDS flags
    const uint8_t* client_mac = nullptr;
    const uint8_t* ap_bssid   = nullptr;

    if (toDS && !fromDS) {
        // STA → AP:  addr1=BSSID, addr2=STA, addr3=DA
        ap_bssid   = f + 4;
        client_mac = f + 10;
    } else if (!toDS && fromDS) {
        // AP → STA:  addr1=STA, addr2=BSSID, addr3=SA
        client_mac = f + 4;
        ap_bssid   = f + 10;
    } else {
        return;  // IBSS or WDS — ignore for now
    }

    if (!client_mac || macBroadcast(client_mac) || macMulticast(client_mac)) return;
    if (!ap_bssid   || macBroadcast(ap_bssid))   return;

    ClientRecord* cl = findClient(client_mac);
    if (!cl) cl = allocClient(client_mac);
    cl->rssi         = rssi;
    cl->last_seen_ms = millis();
    if (!cl->associated || !macEq(cl->assoc_bssid, ap_bssid)) {
        memcpy(cl->assoc_bssid, ap_bssid, 6);
        cl->associated = true;
    }
}

// ─── Public API ───────────────────────────────────────────────────────────
void netTrackerInit() {
    memset(g_aps,     0, sizeof(g_aps));
    memset(g_clients, 0, sizeof(g_clients));
    memset(g_deauths, 0, sizeof(g_deauths));
    g_ap_count = g_client_count = g_deauth_head = g_deauth_count = 0;
}

bool netTrackerFeed(const uint8_t* frame, uint16_t len, int8_t rssi, uint8_t ch) {
    if (len < 4) return false;

    uint8_t fc0  = frame[0];
    uint8_t type = FC_TYPE(fc0);
    uint8_t sub  = FC_SUBTYPE(fc0);

    if (type == 0) {  // Management
        if (sub == 0x08 || sub == 0x05)  return processBeacon(frame, len, rssi, ch);
        if (sub == 0x04)                  return processProbeReq(frame, len, rssi);
        if (sub == 0x0C || sub == 0x0A) { processDeauth(frame, len, rssi); return false; }
    } else if (type == 2) {  // Data
        processDataFrame(frame, len, rssi);
    }
    return false;
}

uint8_t          netTrackerApCount()          { return g_ap_count; }
const ApRecord*  netTrackerGetAp(uint8_t i)   { return (i < g_ap_count) ? &g_aps[i] : nullptr; }
const ApRecord*  netTrackerFindAp(const uint8_t* b) { return findAp(b); }
uint8_t             netTrackerClientCount()          { return g_client_count; }
const ClientRecord* netTrackerGetClient(uint8_t i)   { return (i < g_client_count) ? &g_clients[i] : nullptr; }
uint8_t             netTrackerDeauthCount()          { return g_deauth_count; }
const DeauthEvent*  netTrackerGetDeauth(uint8_t i)   {
    if (i >= g_deauth_count) return nullptr;
    uint8_t idx = (g_deauth_count < 20)
        ? i
        : (g_deauth_head + i) % 20;
    return &g_deauths[idx];
}

const char* encName(EncType e) {
    switch(e) {
        case ENC_OPEN:  return "OPEN";
        case ENC_WEP:   return "WEP";
        case ENC_WPA:   return "WPA";
        case ENC_WPA2:  return "WPA2";
        case ENC_WPA3:  return "WPA3";
        case ENC_WPA2E: return "WPA2E";
        default:        return "?";
    }
}

void netTrackerExpire() {
    uint32_t now = millis();
    for (uint8_t i = 0; i < g_ap_count; i++) {
        if (g_aps[i].active && (now - g_aps[i].last_seen_ms) > AP_EXPIRE_MS) {
            g_aps[i].active = false;
        }
    }
    for (uint8_t i = 0; i < g_client_count; i++) {
        if (g_clients[i].active && (now - g_clients[i].last_seen_ms) > CLIENT_EXPIRE_MS) {
            g_clients[i].active = false;
        }
    }
}
