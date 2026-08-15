#pragma once
#include <stdint.h>
#include <string.h>

#include <AES.h>
#include <EAX.h>
#include <SHA256.h>

// ─── WifiFrameScanner LoRa telemetry protocol ──────────────────────────────
// Self-contained wire format for reporting scan telemetry to a LoRa base
// station: AES-256-EAX encryption, AEAD authentication, per-packet nonce.

#define PROTO_MAGIC_0     0xAD
#define PROTO_MAGIC_1     0xDE
#define PROTO_VERSION     0x01

// ─── Direction ────────────────────────────────────────────────────────────
#define DIR_NODE_TO_BASE  0x00   // only mode this node uses — it only reports

// ─── Firmware / mode type ─────────────────────────────────────────────────
#define FW_PING           0x00
#define FW_SCANNER        0x04   // this scanner's report tag

// ─── Severity ─────────────────────────────────────────────────────────────
#define SEV_INFO          0x00
#define SEV_LOW           0x01
#define SEV_MEDIUM        0x02
#define SEV_HIGH          0x03
#define SEV_CRITICAL      0x04

// ─── Authentication scaffold ──────────────────────────────────────────────
// This is a lightweight shared-key packet tag scaffold for lab and product
// bring-up. Replace with a stronger MAC/HMAC design before field deployment.
#ifndef PROTO_REQUIRE_AUTH
    #define PROTO_REQUIRE_AUTH 1
#endif

#ifndef PROTO_REQUIRE_ENCRYPTION
    #define PROTO_REQUIRE_ENCRYPTION 1
#endif

#ifndef PROTO_AES_KEY_TEXT
    #define PROTO_AES_KEY_TEXT "REPLACE_WITH_BASE64_32BYTE_KEY_FROM_CSPRNG="
#endif

#ifndef PROTO_AUTH_KEY_A
    #define PROTO_AUTH_KEY_A 0x13579BDFUL
#endif

#ifndef PROTO_AUTH_KEY_B
    #define PROTO_AUTH_KEY_B 0x2468ACE0UL
#endif

#ifndef PROTO_AUTH_KEY_C
    #define PROTO_AUTH_KEY_C 0x10203040UL
#endif

#ifndef PROTO_AUTH_KEY_D
    #define PROTO_AUTH_KEY_D 0x55667788UL
#endif

// ─── Packet structure ─────────────────────────────────────────────────────
#define PROTO_MAX_PAYLOAD 200

typedef struct __attribute__((packed)) {
    uint8_t  magic[2];          // PROTO_MAGIC_0, PROTO_MAGIC_1
    uint8_t  version;           // PROTO_VERSION
    uint8_t  node_id;           // sender node ID (1-254, 0xFF = broadcast)
    uint8_t  fw_type;           // FW_xxx — current mode of sender
    uint8_t  direction;         // DIR_xxx
    uint8_t  seq;               // rolling 0-255, detect drops
    uint8_t  severity;          // SEV_xxx
    uint32_t timestamp;         // millis() of sender
    uint64_t nonce;             // per-packet nonce for AEAD
    uint8_t  auth_tag[16];      // AEAD tag (or legacy auth bytes)
    uint8_t  payload_len;       // length of valid message bytes
    uint8_t  payload[PROTO_MAX_PAYLOAD];
} LoraPacket;

// Overhead = everything before message buffer = 37 bytes
#define PROTO_OVERHEAD  (sizeof(LoraPacket) - PROTO_MAX_PAYLOAD)

// ─── Helpers ──────────────────────────────────────────────────────────────
enum ProtoValidationReason : uint8_t {
    PROTO_VALID_OK              = 0,
    PROTO_ERR_MAGIC             = 1,
    PROTO_ERR_VERSION           = 2,
    PROTO_ERR_PAYLOAD_LEN       = 3,
    PROTO_ERR_ENCRYPTION_NONCE  = 4,
};

// Runtime key override — defaults to compile-time values.
// Call proto_set_keys() on boot if loading keys from NVS.
// Each firmware is a single translation unit, so static is safe here.
static uint32_t     g_proto_key_a        = PROTO_AUTH_KEY_A;
static uint32_t     g_proto_key_b        = PROTO_AUTH_KEY_B;
static uint32_t     g_proto_key_c        = PROTO_AUTH_KEY_C;
static uint32_t     g_proto_key_d        = PROTO_AUTH_KEY_D;
static uint64_t     g_proto_nonce_counter = 1;
static const char*  g_proto_aes_key_text = PROTO_AES_KEY_TEXT;

inline void proto_set_keys(uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
    g_proto_key_a = a; g_proto_key_b = b; g_proto_key_c = c; g_proto_key_d = d;
}

inline uint32_t proto_auth_seed() {
    return g_proto_key_a ^ g_proto_key_b ^ g_proto_key_c ^ g_proto_key_d;
}

inline uint64_t proto_next_nonce(const LoraPacket* p) {
    uint64_t mixed = ((uint64_t)p->timestamp << 24) ^
                     ((uint64_t)p->node_id << 16) ^
                     ((uint64_t)p->seq << 8) ^
                     ((uint64_t)p->direction);
    mixed ^= (g_proto_nonce_counter++ << 32);
    return mixed ? mixed : (g_proto_nonce_counter++ << 32);
}

inline void proto_get_aes_material(uint8_t out_key[32]) {
    SHA256 sha;
    const char* key_txt = g_proto_aes_key_text;
    sha.update(key_txt, strlen(key_txt));

    uint32_t mix[4] = { g_proto_key_a, g_proto_key_b, g_proto_key_c, g_proto_key_d };
    sha.update(mix, sizeof(mix));
    sha.finalize(out_key, 32);
}

inline void proto_make_iv(const LoraPacket* p, uint8_t iv[12]) {
    iv[0]  = (uint8_t)(p->nonce & 0xFF);
    iv[1]  = (uint8_t)((p->nonce >> 8) & 0xFF);
    iv[2]  = (uint8_t)((p->nonce >> 16) & 0xFF);
    iv[3]  = (uint8_t)((p->nonce >> 24) & 0xFF);
    iv[4]  = (uint8_t)((p->nonce >> 32) & 0xFF);
    iv[5]  = (uint8_t)((p->nonce >> 40) & 0xFF);
    iv[6]  = (uint8_t)((p->nonce >> 48) & 0xFF);
    iv[7]  = (uint8_t)((p->nonce >> 56) & 0xFF);
    iv[8]  = p->node_id;
    iv[9]  = p->direction;
    iv[10] = p->seq;
    iv[11] = p->fw_type;
}

inline void proto_add_aad(EAX<AES256>& eax, const LoraPacket* p) {
    eax.addAuthData(p->magic, sizeof(p->magic));
    eax.addAuthData(&p->version, 1);
    eax.addAuthData(&p->node_id, 1);
    eax.addAuthData(&p->fw_type, 1);
    eax.addAuthData(&p->direction, 1);
    eax.addAuthData(&p->seq, 1);
    eax.addAuthData(&p->severity, 1);
    eax.addAuthData(&p->timestamp, sizeof(p->timestamp));
    eax.addAuthData(&p->nonce, sizeof(p->nonce));
    eax.addAuthData(&p->payload_len, 1);
}

inline void proto_get_aes_key(uint8_t out_key[32]) {
    proto_get_aes_material(out_key);
}

inline bool proto_encrypt_payload(LoraPacket* p) {
    if (p->payload_len > PROTO_MAX_PAYLOAD) {
        return false;
    }

    if (!PROTO_REQUIRE_ENCRYPTION) {
        return true;
    }

    if (p->nonce == 0) {
        p->nonce = proto_next_nonce(p);
    }

    uint8_t key[32];
    uint8_t iv[12];
    proto_get_aes_key(key);
    proto_make_iv(p, iv);

    EAX<AES256> eax;
    if (!eax.setKey(key, sizeof(key)) || !eax.setIV(iv, sizeof(iv))) {
        return false;
    }

    proto_add_aad(eax, p);
    if (p->payload_len > 0) {
        eax.encrypt(p->payload, p->payload, p->payload_len);
    }
    eax.computeTag(p->auth_tag, sizeof(p->auth_tag));
    return true;
}

inline bool proto_decrypt_payload(LoraPacket* p) {
    if (p->payload_len > PROTO_MAX_PAYLOAD) {
        return false;
    }

    if (!PROTO_REQUIRE_ENCRYPTION) {
        return true;
    }

    if (p->nonce == 0) {
        return false;
    }

    uint8_t key[32];
    uint8_t iv[12];
    proto_get_aes_key(key);
    proto_make_iv(p, iv);

    EAX<AES256> eax;
    if (!eax.setKey(key, sizeof(key)) || !eax.setIV(iv, sizeof(iv))) {
        return false;
    }

    proto_add_aad(eax, p);
    if (p->payload_len > 0) {
        eax.decrypt(p->payload, p->payload, p->payload_len);
    }

    bool ok = eax.checkTag(p->auth_tag, sizeof(p->auth_tag));
    if (!ok) {
        memset(p->payload, 0, p->payload_len);
        p->payload_len = 0;
    }
    return ok;
}

inline uint32_t proto_auth_mix(uint32_t hash, uint8_t value) {
    hash ^= value;
    hash *= 16777619UL;
    return hash;
}

inline uint32_t proto_auth_tag_for(const LoraPacket* p) {
    uint32_t hash = 2166136261UL ^ proto_auth_seed();

    hash = proto_auth_mix(hash, p->magic[0]);
    hash = proto_auth_mix(hash, p->magic[1]);
    hash = proto_auth_mix(hash, p->version);
    hash = proto_auth_mix(hash, p->node_id);
    hash = proto_auth_mix(hash, p->fw_type);
    hash = proto_auth_mix(hash, p->direction);
    hash = proto_auth_mix(hash, p->seq);
    hash = proto_auth_mix(hash, p->severity);

    uint32_t ts = p->timestamp;
    hash = proto_auth_mix(hash, (uint8_t)(ts & 0xFF));
    hash = proto_auth_mix(hash, (uint8_t)((ts >> 8) & 0xFF));
    hash = proto_auth_mix(hash, (uint8_t)((ts >> 16) & 0xFF));
    hash = proto_auth_mix(hash, (uint8_t)((ts >> 24) & 0xFF));

    hash = proto_auth_mix(hash, p->payload_len);
    for (uint8_t i = 0; i < p->payload_len; i++) {
        hash = proto_auth_mix(hash, p->payload[i]);
    }

    return hash;
}

inline uint8_t proto_validate_reason(const LoraPacket* p) {
    if (p->magic[0] != PROTO_MAGIC_0 || p->magic[1] != PROTO_MAGIC_1) {
        return PROTO_ERR_MAGIC;
    }
    if (p->version != PROTO_VERSION) {
        return PROTO_ERR_VERSION;
    }
    if (p->payload_len > PROTO_MAX_PAYLOAD) {
        return PROTO_ERR_PAYLOAD_LEN;
    }
    if (PROTO_REQUIRE_ENCRYPTION && p->nonce == 0) {
        return PROTO_ERR_ENCRYPTION_NONCE;
    }
    return PROTO_VALID_OK;
}

inline bool proto_valid(const LoraPacket* p) {
    return proto_validate_reason(p) == PROTO_VALID_OK;
}

inline bool proto_authenticated(const LoraPacket* p) {
    if (!PROTO_REQUIRE_AUTH) {
        return true;
    }

    if (PROTO_REQUIRE_ENCRYPTION) {
        // AEAD tag is checked during proto_decrypt_payload().
        return true;
    }

    uint32_t expected = proto_auth_tag_for(p);
    uint32_t got = (uint32_t)p->auth_tag[0] |
                   ((uint32_t)p->auth_tag[1] << 8) |
                   ((uint32_t)p->auth_tag[2] << 16) |
                   ((uint32_t)p->auth_tag[3] << 24);
    return got == expected;
}

inline void proto_sign(LoraPacket* p) {
    if (!PROTO_REQUIRE_AUTH) {
        memset(p->auth_tag, 0, sizeof(p->auth_tag));
        return;
    }

    if (PROTO_REQUIRE_ENCRYPTION) {
        // Tag produced in proto_encrypt_payload().
        return;
    }

    uint32_t tag = proto_auth_tag_for(p);
    memset(p->auth_tag, 0, sizeof(p->auth_tag));
    p->auth_tag[0] = (uint8_t)(tag & 0xFF);
    p->auth_tag[1] = (uint8_t)((tag >> 8) & 0xFF);
    p->auth_tag[2] = (uint8_t)((tag >> 16) & 0xFF);
    p->auth_tag[3] = (uint8_t)((tag >> 24) & 0xFF);
}

inline void proto_init(LoraPacket* p, uint8_t node_id, uint8_t fw_type,
                       uint8_t direction, uint8_t severity) {
    p->magic[0]    = PROTO_MAGIC_0;
    p->magic[1]    = PROTO_MAGIC_1;
    p->version     = PROTO_VERSION;
    p->node_id     = node_id;
    p->fw_type     = fw_type;
    p->direction   = direction;
    p->severity    = severity;
    p->nonce       = 0;
    memset(p->auth_tag, 0, sizeof(p->auth_tag));
    p->payload_len = 0;
}

inline const char* fw_name(uint8_t fw_type) {
    switch (fw_type) {
        case FW_PING:     return "PING";
        case FW_SCANNER:  return "SCANNER";
        default:          return "UNK";
    }
}

inline const char* sev_name(uint8_t sev) {
    switch (sev) {
        case SEV_INFO:     return "INFO";
        case SEV_LOW:      return "LOW";
        case SEV_MEDIUM:   return "MED";
        case SEV_HIGH:     return "HIGH";
        case SEV_CRITICAL: return "CRIT";
        default:           return "?";
    }
}
