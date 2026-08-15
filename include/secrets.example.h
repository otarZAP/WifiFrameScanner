#pragma once
// Copy to secrets.h — never commit secrets.h.

// ─── LoRa shared keys (must match your LoRa base station's key table) ─────
#define PROTO_REQUIRE_AUTH        1
#define PROTO_REQUIRE_ENCRYPTION  1
#define PROTO_AES_KEY_TEXT        "REPLACE_WITH_BASE64_KEY="
#define PROTO_AUTH_KEY_A          0xDEADBEEFUL
#define PROTO_AUTH_KEY_B          0xCAFEBABEUL
#define PROTO_AUTH_KEY_C          0xFEEDFACEUL
#define PROTO_AUTH_KEY_D          0xC0FFEE00UL
