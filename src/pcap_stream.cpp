#include "pcap_stream.h"
#include "config.h"
#include <Arduino.h>
#include <string.h>

// ─── PCAP file format constants ───────────────────────────────────────────
// Reference: https://wiki.wireshark.org/Development/LibpcapFileFormat
#define PCAP_MAGIC        0xA1B2C3D4UL   // little-endian microsecond timestamps
#define PCAP_VER_MAJOR    2
#define PCAP_VER_MINOR    4
#define PCAP_DLT_IEEE802_11_RADIO  127   // 802.11 with radiotap header

// ─── Radiotap header layout ───────────────────────────────────────────────
// We emit a minimal radiotap with Channel and Antenna Signal fields.
// Byte order: little-endian throughout.
//
//  Offset  Size  Field
//    0       1   it_version  (always 0)
//    1       1   it_pad      (always 0)
//    2       2   it_len      (= 13, total radiotap header bytes)
//    4       4   it_present  (= 0x00000028: bit3=Channel, bit5=Ant.Signal)
//    8       2   channel_freq (MHz, e.g. 2412 for ch1)
//   10       2   channel_flags (0x00A0 = 2.4GHz OFDM)
//   12       1   antenna_signal (signed dBm)
// Total: 13 bytes
#define RADIOTAP_LEN      13
#define CHAN_FLAGS_2G     0x00A0   // 2.4GHz OFDM

// Channel number → centre frequency (MHz)
static uint16_t channelToFreq(uint8_t ch) {
    if (ch == 14) return 2484;
    if (ch >= 1 && ch <= 13) return (uint16_t)(2412 + (ch - 1) * 5);
    return 2412;  // fallback
}

// Write N bytes to Serial as raw binary
static void writeBytes(const void* data, size_t len) {
    Serial.write(reinterpret_cast<const uint8_t*>(data), len);
}

static void writeU16LE(uint16_t v) { writeBytes(&v, 2); }
static void writeU32LE(uint32_t v) { writeBytes(&v, 4); }

// ─── PCAP global header (24 bytes) ───────────────────────────────────────
void pcapStreamBegin() {
    // Flush any pending text output first
    Serial.flush();

    writeU32LE(PCAP_MAGIC);
    writeU16LE(PCAP_VER_MAJOR);
    writeU16LE(PCAP_VER_MINOR);
    writeU32LE(0);                   // thiszone (UTC offset, 0 = UTC)
    writeU32LE(0);                   // sigfigs (always 0)
    writeU32LE(PCAP_SNAPLEN);        // snaplen
    writeU32LE(PCAP_DLT_IEEE802_11_RADIO);  // network (link type)
    Serial.flush();
}

// ─── Per-packet record ────────────────────────────────────────────────────
// Layout: [pcap_pkt_hdr:16][radiotap:13][802.11_frame:frame.len]
void pcapStreamWrite(const RawFrame* frame) {
    uint32_t incl_len = RADIOTAP_LEN + frame->len;
    uint32_t orig_len = RADIOTAP_LEN + frame->orig_len;

    // PCAP packet header (16 bytes)
    uint32_t ts_sec  = frame->timestamp_us / 1000000UL;
    uint32_t ts_usec = frame->timestamp_us % 1000000UL;
    writeU32LE(ts_sec);
    writeU32LE(ts_usec);
    writeU32LE(incl_len);
    writeU32LE(orig_len);

    // Radiotap header (13 bytes)
    uint8_t radiotap[RADIOTAP_LEN] = {};
    radiotap[0] = 0;                               // version
    radiotap[1] = 0;                               // pad
    // it_len LE
    radiotap[2] = RADIOTAP_LEN & 0xFF;
    radiotap[3] = (RADIOTAP_LEN >> 8) & 0xFF;
    // it_present LE: bit3=Channel (0x08), bit5=AntennaSignal (0x20) → 0x28
    radiotap[4] = 0x28; radiotap[5] = 0; radiotap[6] = 0; radiotap[7] = 0;
    // Channel frequency LE
    uint16_t freq = channelToFreq(frame->channel);
    radiotap[8]  = freq & 0xFF;
    radiotap[9]  = (freq >> 8) & 0xFF;
    // Channel flags LE
    radiotap[10] = CHAN_FLAGS_2G & 0xFF;
    radiotap[11] = (CHAN_FLAGS_2G >> 8) & 0xFF;
    // Antenna signal (signed byte, dBm)
    radiotap[12] = (uint8_t)(int8_t)frame->rssi;

    writeBytes(radiotap, RADIOTAP_LEN);

    // Raw 802.11 frame
    writeBytes(frame->data, frame->len);
    Serial.flush();
}
