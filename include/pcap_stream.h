#pragma once
#include "frame_capture.h"

// PCAP stream over Serial (USB).
//
// Binary format written to Serial:
//   1. pcapStreamBegin()  — writes the 24-byte PCAP global header once
//   2. pcapStreamWrite()  — writes one packet record per frame:
//        [ts_sec:4][ts_usec:4][incl_len:4][orig_len:4]
//        [radiotap_header:13][802.11_frame:incl_len-13]
//
// The Python helper (scripts/scanner_pipe.py) reads this stream and
// pipes it to Wireshark via stdin:
//   python scanner_pipe.py COM3 | wireshark -k -i -
//
// DLT type: DLT_IEEE802_11_RADIO (127) — 802.11 with radiotap header.
// This is the same link type used by real WiFi capture adapters.

void pcapStreamBegin();   // write global header — call once on PCAP mode entry
void pcapStreamWrite(const RawFrame* frame);  // write one packet record
