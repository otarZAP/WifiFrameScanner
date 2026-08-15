# WifiFrameScanner — Passive 802.11 Scanner with LoRa Telemetry

**Status:** Complete — generate real LoRa keys before deploy
**Board:** Heltec WiFi LoRa 32 V4 (ESP32-S3 + SX1262)
**Role:** Passive 802.11 scanner with Kismet-style AP/client tracking, live Wireshark PCAP output, and LoRa telemetry

---

## What It Does

WifiFrameScanner puts the ESP32's built-in 2.4GHz WiFi radio into promiscuous monitor mode and silently captures 802.11 frames. An onboard SX1262 LoRa radio optionally transmits findings to a LoRa base station — the ESP32 WiFi radio does the scanning, LoRa is purely for reporting.

| What it captures | Detail |
|---|---|
| **Beacons** | Every AP nearby — SSID, BSSID, channel, RSSI, encryption, WPS flag |
| **Probe Requests** | Client MAC, OUI vendor, SSIDs the device is searching for |
| **Client associations** | Which client is connected to which AP — inferred from data frame headers, no decryption |
| **Deauth / Disassoc** | Who is sending deauth frames and at whom |
| **Live PCAP** | Binary 802.11+radiotap stream over USB serial → pipe directly into Wireshark |

**Limits:** 2.4GHz only. Data frame payloads are always encrypted — management frames are fully visible. Frames truncated at 512 bytes.

---

## Hardware

| Item | Notes |
|---|---|
| Heltec WiFi LoRa 32 V4 | ESP32-S3 + SX1262 + onboard OLED — one board, no extras needed |
| USB cable | Required for flashing and for the PCAP serial stream |

---

## LoRa Telemetry Protocol

`include/lora_protocol.h` is a self-contained packet format for reporting scan events to a base station — no external dependencies:

- 37-byte header (magic, version, node ID, sequence, timestamp, per-packet nonce) + up to 200 bytes of payload
- AES-256-EAX authenticated encryption keyed from a CSPRNG-generated shared secret plus a 4-word auth seed
- Four report types, debounced independently: periodic scan summary (every 30s), new-AP, new-client, and deauth events, each tagged with its own severity

If you don't have a matching LoRa base station, the scanner still runs standalone — LoRa transmit failures are logged and otherwise ignored; scanning, the OLED display, serial output, and PCAP mode all work with no base station present.

---

## Configuration

1. Copy `include/secrets.example.h` → `include/secrets.h` and fill in LoRa keys
2. Optionally change `NODE_ID` in `include/config.h` if `0x05` conflicts with another node on your LoRa network

---

## Flash

```bash
cd WifiFrameScanner
pio run -t upload
pio device monitor   # 115200 baud
```

---

## Operating Modes

| Mode | How to enter | Behaviour |
|---|---|---|
| **SCAN** | Default on boot | Channel-hops 1–13, human-readable serial, LoRa reports |
| **Fixed** | Short press BTN_MODE or send `h` via serial | Stays on current channel, still text serial |
| **PCAP** | Hold BTN_MODE 2s or send `p` via serial | Binary PCAP on serial at 921600 baud → Wireshark |

---

## Live Wireshark Capture

Enter PCAP mode first (hold BTN_MODE 2s), then:

```bash
pip install pyserial

# Windows
python scripts/scanner_pipe.py COM3 | wireshark -k -i -

# Linux / macOS
python scripts/scanner_pipe.py /dev/ttyUSB0 | wireshark -k -i -

# Save to file instead
python scripts/scanner_pipe.py COM3 > capture.pcap
```

Useful Wireshark display filters:

```
wlan.fc.type_subtype == 8    beacons
wlan.fc.type_subtype == 4    probe requests
wlan.fc.type_subtype == 12   deauth frames
eapol                        WPA 4-way handshake
wlan.ssid contains "Name"    filter by SSID
wlan.sa == aa:bb:cc:dd:ee:ff filter by MAC
```

---

## Display Views (cycle with BTN_VIEW / GPIO 0)

| View | Shows |
|---|---|
| STATUS | Channel, hop/fixed, AP count, client count, total frames, deauth count, LoRa RSSI |
| NETWORKS | Scrolling AP list — SSID, encryption, RSSI, channel |
| CLIENTS | Scrolling client list — MAC, vendor, probed SSIDs |
| ACTIVITY | Live counters — total frames, mgmt, beacons, probes, deauths, queue drops |

**BTN_MODE (GPIO 35) short press:** toggle channel hop on/off
**BTN_MODE long press (2s):** toggle PCAP mode

New AP and deauth events flash a 3-second alert over whatever view is active.

---

## Serial Commands (SCAN mode only, 115200 baud)

| Key | Action |
|---|---|
| `p` | Toggle PCAP mode |
| `h` | Toggle channel hopping |
| `1`–`9`, `a`–`d` | Jump to channel 1–13 |
| `s` | Print AP/client/frame summary |
| `r` | Reset frame counters |

---

## Notes for Reviewers

This is a portfolio-scoped extraction of a larger personal WiFi-monitoring project; `include/lora_protocol.h` here is a trimmed, standalone copy of a shared wire format used across several sibling projects, kept self-contained for this repo. This scanner is receive-only with respect to 802.11 — it never transmits deauth or any other 802.11 frame, only passively observes and (optionally) reports over LoRa.
