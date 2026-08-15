#!/usr/bin/env python3
"""
scanner_pipe.py — serial PCAP bridge for Wireshark

Reads the binary PCAP stream from a scanner node over USB serial and writes
it to stdout so Wireshark can read it as a live capture.

Requirements:
    pip install pyserial

Usage:
    # Windows
    python scanner_pipe.py COM3 | wireshark -k -i -

    # Linux / macOS
    python scanner_pipe.py /dev/ttyUSB0 | wireshark -k -i -

    # Specify baud explicitly (default matches SERIAL_BAUD_PCAP in firmware)
    python scanner_pipe.py COM3 --baud 921600

    # Save to a .pcap file instead
    python scanner_pipe.py COM3 > capture.pcap

    # Save and display stats
    python scanner_pipe.py COM3 --stats > capture.pcap

Before running this script:
    1. Flash the scanner firmware to the Heltec board
    2. Power it on — it boots in SCAN mode (text serial)
    3. Enter PCAP mode: hold BTN_MODE (GPIO 35) for 2 seconds
       OR send 'p' via any serial terminal then close the terminal
    4. Run this script — it will start receiving the binary PCAP stream

Wireshark display filter tips (after opening):
    wlan.fc.type == 0                   all management frames
    wlan.fc.type_subtype == 8           beacons only
    wlan.fc.type_subtype == 4           probe requests
    wlan.fc.type_subtype == 12          deauth frames
    wlan.ssid contains "MyNetwork"      filter by SSID
    wlan.sa == aa:bb:cc:dd:ee:ff        filter by source MAC
"""

import sys
import time
import struct
import argparse

try:
    import serial
except ImportError:
    print("ERROR: pyserial not installed. Run: pip install pyserial", file=sys.stderr)
    sys.exit(1)

# PCAP global header magic — used to detect stream start
PCAP_MAGIC = b'\xd4\xc3\xb2\xa1'  # little-endian
PCAP_MAGIC_BE = b'\xa1\xb2\xc3\xd4'

PCAP_GLOBAL_HDR_LEN = 24
PCAP_PKT_HDR_LEN    = 16


def wait_for_pcap_header(ser, timeout_s=30):
    """Read bytes until we find the PCAP magic, then read the rest of the header."""
    print(f"[pipe] Waiting for PCAP stream from device...", file=sys.stderr)
    deadline = time.time() + timeout_s
    buf = b''
    while time.time() < deadline:
        chunk = ser.read(64)
        if not chunk:
            continue
        buf += chunk
        # Search for magic
        idx = buf.find(PCAP_MAGIC)
        if idx == -1:
            idx = buf.find(PCAP_MAGIC_BE)
        if idx != -1:
            buf = buf[idx:]
            # Read remaining header bytes if needed
            while len(buf) < PCAP_GLOBAL_HDR_LEN:
                more = ser.read(PCAP_GLOBAL_HDR_LEN - len(buf))
                if more:
                    buf += more
            print(f"[pipe] PCAP stream started — piping to Wireshark", file=sys.stderr)
            return buf[:PCAP_GLOBAL_HDR_LEN]
        # Keep tail in case magic spans two reads
        if len(buf) > 128:
            buf = buf[-8:]
    return None


def run(port: str, baud: int, show_stats: bool):
    try:
        ser = serial.Serial(port, baud, timeout=0.5)
    except serial.SerialException as e:
        print(f"[pipe] Cannot open {port}: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[pipe] Opened {port} @ {baud} baud", file=sys.stderr)

    hdr = wait_for_pcap_header(ser)
    if not hdr:
        print("[pipe] Timed out waiting for PCAP stream.", file=sys.stderr)
        print("[pipe] Is the device in PCAP mode? (hold BTN_MODE 2s or send 'p' via serial)", file=sys.stderr)
        ser.close()
        sys.exit(1)

    # Write global header to stdout
    sys.stdout.buffer.write(hdr)
    sys.stdout.buffer.flush()

    pkt_count  = 0
    byte_count = 0
    start_time = time.time()
    last_stat  = start_time

    try:
        while True:
            # Read packet header (16 bytes)
            pkt_hdr = b''
            while len(pkt_hdr) < PCAP_PKT_HDR_LEN:
                chunk = ser.read(PCAP_PKT_HDR_LEN - len(pkt_hdr))
                if chunk:
                    pkt_hdr += chunk

            if len(pkt_hdr) < PCAP_PKT_HDR_LEN:
                continue

            ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', pkt_hdr)

            # Sanity check — max frame size
            if incl_len > 65535:
                print(f"[pipe] Bogus incl_len={incl_len}, skipping", file=sys.stderr)
                continue

            # Read packet data
            pkt_data = b''
            while len(pkt_data) < incl_len:
                chunk = ser.read(incl_len - len(pkt_data))
                if chunk:
                    pkt_data += chunk

            # Write complete packet record to stdout
            sys.stdout.buffer.write(pkt_hdr)
            sys.stdout.buffer.write(pkt_data)
            sys.stdout.buffer.flush()

            pkt_count  += 1
            byte_count += PCAP_PKT_HDR_LEN + incl_len

            if show_stats:
                now = time.time()
                if now - last_stat >= 5.0:
                    elapsed = now - start_time
                    rate = byte_count / elapsed / 1024
                    print(f"[pipe] {pkt_count} frames  {byte_count/1024:.1f} KB  "
                          f"{rate:.1f} KB/s  {elapsed:.0f}s", file=sys.stderr)
                    last_stat = now

    except KeyboardInterrupt:
        elapsed = time.time() - start_time
        print(f"\n[pipe] Stopped. {pkt_count} frames captured in {elapsed:.1f}s", file=sys.stderr)
    finally:
        ser.close()


def main():
    parser = argparse.ArgumentParser(
        description="Pipe scanner PCAP stream to Wireshark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("port", help="Serial port (e.g. COM3 or /dev/ttyUSB0)")
    parser.add_argument("--baud", type=int, default=921600,
                        help="Baud rate (default: 921600, matches SERIAL_BAUD_PCAP)")
    parser.add_argument("--stats", action="store_true",
                        help="Print capture stats to stderr every 5 seconds")
    args = parser.parse_args()

    run(args.port, args.baud, args.stats)


if __name__ == "__main__":
    main()
