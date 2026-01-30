#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Windows Scapy Sniffer – Behavioral Feature Extraction
Extracts 11 semantically meaningful features per packet
and stores them as NDJSON (JSON Lines) for flow aggregation & LLM ingestion.
"""

import time
import argparse
import sys
import json
from datetime import datetime
from collections import Counter

from scapy.all import (
    sniff, IP, TCP, UDP, ICMP, ARP,
    Ether, PcapWriter,
    get_if_list, get_if_addr, get_if_hwaddr
)

# ==================== CLI ====================

def parse_args():
    p = argparse.ArgumentParser(description="Behavioral Network Sniffer (LLM-ready)")
    p.add_argument("-i", "--iface", required=False, help="Interface name (use --list)")
    p.add_argument("--list", action="store_true", help="List interfaces and exit")
    p.add_argument("--pcap", help="Optional PCAP output file")
    p.add_argument("--promisc", action="store_true", help="Enable promiscuous mode")
    return p.parse_args()

def list_ifaces_and_exit():
    print("Available interfaces:")
    for iface in get_if_list():
        print(" -", iface)
    sys.exit(0)

# ==================== Helpers ====================

def safe_lower(x):
    return x.lower() if isinstance(x, str) else x

def identify_protocol(pkt):
    if pkt.haslayer(ARP):
        return "ARP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    return "OTHER"

def tcp_flags_to_str(flags):
    return str(flags) if flags else None

# ==================== Main ====================

def main():
    args = parse_args()

    if args.list:
        list_ifaces_and_exit()

    if not args.iface:
        print("No interface specified. Use --list")
        sys.exit(1)

    try:
        my_ip = get_if_addr(args.iface)
    except Exception:
        my_ip = None

    try:
        my_mac = safe_lower(get_if_hwaddr(args.iface))
    except Exception:
        my_mac = None

    print(f"Listening on      : {args.iface}")
    print(f"Detected IP       : {my_ip}")
    print(f"Detected MAC      : {my_mac}")
    print("Feature set       : Packet-level behavioral features")
    print("Output format     : NDJSON (JSON Lines)")
    print("Press Ctrl+C to stop\n")

    stats = Counter()
    writer = None

    if args.pcap:
        writer = PcapWriter(args.pcap, append=True, sync=True)
        print(f"Writing PCAP to   : {args.pcap}")

    json_out = open("captured_packets.jsonl", "a", buffering=1)

    # ---------------- Packet Direction ----------------

    def get_direction(pkt):
        if pkt.haslayer(IP) and my_ip:
            if pkt[IP].dst == my_ip:
                return "inbound"
            elif pkt[IP].src == my_ip:
                return "outbound"
        return "unknown"

    # ---------------- Packet Handler ----------------

    def handle(pkt):
        try:
            if not pkt.haslayer(IP):
                return

            ip = pkt[IP]

            protocol = identify_protocol(pkt)
            direction = get_direction(pkt)

            src_ip = ip.src
            dst_ip = ip.dst
            ttl = ip.ttl

            # ✅ CORRECT BYTE COUNT
            packet_bytes = len(pkt)

            src_port = None
            dst_port = None
            tcp_flags = None
            icmp_type = None

            if pkt.haslayer(TCP):
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                tcp_flags = tcp_flags_to_str(pkt[TCP].flags)

            elif pkt.haslayer(UDP):
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport

            elif pkt.haslayer(ICMP):
                icmp_type = pkt[ICMP].type

            record = {
                "timestamp": datetime.utcnow().isoformat(),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "direction": direction,
                "protocol": protocol,

                # ✅ BYTE-SAFE FIELDS
                "packet_bytes": packet_bytes,
                "packet_length": packet_bytes,  # kept for compatibility

                "ttl": ttl,
                "tcp_flags": tcp_flags,
                "icmp_type": icmp_type
            }

            json_out.write(json.dumps(record) + "\n")

            if writer:
                writer.write(pkt)

            stats[protocol] += 1

            ts = time.strftime("%H:%M:%S")
            print(f"{ts} {protocol:5} {direction:8} bytes={packet_bytes:4} "
                  f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}")

        except Exception as e:
            print("Error:", e)

    # ---------------- Start Capture ----------------

    try:
        sniff(
            iface=args.iface,
            prn=handle,
            store=False,
            promisc=args.promisc
        )
    except KeyboardInterrupt:
        print("\n[+] Capture stopped.")
    finally:
        json_out.close()
        if writer:
            writer.close()

        print("\n===== Summary =====")
        for proto, count in stats.items():
            print(f"{proto:>6} : {count}")
        print("===================")

# ==================== Entry ====================

if __name__ == "__main__":
    main()
