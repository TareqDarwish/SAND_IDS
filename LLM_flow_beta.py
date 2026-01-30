#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Edge Flow Processor
- Reads packet NDJSON from sniffer
- Aggregates packets into flows
- Assigns priority at the edge
- Sends flows securely to central server via HTTPS API
"""

import json
import time
import requests
from datetime import datetime
from collections import Counter

# ==================== Configuration ====================

PACKET_FILE = "captured_packets.jsonl"

# 🔐 HTTPS endpoint on central server
SERVER_API = "https://192.168.100.174:8443/api/flows" #change this to your server IP

WINDOW_SECONDS = 5
POLL_INTERVAL = 1

# ⚠️ For self-signed certificates (development only)
VERIFY_TLS = False   # set to True when using CA-signed certs

# ==================== Flow State ====================

flows = {}
last_file_position = 0

# ==================== Helpers ====================

def parse_ts(ts):
    return datetime.fromisoformat(ts)

def make_flow_key(pkt):
    """
    Directional 5-tuple
    """
    return (
        pkt.get("src_ip"),
        pkt.get("dst_ip"),
        pkt.get("src_port"),
        pkt.get("dst_port"),
        pkt.get("protocol")
    )

def init_flow(pkt):
    return {
        "start_time": pkt["timestamp"],
        "last_seen": pkt["timestamp"],
        "packet_count": 0,
        "byte_count": 0,
        "ttl_values": [],
        "tcp_flags": Counter()
    }

def finalize_flow(flow_key, flow):
    start = parse_ts(flow["start_time"])
    end   = parse_ts(flow["last_seen"])
    duration = (end - start).total_seconds()

    src_ip, dst_ip, src_port, dst_port, proto = flow_key

    return {
        "flow_id": f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": proto,
        "start_time": flow["start_time"],
        "end_time": flow["last_seen"],
        "duration_sec": round(duration, 3),
        "packet_count": flow["packet_count"],
        "byte_count": flow["byte_count"],
        "avg_packet_size": (
            round(flow["byte_count"] / flow["packet_count"], 2)
            if flow["packet_count"] > 0 else 0
        ),
        "avg_ttl": (
            round(sum(flow["ttl_values"]) / len(flow["ttl_values"]), 2)
            if flow["ttl_values"] else None
        ),
        "tcp_flag_summary": dict(flow["tcp_flags"])
    }

# ==================== Priority Logic ====================

def assign_priority(flow):
    """
    Fast deterministic edge-side prioritization
    (NO LLM here)
    """

    proto = flow["protocol"]
    pkt_count = flow["packet_count"]
    duration = flow["duration_sec"]
    avg_size = flow["avg_packet_size"]
    flags = flow["tcp_flag_summary"]
    dst_port = flow["dst_port"]

    # ---------- HIGH ----------
    if proto == "TCP" and dst_port == 21 and pkt_count > 50:
        return "HIGH"

    if pkt_count > 200 and duration < 2:
        return "HIGH"

    if "S" in flags and "F" in flags:
        return "HIGH"

    # ---------- MEDIUM ----------
    if pkt_count > 50 and avg_size < 200:
        return "MEDIUM"

    if duration > 30 and pkt_count < 10:
        return "MEDIUM"

    # ---------- LOW ----------
    return "LOW"

# ==================== Secure API Send ====================

def send_to_server(flow):
    try:
        r = requests.post(
            SERVER_API,
            json=flow,
            timeout=3,
            verify=VERIFY_TLS
        )

        if r.status_code == 200:
            print(f"[✓] Sent flow {flow['flow_id']} ({flow['priority']})")
        else:
            print(f"[!] Server error {r.status_code}: {r.text}")

    except requests.exceptions.RequestException as e:
        print(f"[!] Failed to send flow {flow['flow_id']}: {e}")


# ==================== Main Loop ====================

print("[*] Edge flow processor started")
print(f"[*] Reading packets from : {PACKET_FILE}")
print(f"[*] Sending flows to     : {SERVER_API}")
print(f"[*] TLS verification     : {VERIFY_TLS}\n")

with open(PACKET_FILE, "r") as pkt_file:
    while True:
        pkt_file.seek(last_file_position)
        new_lines = pkt_file.readlines()
        last_file_position = pkt_file.tell()

        now = datetime.utcnow()

        # ---------- Process new packets ----------
        for line in new_lines:
            try:
                pkt = json.loads(line.strip())
            except json.JSONDecodeError:
                continue

            key = make_flow_key(pkt)

            if key not in flows:
                flows[key] = init_flow(pkt)

            flow = flows[key]
            flow["packet_count"] += 1
            flow["byte_count"] += pkt.get("packet_bytes", 0)
            flow["last_seen"] = pkt["timestamp"]

            if pkt.get("ttl") is not None:
                flow["ttl_values"].append(pkt["ttl"])

            if pkt.get("tcp_flags"):
                flow["tcp_flags"][pkt["tcp_flags"]] += 1

        # ---------- Expire and send flows ----------
        expired = []

        for key, flow in flows.items():
            if (now - parse_ts(flow["last_seen"])).total_seconds() >= WINDOW_SECONDS:
                record = finalize_flow(key, flow)
                record["priority"] = assign_priority(record)
                record["edge_timestamp"] = time.time()

                # 🚫 Ignore flows sent TO the IDS server itself (self-traffic)
                if record["dst_ip"] == "192.168.100.174" and record["dst_port"] == 8443:
                    expired.append(key)
                    continue

                send_to_server(record)
                expired.append(key)


        for key in expired:
            del flows[key]

        time.sleep(POLL_INTERVAL)
