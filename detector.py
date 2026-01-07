from collections import defaultdict
from datetime import datetime, timedelta

# ==============================
# CONFIGURATION
# ==============================
TIME_WINDOW = 10  # seconds

SYN_THRESHOLD = 50
PORT_SCAN_THRESHOLD = 20
FAILED_HANDSHAKE_THRESHOLD = 30

BLACKLIST_FILE = "blacklist.txt"

# ==============================
# LOAD BLACKLIST
# ==============================
def load_blacklist():
    try:
        with open(BLACKLIST_FILE, "r") as f:
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        return set()

blacklisted_ips = load_blacklist()

# ==============================
# TRACKERS
# ==============================
syn_tracker = defaultdict(list)
port_scan_tracker = defaultdict(dict)
handshake_tracker = defaultdict(lambda: {"syn": [], "ack": []})

# ==============================
# DETECTION FUNCTIONS
# ==============================
def detect_blacklist(src_ip, dst_ip, dst_port):
    if src_ip in blacklisted_ips:
        return {
            "type": "BLACKLISTED_IP",
            "src_ip": src_ip,
            "dst": f"{dst_ip}:{dst_port}",
            "time": datetime.now()
        }

def detect_syn_flood(src_ip, timestamp):
    syn_tracker[src_ip].append(timestamp)
    syn_tracker[src_ip] = [
        t for t in syn_tracker[src_ip]
        if timestamp - t <= timedelta(seconds=TIME_WINDOW)
    ]

    if len(syn_tracker[src_ip]) >= SYN_THRESHOLD:
        return {
            "type": "SYN_FLOOD",
            "src_ip": src_ip,
            "count": len(syn_tracker[src_ip]),
            "time": timestamp
        }

def detect_port_scan(src_ip, dst_port, timestamp):
    port_scan_tracker[src_ip][dst_port] = timestamp
    port_scan_tracker[src_ip] = {
        p: t for p, t in port_scan_tracker[src_ip].items()
        if timestamp - t <= timedelta(seconds=TIME_WINDOW)
    }

    if len(port_scan_tracker[src_ip]) >= PORT_SCAN_THRESHOLD:
        return {
            "type": "PORT_SCAN",
            "src_ip": src_ip,
            "ports": list(port_scan_tracker[src_ip].keys()),
            "time": timestamp
        }

def detect_failed_handshake(src_ip, flags, timestamp):
    if flags == "S":
        handshake_tracker[src_ip]["syn"].append(timestamp)
    if "A" in flags:
        handshake_tracker[src_ip]["ack"].append(timestamp)

    handshake_tracker[src_ip]["syn"] = [
        t for t in handshake_tracker[src_ip]["syn"]
        if timestamp - t <= timedelta(seconds=TIME_WINDOW)
    ]
    handshake_tracker[src_ip]["ack"] = [
        t for t in handshake_tracker[src_ip]["ack"]
        if timestamp - t <= timedelta(seconds=TIME_WINDOW)
    ]

    failed = (
        len(handshake_tracker[src_ip]["syn"])
        - len(handshake_tracker[src_ip]["ack"])
    )

    if failed >= FAILED_HANDSHAKE_THRESHOLD:
        return {
            "type": "FAILED_HANDSHAKES",
            "src_ip": src_ip,
            "count": failed,
            "time": timestamp
        }

import json
import os

ALERT_FILE = "alerts.json"

def log_alert(alert):
    if not alert:
        return

    if not os.path.exists(ALERT_FILE):
        with open(ALERT_FILE, "w") as f:
            json.dump([], f)

    with open(ALERT_FILE, "r+") as f:
        data = json.load(f)
        alert["time"] = alert["time"].strftime("%Y-%m-%d %H:%M:%S")
        data.append(alert)
        f.seek(0)
        json.dump(data, f, indent=4)
