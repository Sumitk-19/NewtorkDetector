from scapy.all import sniff, IP, TCP
from collections import defaultdict
from datetime import datetime, timedelta

# ==============================
# CONFIGURATION
# ==============================
SYN_THRESHOLD = 50          # SYN packets
TIME_WINDOW = 10            # seconds

# ==============================
# DATA STRUCTURES
# ==============================
syn_tracker = defaultdict(list)

# ==============================
# PACKET PROCESSOR
# ==============================
def process_packet(packet):
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        flags = packet[TCP].flags

        timestamp = datetime.now()

        # SYN packet (S flag set, A flag not set)
        if flags == "S":
            syn_tracker[src_ip].append(timestamp)

            # Remove old SYNs outside time window
            syn_tracker[src_ip] = [
                t for t in syn_tracker[src_ip]
                if timestamp - t <= timedelta(seconds=TIME_WINDOW)
            ]

            syn_count = len(syn_tracker[src_ip])

            print(f"[{timestamp.strftime('%H:%M:%S')}] "
                  f"SYN detected from {src_ip} -> {dst_ip} "
                  f"(Count: {syn_count})")

            # ALERT CONDITION
            if syn_count >= SYN_THRESHOLD:
                print("\n" + "!" * 60)
                print(f"[ALERT] POSSIBLE SYN FLOOD ATTACK DETECTED")
                print(f"Source IP: {src_ip}")
                print(f"SYN packets in {TIME_WINDOW}s: {syn_count}")
                print("!" * 60 + "\n")

def start_sniffing():
    print("[*] Starting packet sniffing with SYN flood detection...")
    print("[*] Press CTRL+C to stop.\n")
    sniff(filter="tcp", prn=process_packet, store=False)

# ==============================
# MAIN
# ==============================
if __name__ == "__main__":
    start_sniffing()
