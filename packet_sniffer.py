from scapy.all import sniff, IP, TCP
from datetime import datetime
import detector

def process_packet(packet):
    if IP not in packet or TCP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    dst_port = packet[TCP].dport
    flags = packet[TCP].flags
    timestamp = datetime.now()

    alerts = []

    alerts.append(detector.detect_blacklist(src_ip, dst_ip, dst_port))
    alerts.append(detector.detect_syn_flood(src_ip, timestamp))
    alerts.append(detector.detect_port_scan(src_ip, dst_port, timestamp))
    alerts.append(detector.detect_failed_handshake(src_ip, flags, timestamp))

    for alert in alerts:
     if alert:
        detector.log_alert(alert)
        print("\n" + "=" * 60)
        print(f"[ALERT] {alert['type']}")
        for k, v in alert.items():
            if k != "type":
                print(f"{k}: {v}")
        print("=" * 60 + "\n")


    print(f"[{timestamp.strftime('%H:%M:%S')}] "
          f"{src_ip} -> {dst_ip}:{dst_port} | FLAGS={flags}")

def start_sniffing():
    print("[*] Network IDS running (Modular Architecture)")
    print("[*] Press CTRL+C to stop\n")
    sniff(filter="tcp", prn=process_packet, store=False)

if __name__ == "__main__":
    start_sniffing()
