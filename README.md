# Network Intrusion Detection System (NIDS)

A modular, real-time **Network Intrusion Detection System** built using **Python, Scapy, Flask, and Chart.js** on **Kali Linux**.  
The system captures live network traffic, detects common network attacks, logs alerts, and visualizes them on a SOC-style web dashboard.

---

## 📌 Features

### 🔍 Real-Time Detection
- SYN Flood Attack Detection
- TCP Port Scan Detection
- Repeated Failed TCP Handshake Detection
- Blacklisted IP Detection

### 📊 Visualization Dashboard
- Flask-based web dashboard
- Chart.js attack statistics
- Live alert table (auto-refresh)

### 🧠 Clean Architecture
- Packet capture and detection logic separated
- Easily extensible detection engine
- JSON-based alert logging (SIEM-style)

---

## 🏗️ System Architecture

+-------------------+
| Network Interface |
+-------------------+
|
v
+-------------------+
| Scapy Packet |
| Sniffer |
+-------------------+
|
v
+-------------------+
| Detection Engine |
| (detector.py) |
+-------------------+
|
v
+-------------------+
| alerts.json |
+-------------------+
|
v
+-------------------+
| Flask REST API |
+-------------------+
|
v
+-------------------+
| Web Dashboard |
| (Chart.js) |
+-------------------+


---

## 🧰 Tech Stack

| Layer | Technology |
|-----|-----------|
| OS | Kali Linux |
| Language | Python 3 |
| Packet Capture | Scapy |
| Backend | Flask |
| Frontend | HTML, Chart.js |
| Data Storage | JSON |
| Visualization | Chart.js |

---

## 📁 Project Structure

network-nids/
│
├── packet_sniffer.py # Packet capture logic
├── detector.py # Attack detection engine
├── app.py # Flask dashboard backend
├── alerts.json # Logged alerts
├── blacklist.txt # Blacklisted IPs
│
├── templates/
│ └── dashboard.html # Dashboard UI
│
├── static/
│ └── charts.js # Chart.js logic
│
└── README.md

---

## ⚙️ Installation & Setup

### 1️⃣ Prerequisites
- Kali Linux
- Python 3
- Root privileges (required for packet sniffing)

### 2️⃣ Install Dependencies
sudo apt update
sudo apt install python3-pip libpcap-dev -y
pip install scapy flask

▶️ Running the Project
Terminal 1 – Start IDS
sudo python3 packet_sniffer.py

Terminal 2 – Start Dashboard
python3 app.py

Open in Browser
http://127.0.0.1:5000

🧪 Testing Attacks (Lab / VM Only)
Port Scan
nmap -sS -p 1-1000 <target-ip>

SYN Flood
sudo hping3 -S -p 80 --flood <target-ip>

Failed Handshakes
sudo hping3 -S -p 22 --flood <target-ip>

⚠️Warning - Only test on systems you own or have permission to test.

📄 Alert Types

SYN_FLOOD
PORT_SCAN
FAILED_HANDSHAKES
BLACKLISTED_IP

All alerts are stored in alerts.json with timestamps.
