# 🛡️ NetSentinel

A real-time Network Intrusion Detection System (IDS) built with Python.

> ⚠️ **WARNING:** Use only on networks you are authorized to monitor.

---

## 🔥 Features

- **SYN Flood Detection** → Detects TCP SYN flood attacks in real-time
- **Port Scan Detection** → Identifies port scanning attempts
- **Brute Force Detection** → Monitors SSH, FTP, RDP, VNC, Telnet
- **ICMP Flood Detection** → Detects ping flood / ping of death
- **ARP Spoofing Detection** → Identifies ARP poisoning attacks
- **DNS Anomaly Detection** → Detects DNS flood attacks
- **HTML Report Generation** → Beautiful visual reports
- **Real-time Alerting** → Instant alerts with severity levels
- **Configurable Rules** → JSON-based rule configuration

---

## ⚙️ Installation

```bash
git clone https://github.com/berfin-sec/NetSentinel.git
cd NetSentinel
pip install -r requirements.txt
```

> **Windows users:** Install [Npcap](https://npcap.com/#download) for packet capture support.

---

## 🚀 Usage

```bash
# Basic usage
python netsentinel.py

# Specify network interface
python netsentinel.py -i eth0

# Capture 100 packets and generate report
python netsentinel.py -c 100 --report

# Custom config file
python netsentinel.py --config rules/custom.json
```

---

## 🚨 Alert Severity Levels

| Level | Description |
|-------|-------------|
| 🔵 LOW | Informational alerts |
| 🟡 MEDIUM | Suspicious activity |
| 🟠 HIGH | Likely attack detected |
| 🔴 CRITICAL | Active attack in progress |

---

## ⚙️ Configuration

Edit `rules/config.json` to customize detection thresholds:

| Parameter | Default | Description |
|-----------|---------|-------------|
| syn_threshold | 100 | SYN packets to trigger alert |
| port_scan_threshold | 20 | Unique ports to trigger alert |
| brute_force_threshold | 10 | Connection attempts to trigger alert |
| icmp_threshold | 50 | ICMP packets to trigger alert |
| dns_threshold | 50 | DNS queries to trigger alert |

---

## ⚠️ Legal Disclaimer

This tool is developed for **educational purposes** and **ethical security research only**.
Always get proper authorization before monitoring any network.

---

## 📜 License

MIT License
