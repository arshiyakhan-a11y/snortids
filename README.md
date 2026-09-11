# NIDS_Snort3_Complete - Network Intrusion Detection System

Complete NIDS pipeline for **Kali Linux** with **Snort 3.12.2.0**.

## Quick Start

```bash
# 1. Unzip and enter directory
cd NIDS_Snort3_Complete

# 2. Fix permissions FIRST (important!)
chmod 777 data data/preprocessed logs pcaps dashboard/static/charts
# Or run: ./fix_permissions.sh

# 3. Setup Snort 3 rules (needs sudo)
sudo python3 setup.py

# 4. Create virtual environment
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt

# 5. Generate test pcap
python test_pcap_generator.py

# 6. Run full analysis pipeline
sudo venv/bin/python main.py --pcap pcaps/test.pcap

# 7. OR start web dashboard
venv/bin/python dashboard/app.py
# Open http://127.0.0.1:5000
```

## Or use the launcher script
```bash
./run_dashboard.sh
```

## Pipeline Steps
1. **Capture** - Scapy reads pcap or captures live traffic
2. **Preprocess** - Feature extraction (IPs, ports, protocols, sizes)
3. **Snort 3** - Runs snort with rules, captures alerts from stdout
4. **Parse** - Extracts alerts from combined stdout/stderr
5. **Visualize** - 6 Matplotlib charts
6. **Dashboard** - Flask web UI with upload & live capture

## Snort 3 Rules (20 rules)
All Snort 3.12.2.0 compatible:
- ICMP Ping / Flood
- TCP SYN Flood / Port Scan
- SSH / FTP / Telnet / RDP / MySQL / SMB detection
- HTTP / DNS / UDP traffic
- Meterpreter port 4444
- Large packet anomaly

## Files
| File | Purpose |
|------|---------|
| main.py | Full pipeline orchestrator |
| capture_traffic.py | Scapy capture/read pcap |
| preprocess_traffic.py | Feature extraction |
| snort_runner.py | Snort 3 wrapper with stdout capture |
| alert_parser.py | Parse alerts from combined output |
| visualize.py | Matplotlib charts |
| dashboard/app.py | Flask web server |
| dashboard/templates/index.html | Dashboard UI |
| rules/local.rules | 20 Snort 3 rules |
| setup.py | Configure Snort rules + fix permissions |
| test_pcap_generator.py | Generate test traffic |
| run_dashboard.sh | One-click dashboard launcher |
| fix_permissions.sh | Fix directory permissions |

## Troubleshooting

**Permission denied on pcaps/ or data/?**
```bash
chmod 777 data data/preprocessed logs pcaps dashboard/static/charts
./fix_permissions.sh
```

**externally-managed-environment?**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**setuptools error?**
```bash
pip install --upgrade pip setuptools wheel
```

**No alerts?**
```bash
# Check rules are valid
sudo snort -c /etc/snort/snort.lua -R /etc/snort/rules/local.rules -T
# Should show: Rule syntax: VALID
```

**Permission denied for Snort?**
```bash
sudo venv/bin/python main.py --pcap pcaps/test.pcap
```
