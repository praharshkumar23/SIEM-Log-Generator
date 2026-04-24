# 🛡️ SIEM Log Generator — Praharsh Edition

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=26&duration=3000&pause=1000&color=00FF41&center=true&vCenter=true&multiline=true&repeat=true&width=700&height=100&lines=SIEM+LOG+GENERATOR+v2.0;Multi-SIEM+SOC+Lab+Edition" alt="Typing SVG" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/Splunk-Ready-FF69B4?style=for-the-badge&logo=splunk&logoColor=white"/>
  <img src="https://img.shields.io/badge/Wazuh-Ready-005571?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Microsoft_Sentinel-Ready-0078D4?style=for-the-badge&logo=microsoft&logoColor=white"/>
  <img src="https://img.shields.io/badge/MITRE_ATT%26CK-Mapped-orange?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge"/>
</p>

<p align="center">
  <b>🔥 3,000+ Realistic Security Events | 🎯 30+ MITRE ATT&CK Techniques | 🖥️ 4 SIEM Output Formats</b>
</p>

---

## 👤 Author

**Praharsh Kumar**
*SOC Analyst | Detection Engineer | Multi-SIEM Lab Builder*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0077B5?style=flat&logo=linkedin)](https://linkedin.com/in/praharshkumar)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-181717?style=flat&logo=github)](https://github.com/praharsh-kumar)

---

## 📋 Overview

This is my personal SIEM log generator, built for my **Multi-VM SOC Lab**. I use this to practice threat hunting, build detection rules, and test my Splunk, Wazuh, ELK, and Microsoft Sentinel setups.

Unlike generic log generators, this one is **built around a real lab environment** — the IPs, hostnames, attack techniques, and tool names all match what I actually run in my lab.

### 🖥️ My Lab Setup

```
Kali Linux (Attacker)    → 192.168.66.104
Windows 10 VM (Target)   → 192.168.66.105
Splunk Enterprise VM     → 192.168.56.101
Wazuh Manager VM         → 192.168.66.102
ELK Stack VM             → 192.168.66.103
```

---

## ⚡ Features

### What Makes This Different

| Feature | Generic Generators | This Project |
|---------|-------------------|--------------|
| Output formats | JSON + CSV only | JSON + CSV + Wazuh + Sentinel |
| Lab IPs | Generic/random | Your actual lab IPs |
| Attack tools | Not specified | Hydra, Mimikatz, Metasploit, Nmap |
| Sysmon events | Basic | Event IDs 1, 3, 7, 8, 11, 13 |
| Wazuh format | ❌ | ✅ Rule levels + Agent info |
| Sentinel format | ❌ | ✅ KQL-ready fields |
| MITRE coverage | ~15 techniques | 30+ techniques |
| Event count | 2,500 | 3,000+ |

### 🎯 Event Categories

| Category | Event Types | MITRE Techniques |
|----------|-------------|------------------|
| 🔐 **Authentication** | Failed Login, Brute Force, RDP BF, SSH BF, Password Spray, Kerberoasting | T1110, T1558 |
| 💻 **Sysmon** | Process Create, Network Conn, Image Load, File Create, Registry Set | T1003, T1055, T1547 |
| 🐚 **Execution** | Reverse Shell, PowerShell, LOLBIN, WMI | T1059, T1218, T1047 |
| 🔼 **Privilege Esc** | Token Impersonation, SeDebugPrivilege | T1068 |
| 🌐 **Lateral Movement** | RDP, PsExec, WMI Remote | T1021, T1570 |
| 📤 **C2 & Exfil** | C2 Outbound, DNS Tunneling, Data Transfer | T1071, T1048 |
| 🛡️ **Endpoint** | Mimikatz, Process Injection, Malware, Ransomware | T1003, T1055, T1486 |
| ☁️ **Cloud** | IAM Abuse, Impossible Travel | T1098, T1078.004 |
| 🌊 **Network** | Firewall Blocks, Port Scans (Nmap), IDS Alerts | T1046 |
| 📧 **Email** | Phishing, Malicious Attachments | T1566 |
| 🔔 **Wazuh** | Rule-based alerts from Wazuh Manager | Various |

---

## 🚀 Quick Start

### Requirements

- Python 3.8+
- No external dependencies (standard library only)

### Run

```bash
# Clone
git clone https://github.com/praharsh-kumar/siem-log-generator.git
cd siem-log-generator

# Generate all logs
python generate_logs.py

# Convert formats
python convert_to_csv.py
```

### Output Files

```
output/
├── praharsh_siem_logs_3000.json      ← Full JSON (all fields)
├── praharsh_siem_logs_3000.csv       ← Splunk / ELK import
├── praharsh_siem_logs_wazuh.json     ← Wazuh-format (rule levels + agents)
└── praharsh_siem_logs_sentinel.json  ← Microsoft Sentinel KQL-ready
```

---

## 🖥️ SIEM Integration

### Splunk

```bash
# Upload CSV via Splunk Web
Settings → Add Data → Upload → praharsh_siem_logs_3000.csv

# Or monitor file
splunk add monitor /path/to/praharsh_siem_logs_3000.csv -sourcetype csv
```

Base SPL query:
```spl
source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| head 20
```

### Wazuh

```bash
# Copy to Wazuh manager
cp output/praharsh_siem_logs_wazuh.json /var/ossec/logs/alerts/
```

### Microsoft Sentinel

Use the Sentinel KQL-ready JSON with Azure Log Analytics API:
```python
import requests, json

with open("output/praharsh_siem_logs_sentinel.json") as f:
    logs = json.load(f)

# POST to Log Analytics workspace
headers = {"Authorization": "Bearer YOUR_TOKEN", "Content-Type": "application/json"}
requests.post("https://api.loganalytics.io/v1/workspaces/YOUR_WS/query",
              headers=headers, json={"logs": logs})
```

KQL query example:
```kql
praharsh_siem_logs_CL
| where Severity == "Critical"
| where MitreTechnique startswith "T1003"
| summarize count() by Computer, EventType
| sort by count_ desc
```

### ELK / Logstash

```yaml
input {
  file {
    path => "/path/to/praharsh_siem_logs_3000.json"
    codec => json
    start_position => "beginning"
  }
}
output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "praharsh-soc-lab-%{+yyyy.MM.dd}"
  }
}
```

---

## 📊 Splunk Dashboard

A complete Splunk dashboard is included in `docs/SPLUNK_DASHBOARD_GUIDE.md`.

Panels included:
- Total Event Count
- Security Events Over Time (by severity)
- MITRE ATT&CK Technique Distribution
- User Risk Scores
- Failed Login Trends
- C2 Communication Hotspots
- Security Posture Score (Gauge)
- Recent Malware Detections Table
- Most Targeted Hosts

---

## 🗺️ MITRE ATT&CK Coverage

| Tactic | Techniques |
|--------|-----------|
| Initial Access | T1566 (Phishing), T1078 (Valid Accounts) |
| Execution | T1059 (PowerShell/CMD), T1218 (LOLBIN), T1047 (WMI) |
| Persistence | T1053 (Sched Task), T1547 (Registry), T1543 (Service) |
| Privilege Escalation | T1068, T1055 (Process Injection) |
| Defense Evasion | T1070 (Log Clear), T1562 (Disable AV), T1218 (LOLBIN) |
| Credential Access | T1003 (Mimikatz/LSASS), T1110 (Brute Force), T1558 (Kerberoasting) |
| Discovery | T1046 (Nmap Port Scan) |
| Lateral Movement | T1021 (RDP), T1570 (PsExec) |
| C2 | T1071 (C2 Outbound), T1071.004 (DNS Tunnel) |
| Exfiltration | T1048 (Data Transfer) |
| Impact | T1486 (Ransomware) |
| Cloud | T1098 (IAM Abuse), T1078.004 (Impossible Travel) |

---

## 🔧 Customization

Edit the config section in `generate_logs.py`:

```python
# Update with your actual VM IPs
internal_ips = [
    "192.168.66.105",  # Your Windows VM
    "192.168.66.101",  # Your Splunk VM
    ...
]

attacker_ip = "192.168.66.104"  # Your Kali VM

# Add your own hostnames
hosts = ["WIN-PRAHARSH-01", "SPLUNK-VM-01", ...]
```

---

## 📁 Project Structure

```
siem-log-generator/
├── 📜 generate_logs.py              # Main script — 3000+ events, 28 event types
├── 📜 convert_to_csv.py             # JSON to CSV converter
├── 📊 output/
│   ├── praharsh_siem_logs_3000.json
│   ├── praharsh_siem_logs_3000.csv
│   ├── praharsh_siem_logs_wazuh.json
│   └── praharsh_siem_logs_sentinel.json
├── 📖 README.md
├── 📖 USAGE.md
├── 📖 docs/
│   ├── SPLUNK_DASHBOARD_GUIDE.md
│   └── ENTERPRISE_SOC_DASHBOARDS.md
└── 📋 requirements.txt
```

---

## 📜 License

MIT License — free to use, share, and modify.

---

<p align="center">
  <b>Built for my Multi-SIEM SOC Lab 🛡️ | Splunk + Wazuh + ELK + Sentinel</b>
</p>
