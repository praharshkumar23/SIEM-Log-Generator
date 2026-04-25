# 📖 Usage Guide — Praharsh SIEM Log Generator

<p align="center">
  <b>Complete step-by-step guide to generate, import, and analyze logs</b><br>
  <i>Works with Splunk · Wazuh · Microsoft Sentinel · ELK Stack</i>
</p>

---

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start](#quick-start)
3. [Output Files Explained](#output-files-explained)
4. [Import to Splunk](#import-to-splunk)
5. [Import to Wazuh](#import-to-wazuh)
6. [Import to Microsoft Sentinel](#import-to-microsoft-sentinel)
7. [Import to ELK Stack](#import-to-elk-stack)
8. [Customization Guide](#customization-guide)
9. [Severity Reference](#severity-reference)
10. [KQL Queries — Microsoft Sentinel](#kql-queries--microsoft-sentinel)
11. [Wazuh Rule Levels Reference](#wazuh-rule-levels-reference)
12. [Troubleshooting](#troubleshooting)

---

## Prerequisites

Before you start, make sure you have:

- Python 3.8 or higher installed
- pip packages installed:

```bash
pip install -r requirements.txt
```

**requirements.txt includes:**
faker
uuid
json
csv
random
datetime

text

**Lab Environment (Recommended):**

| VM | Role | IP |
|----|------|----|
| Windows 10/11 | Victim Workstation | 192.168.56.145 |
| Windows Server 2019 | Domain Controller | 192.168.56.122 |
| Kali Linux | Attacker | 192.168.56.124 |
| Ubuntu (Splunk/ELK) | SIEM Server | 192.168.56.131 |
| Ubuntu (Wazuh) | SIEM Server | 192.168.56.123 |

---

## Quick Start

### Step 1 — Clone or Download

```bash
git clone https://github.com/praharshkumar23/siem-log-generator.git
cd siem-log-generator
```

### Step 2 — Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 3 — Generate All Logs

```bash
python generate_logs.py
```

**Expected Output:**
🚀 Starting Praharsh SIEM Log Generator...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ Generated 3000 SIEM log events

📁 Output Files:
output/praharsh_siem_logs_3000.json → Universal JSON
output/praharsh_siem_logs_3000.csv → Splunk / ELK
output/praharsh_siem_logs_wazuh.json → Wazuh format
output/praharsh_siem_logs_sentinel.json → Microsoft Sentinel

📊 Event Breakdown:
Critical : 312 events
High : 687 events
Medium : 1104 events
Low : 897 events

⏱️ Time taken: 2.3 seconds
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

text

---

## Output Files Explained

| File | Format | Best For | Size (approx) |
|------|--------|----------|---------------|
| `praharsh_siem_logs_3000.csv` | CSV | Splunk, Excel analysis | ~400 KB |
| `praharsh_siem_logs_3000.json` | JSON | ELK, custom scripts | ~720 KB |
| `praharsh_siem_logs_wazuh.json` | Wazuh JSON | Wazuh Manager | ~1.1 MB |
| `praharsh_siem_logs_sentinel.json` | Azure JSON | Microsoft Sentinel | ~940 KB |

### Log Fields Reference

Every log event contains these fields:

| Field | Description | Example |
|-------|-------------|---------|
| `timestamp` | ISO 8601 format | `2025-03-15T14:23:11` |
| `event_type` | Type of security event | `Brute Force Attempt` |
| `severity` | Criticality level | `Critical` |
| `host` | Source machine name | `WIN-WORKSTATION-01` |
| `user` | User involved | `administrator` |
| `source_ip` | Attacker/source IP | `192.168.56.104` |
| `destination_ip` | Target IP | `192.168.56.102` |
| `mitre_technique` | MITRE ATT&CK ID | `T1110.001` |
| `action_taken` | SIEM response | `Alert Triggered` |
| `log_source` | Log origin | `Sysmon`, `Windows Security` |
| `bytes_sent` | Data transferred | `204800` |
| `process` | Process name | `powershell.exe` |
| `command_line` | Full command | `powershell -enc ...` |

---

## Import to Splunk

### Option 1 — Upload via Splunk Web (Easiest)

1. Open Splunk Web → `http://localhost:8000`
2. Go to **Settings** → **Add Data** → **Upload**
3. Select `output/praharsh_siem_logs_3000.csv`
4. Set **Source Type** → `csv`
5. Set **Index** → Create new: `praharsh_soc_lab`
6. Click **Review** → **Submit**

### Option 2 — Splunk CLI (Faster)

```bash
splunk add oneshot /path/to/output/praharsh_siem_logs_3000.csv \
  -index praharsh_soc_lab \
  -sourcetype csv \
  -host WIN-LAB-01

splunk search "index=praharsh_soc_lab | stats count" -auth admin:password
```

### Option 3 — File Monitor (Continuous)

```bash
splunk add monitor /path/to/output/ \
  -index praharsh_soc_lab \
  -sourcetype csv
```

### Verify in Splunk

```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv"
| stats count by severity
| sort - count
```

---

## Import to Wazuh

### Method 1 — Direct File Copy

```bash
sudo cp output/praharsh_siem_logs_wazuh.json \
  /var/ossec/logs/alerts/praharsh_lab_alerts.json

sudo chown ossec:ossec /var/ossec/logs/alerts/praharsh_lab_alerts.json
sudo chmod 660 /var/ossec/logs/alerts/praharsh_lab_alerts.json
```

### Method 2 — Wazuh Agent Log Collector

Add to `/var/ossec/etc/ossec.conf`:

```xml
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/path/to/output/praharsh_siem_logs_wazuh.json</location>
  </localfile>
</ossec_config>
```

```bash
sudo systemctl restart wazuh-agent
```

### Method 3 — Wazuh API

```bash
curl -X POST "https://192.168.56.103:55000/events" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @output/praharsh_siem_logs_wazuh.json
```

### Verify in Wazuh Dashboard

1. Open Wazuh Dashboard → `https://192.168.56.143`
2. Go to **Security Events** → Filter by `agent.name: praharsh-lab`
3. You should see alerts with levels 5, 8, 12, 15

---

## Import to Microsoft Sentinel

### Method 1 — Custom Logs via Log Analytics Workspace

1. Go to **Azure Portal** → **Log Analytics Workspace**
2. Select workspace → **Custom Logs** → **Add custom log**
3. Upload `output/praharsh_siem_logs_sentinel.json` as sample
4. Set **Custom log name**: `praharsh_siem_logs`
5. Click **Create**

### Method 2 — Data Collector API (Python)

```python
import requests, json, hashlib, hmac, base64, datetime

workspace_id = "YOUR_WORKSPACE_ID"
primary_key  = "YOUR_PRIMARY_KEY"
log_type     = "praharsh_siem_logs"

with open("output/praharsh_siem_logs_sentinel.json") as f:
    body = f.read()

rfc1123date    = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
string_to_hash = f"POST\n{len(body)}\napplication/json\nx-ms-date:{rfc1123date}\n/api/logs"
decoded_key    = base64.b64decode(primary_key)
encoded_hash   = base64.b64encode(
    hmac.new(decoded_key, string_to_hash.encode("utf-8"), digestmod=hashlib.sha256).digest()
).decode("utf-8")

headers = {
    "content-type":  "application/json",
    "Authorization": f"SharedKey {workspace_id}:{encoded_hash}",
    "Log-Type":      log_type,
    "x-ms-date":     rfc1123date
}

uri      = f"https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
response = requests.post(uri, data=body, headers=headers)
print(f"Status: {response.status_code}")
```

### Verify in Sentinel

```kql
praharsh_siem_logs_CL
| take 10
| project TimeGenerated, EventType_s, Severity_s, Computer_s
```

---

## Import to ELK Stack

### Logstash Config — `logstash_praharsh.conf`

```ruby
input {
  file {
    path           => "/path/to/output/praharsh_siem_logs_3000.json"
    codec          => json
    start_position => "beginning"
    sincedb_path   => "/dev/null"
    tags           => ["praharsh_soc_lab"]
  }
}

filter {
  date {
    match  => ["timestamp", "ISO8601"]
    target => "@timestamp"
  }
  mutate {
    rename => {
      "event_type"      => "event.type"
      "severity"        => "event.severity"
      "source_ip"       => "source.ip"
      "destination_ip"  => "destination.ip"
      "mitre_technique" => "threat.technique.id"
      "host"            => "host.name"
      "user"            => "user.name"
    }
  }
  if [event.severity] == "Critical" {
    mutate { add_tag => ["high_priority"] }
  }
}

output {
  elasticsearch {
    hosts    => ["http://192.168.56.123:9200"]
    index    => "praharsh-soc-lab-%{+yyyy.MM.dd}"
    user     => "elastic"
    password => "your_password"
  }
  stdout { codec => rubydebug }
}
```

```bash
# Validate
logstash --config.test_and_exit -f logstash_praharsh.conf

# Run
logstash -f logstash_praharsh.conf
```

### Kibana Index Pattern

1. Kibana → **Stack Management** → **Index Patterns**
2. Create: `praharsh-soc-lab-*`
3. Time field: `@timestamp`

### Verify via API

```bash
curl -u elastic:password http://192.168.26.143:9200/_cat/indices/praharsh*
```

---

## Customization Guide

### Change Event Counts

```python
# In generate_logs.py
BRUTE_FORCE_COUNT  = 500   # default: 100
MALWARE_COUNT      = 200   # default: 80
RANSOMWARE_COUNT   = 50    # default: 20
LATERAL_MOVE_COUNT = 150   # default: 60
```

### Change Lab IP Addresses

```python
LAB_CONFIG = {
    "windows_workstation" : "192.168.56.115",
    "domain_controller"   : "192.168.56.112",
    "splunk_server"       : "192.168.56.101",
    "elk_server"          : "192.168.66.103",
    "kali_attacker"       : "192.168.66.104",
}
```

### Add Custom Event Type

```python
def generate_custom_event():
    return {
        "timestamp"       : generate_timestamp(),
        "event_type"      : "My Custom Alert",
        "severity"        : "High",
        "host"            : random.choice(windows_hosts),
        "user"            : random.choice(users),
        "source_ip"       : kali_ip,
        "mitre_technique" : "T1059.001",
        "action_taken"    : "Alert Triggered",
        "log_source"      : "Custom",
        "description"     : "Custom event for lab testing"
    }
```

### Generate Only One Format

```python
save_csv(logs)        # Splunk
# save_json(logs)     # Generic JSON   — comment out if not needed
# save_wazuh(logs)    # Wazuh          — comment out if not needed
# save_sentinel(logs) # Sentinel       — comment out if not needed
```

---

## Severity Reference

| Level | Weight | Color | Example Events | Response Time |
|-------|--------|-------|----------------|---------------|
| Info | 0 | ⚪ | System startup, DNS query | Log only |
| Low | 1 | 🟢 | USB connected, firewall block | 72 hours |
| Medium | 4 | 🟡 | Failed login x3, port scan | 24 hours |
| High | 7 | 🟠 | Brute force, malware detected | 4 hours |
| Critical | 10 | 🔴 | Reverse shell, Mimikatz, ransomware | Immediate |

---

## KQL Queries — Microsoft Sentinel

```kql
// All critical events
praharsh_siem_logs_CL
| where Severity_s == "Critical"
| summarize count() by EventType_s, Computer_s
| sort by count_ desc

// Brute force — 5+ failures from same IP in 5 min
praharsh_siem_logs_CL
| where EventType_s has "Failed Login" or EventType_s has "Brute Force"
| summarize FailureCount = count() by SourceIP_s, User_s, bin(TimeGenerated, 5m)
| where FailureCount > 5

// Kali attacker traffic
praharsh_siem_logs_CL
| where SourceIP_s == "192.168.56.104"
| project TimeGenerated, EventType_s, Computer_s, CommandLine_s, MitreTechnique_s
| sort by TimeGenerated desc

// Lateral movement — same user on 2+ hosts
praharsh_siem_logs_CL
| where EventType_s has "Lateral Movement" or EventType_s has "PsExec"
| summarize HopsCount = dcount(Computer_s), Hosts = make_set(Computer_s) by User_s
| where HopsCount > 2

// MITRE technique frequency
praharsh_siem_logs_CL
| where isnotempty(MitreTechnique_s)
| summarize count() by MitreTechnique_s
| sort by count_ desc
| take 15

// Large data exfiltration
praharsh_siem_logs_CL
| where isnotempty(BytesSent_d)
| summarize TotalMB = sum(BytesSent_d) / 1024 / 1024 by Computer_s, DestinationIP_s
| where TotalMB > 50
| sort by TotalMB desc
```

---

## Wazuh Rule Levels Reference

| Level | Name | Meaning | Response Time | Lab Events |
|-------|------|---------|---------------|------------|
| 0 | Ignored | Noise — not logged | Never | Debug messages |
| 1–3 | Low | Informational, no threat | 72 hours | Successful logon, DNS queries |
| 4–5 | Medium-Low | Unusual but benign | 48 hours | New device, USB, user added to group |
| 6–7 | Medium | Possible threat indicator | 24 hours | Failed login x3, suspicious process |
| 8–9 | High | Active threat indicator | 4 hours | Brute force, port scan, privilege escalation |
| 10–11 | Very High | Likely compromise | 2 hours | Malware detected, lateral movement via SMB |
| 12–13 | Critical | Active attack confirmed | 30 minutes | Reverse shell, Mimikatz, C2 beacon |
| 14 | Maximum | Immediate P1 incident | Immediate | Ransomware started, domain admin compromise |
| 15 | Maximum + Regulatory | Breach + active attack | Immediate | PII/PCI data exfiltration, GDPR violation |

### Example Wazuh JSON by Level

```json
{ "rule": { "level": 5,  "description": "Successful login from known IP" } }
{ "rule": { "level": 8,  "description": "Brute force — multiple failed SSH attempts" } }
{ "rule": { "level": 12, "description": "Mimikatz credential dump detected" } }
{ "rule": { "level": 15, "description": "Ransomware file encryption — mass rename event" } }
```

### Filter by Level via API

```bash
# Level 12+ alerts
curl -u admin:admin "https://192.168.26.103:55000/alerts?level=12&pretty=true"

# Level 8+ last 50
curl -u admin:admin "https://192.168.26.103:55000/alerts?level=8&limit=50&pretty=true"
```

---

## Troubleshooting

**`ModuleNotFoundError: No module named 'faker'`**
```bash
pip install -r requirements.txt
```

**Splunk shows no results**
```spl
| eventcount summarize=false index=* | table index
```
Make sure `praharsh_soc_lab` is listed.

**Wazuh logs not appearing**
```bash
sudo chown ossec:ossec /var/ossec/logs/alerts/praharsh_lab_alerts.json
sudo chmod 660 /var/ossec/logs/alerts/praharsh_lab_alerts.json
sudo systemctl restart wazuh-manager
```

**Logstash — Connection refused**
```bash
curl http://192.168.26.103:9200/_cluster/health
logstash --config.test_and_exit -f logstash_praharsh.conf
```

**Wrong field names in Splunk**
```spl
index="praharsh_soc_lab"
| rename event_type AS EventType, source_ip AS SourceIP, mitre_technique AS MitreTechnique
| table EventType, Severity, SourceIP, MitreTechnique
```

---

<p align="center">
  <b>📖 Praharsh SIEM Log Generator — Usage Guide</b><br>
  <i>For issues → open a GitHub Issue</i>
</p>
