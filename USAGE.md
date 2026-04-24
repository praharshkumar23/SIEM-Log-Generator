# 📖 Usage Guide — Praharsh Edition

## Quick Start

### 1. Generate All Logs

```bash
python generate_logs.py
```

Output:
```
✅ Generated 3000+ SIEM logs
📁 Files:
   output/praharsh_siem_logs_3000.json
   output/praharsh_siem_logs_3000.csv
   output/praharsh_siem_logs_wazuh.json
   output/praharsh_siem_logs_sentinel.json
```

### 2. Import to Splunk

```bash
# Option 1 — File Monitor
splunk add monitor /path/to/output/praharsh_siem_logs_3000.csv -sourcetype csv

# Option 2 — Upload via Splunk Web
Settings → Add Data → Upload → praharsh_siem_logs_3000.csv
```

### 3. Import to Wazuh

```bash
cp output/praharsh_siem_logs_wazuh.json /var/ossec/logs/alerts/praharsh_lab_alerts.json
```

### 4. Import to ELK

```bash
# Start Logstash with config
logstash -f logstash_praharsh.conf
```

Logstash config:
```yaml
input {
  file {
    path => "/path/to/praharsh_siem_logs_3000.json"
    codec => json
    start_position => "beginning"
  }
}
filter {
  date { match => ["timestamp", "ISO8601"] }
}
output {
  elasticsearch {
    hosts => ["192.168.56.103:9200"]
    index => "praharsh-soc-lab-%{+yyyy.MM.dd}"
  }
}
```

---

## Customization

### Change Event Counts

In `generate_logs.py`:

```python
# More brute force events (stress test Splunk alerts)
for _ in range(500):   # was 100
    logs.append({ "event_type": "Brute Force Attempt", ... })
```

### Add Your Own Lab IPs

```python
internal_ips = [
    "192.168.56.105",   # Your actual Windows VM IP
    "192.168.56.101",   # Your Splunk VM
    ...
]
attacker_ip = "192.168.56.104"   # Your Kali IP
```

### Generate Format-Specific Only

Uncomment only the output block you need in `generate_logs.py`.

---

## Severity Reference

| Level | Weight | Example Events |
|-------|--------|----------------|
| Info | 0 | Successful login, benign PowerShell |
| Low | 1 | USB connected, firewall block |
| Medium | 4 | Failed login, port scan |
| High | 7 | Brute force, malware detected |
| Critical | 10 | Reverse shell, Mimikatz, ransomware |

---

## KQL Queries (Microsoft Sentinel)

```kql
// Critical events from lab
praharsh_siem_logs_CL
| where Severity_s == "Critical"
| summarize count() by EventType_s, Computer_s
| sort by count_ desc

// Detect lab attack traffic from Kali
praharsh_siem_logs_CL
| where SourceIP_s == "192.168.56.104"
| project TimeGenerated, EventType_s, Computer_s, CommandLine_s, MitreTechnique_s
| sort by TimeGenerated desc
```

---

## Wazuh Rule Levels Reference

| Level | Meaning |
|-------|---------|
| 5 | Medium — Informational |
| 8 | High — Requires attention |
| 12 | Critical — Active threat |
| 15 | Maximum — Immediate response |
