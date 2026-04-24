# 🛡️ SOC Security Operations Dashboard — Splunk Build Guide
### Praharsh's Multi-SIEM Lab Edition

---

## Prerequisites

- Splunk Enterprise or Splunk Free (up to 500MB/day)
- Generated file: `output/praharsh_siem_logs_3000.csv`
- Basic SPL knowledge

---

## Step 1: Import Data

### 1.1 Upload CSV

1. Open Splunk Web → **Settings** → **Add Data**
2. Select **Upload** → Choose `praharsh_siem_logs_3000.csv`
3. Configure:
   ```
   Source Type: csv
   Host: WIN-PRAHARSH-01
   Index: praharsh_soc_lab
   ```
4. Click **Review** → **Submit**

### 1.2 Verify

```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv"
| head 10
```

---

## Step 2: Create Dashboard

1. Dashboards → **Create New Dashboard**
2. Title: `SOC Security Operations — Praharsh Lab`
3. ID: `praharsh_soc_dashboard`
4. Select **Classic Dashboards** → **Edit**

---

## Step 3: Dashboard Panels

### Base Search (use for all panels)
```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
```

---

### Panel 1: Total Event Count
**Type:** Single Value

```spl
index="praharsh_soc_lab" sourcetype="csv"
| stats count as "Total Events"
```

Config: Color = Green (`#00FF41`), Font = Large

---

### Panel 2: Security Events Over Time
**Type:** Area Chart (Stacked)

```spl
index="praharsh_soc_lab" sourcetype="csv"
| eval _time = strptime(timestamp, "%Y-%m-%dT%H:%M:%S")
| timechart span=1h count by severity
```

Colors: Critical=Red, High=Orange, Medium=Yellow, Low=Blue, Info=Green

---

### Panel 3: MITRE ATT&CK Technique Distribution
**Type:** Pie Chart

```spl
index="praharsh_soc_lab" sourcetype="csv"
| where isnotnull(mitre_technique) AND mitre_technique!=""
| stats count as "Events" by mitre_technique
| sort - Events
| head 12
| rename mitre_technique as "Technique"
```

---

### Panel 4: User Risk Scores
**Type:** Horizontal Bar Chart

```spl
index="praharsh_soc_lab" sourcetype="csv"
| where isnotnull(user) AND user!=""
| eval risk_weight = case(
    severity="Critical", 10,
    severity="High", 7,
    severity="Medium", 4,
    severity="Low", 1,
    1=1, 0
)
| stats sum(risk_weight) as risk_score,
        count as total_events,
        dc(event_type) as unique_attack_types
        by user
| eval risk_level = case(
    risk_score >= 500, "Critical",
    risk_score >= 300, "High",
    risk_score >= 100, "Medium",
    1=1, "Low"
)
| sort - risk_score
| head 10
```

---

### Panel 5: Failed Login Trends
**Type:** Line Chart (Multi-Series)

```spl
index="praharsh_soc_lab" sourcetype="csv"
| where event_type IN ("Failed Login", "Brute Force Attempt", "RDP Brute Force", "SSH Brute Force", "Password Spray")
| eval _time = strptime(timestamp, "%Y-%m-%dT%H:%M:%S")
| timechart span=4h count by event_type
```

---

### Panel 6: Lab Attack Activity (Kali → Windows)
**Type:** Horizontal Bar Chart — UNIQUE TO YOUR LAB

```spl
index="praharsh_soc_lab" sourcetype="csv"
| where source_ip="192.168.56.104" OR attacker_host="KALI-LAB-01"
| stats count as "Attack Events" by event_type
| sort - "Attack Events"
| head 10
| rename event_type as "Attack Technique"
```

---

### Panel 7: C2 Communication Hotspots
**Type:** Bar Chart

```spl
index="praharsh_soc_lab" sourcetype="csv"
| where event_type="C2 Outbound Connection" OR event_type="DNS Tunneling Detected"
| stats sum(bytes_sent) as total_bytes,
        count as connections
        by destination_ip
| eval total_mb = round(total_bytes/1024/1024, 2)
| sort - total_bytes
| head 10
| table destination_ip, total_mb, connections
```

---

### Panel 8: Security Posture Score
**Type:** Radial Gauge

```spl
index="praharsh_soc_lab" sourcetype="csv"
| stats count(eval(severity="Critical")) as critical,
        count(eval(severity="High")) as high,
        count(eval(severity="Medium")) as medium,
        count as total
| eval risk_deduction = (critical * 5) + (high * 3) + (medium * 1)
| eval max_deduction = total * 5
| eval posture_score = round(100 - (risk_deduction / max_deduction * 100), 0)
| eval posture_score = if(posture_score < 0, 0, posture_score)
| table posture_score
```

Gauge Ranges: 0-40=Red, 40-70=Orange, 70-100=Green

---

### Panel 9: Recent Malware Detections
**Type:** Statistics Table

```spl
index="praharsh_soc_lab" sourcetype="csv"
| where event_type="Malware Detected"
| eval detection_time = strftime(strptime(timestamp, "%Y-%m-%dT%H:%M:%S"), "%Y-%m-%d %H:%M:%S")
| table detection_time, host, malware_name, file_path, action_taken, severity
| sort - detection_time
| head 15
```

Row Colors: Critical=Red, High=Orange

---

### Panel 10: Sysmon Event Distribution (NEW — Your Lab)
**Type:** Column Chart

```spl
index="praharsh_soc_lab" sourcetype="csv"
| where log_source="Sysmon"
| stats count by event_code, event_type
| eval sysmon_label = "Event ID " . event_code . " — " . event_type
| sort - count
| table sysmon_label, count
```

---

### Panel 11: Most Targeted Hosts
**Type:** Column Chart

```spl
index="praharsh_soc_lab" sourcetype="csv"
| where severity IN ("High", "Critical")
| stats count as attack_count,
        dc(event_type) as unique_attacks
        by host
| sort - attack_count
| head 10
```

---

## Step 4: Dark Theme

Add to dashboard XML:

```xml
<dashboard theme="dark" version="1.1">
  <label>SOC Security Operations — Praharsh Lab</label>
```

Custom CSS (`$SPLUNK_HOME/etc/apps/search/appserver/static/praharsh_soc.css`):

```css
.dashboard-body { background-color: #0d1117 !important; }
.dashboard-panel { background-color: #161b22 !important; border: 1px solid #30363d !important; border-radius: 8px; }
.panel-title { color: #00ff88 !important; font-weight: bold; }
.single-value .single-result { color: #00ff41 !important; text-shadow: 0 0 10px #00ff41; }
```

---

## 💡 Interview Tips — When You Present This

1. **Point to Panel 6 (Lab Attack Activity)** — "This shows real attacks I ran from Kali against my Windows VM"
2. **Point to MITRE Panel** — "Each technique maps directly to ATT&CK — T1110 is brute force, T1003 is credential dumping with Mimikatz"
3. **Point to Sysmon Panel** — "I deployed Sysmon with a custom config to capture Event IDs 1, 3, 7, 8 for process creation and network connections"
4. **Point to Risk Score Panel** — "I built a weighted scoring model — Critical events score 10, High = 7, Medium = 4"

---

## 🔗 References

- [Splunk SPL Docs](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
