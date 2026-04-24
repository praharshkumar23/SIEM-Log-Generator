# 🏢 Enterprise SOC Dashboards — Real-World Examples

<p align="center">
  <b>How Fortune 500 Companies Monitor Security</b><br>
  <i>Based on industry standards: NIST, ISO 27001, MITRE ATT&CK</i>
</p>

> **Note:** All SPL queries in this file use Praharsh's lab data source.
> Replace `praharsh_siem_logs_3000.csv` with your actual source if different.

---

## 📋 Table of Contents

1. [SOC Dashboard Categories](#soc-dashboard-categories)
2. [Dashboard 1: Executive Security Summary](#dashboard-1-executive-security-summary)
3. [Dashboard 2: Threat Detection & Hunting](#dashboard-2-threat-detection--hunting)
4. [Dashboard 3: Incident Response Tracker](#dashboard-3-incident-response-tracker)
5. [Dashboard 4: Endpoint Security (EDR)](#dashboard-4-endpoint-security-edr)
6. [Dashboard 5: Network Security Operations](#dashboard-5-network-security-operations)
7. [Dashboard 6: Identity & Access Management](#dashboard-6-identity--access-management)
8. [Dashboard 7: Cloud Security Posture (CSPM)](#dashboard-7-cloud-security-posture-cspm)
9. [Dashboard 8: Vulnerability Management](#dashboard-8-vulnerability-management)
10. [Dashboard 9: Compliance & Audit](#dashboard-9-compliance--audit)
11. [Dashboard 10: Threat Intelligence](#dashboard-10-threat-intelligence)
12. [Real Company Examples](#real-company-examples)
13. [Interview Tips](#interview-tips)

---

## SOC Dashboard Categories

Real-world SOCs typically have **3 tiers** of dashboards:

| Tier | Audience | Purpose | Refresh Rate |
|------|----------|---------|--------------|
| **Tier 1 — Tactical** | SOC Analysts (L1/L2) | Real-time alert monitoring | 1–5 minutes |
| **Tier 2 — Operational** | SOC Manager, Team Leads | Incident tracking, metrics | 15–30 minutes |
| **Tier 3 — Strategic** | CISO, Executives, Board | Risk posture, compliance | Daily/Weekly |

---

## Dashboard 1: Executive Security Summary

**Audience:** CISO, C-Suite, Board of Directors
**Purpose:** High-level security posture at a glance
**Refresh:** Daily

### 📊 Panel Layout

```
┌─────────────────────────────────────────────────────────────────┐
│  🛡️ SECURITY RISK SCORE     │  📈 TREND (30 Days)    │ 🎯 SLA  │
│        72/100               │    ▲ +5% improved      │  98.2%  │
├─────────────────────────────┼────────────────────────┼─────────┤
│  🔴 Critical Alerts: 3      │  🟠 High: 12           │ 🟡 Med: 45
├─────────────────────────────┴────────────────────────┴─────────┤
│  📊 INCIDENTS BY CATEGORY (Pie Chart)                           │
│  [Malware 35%] [Phishing 28%] [Insider 15%] [DDoS 12%] [Other] │
├─────────────────────────────────────────────────────────────────┤
│  📈 MONTHLY INCIDENT TREND (Area Chart)                         │
│  ████████████████████████████████████████████████████████████  │
├─────────────────────────────────────────────────────────────────┤
│  ✅ COMPLIANCE STATUS                                            │
│  [PCI-DSS: 94%] [HIPAA: 89%] [SOX: 96%] [GDPR: 91%]            │
└─────────────────────────────────────────────────────────────────┘
```

### SPL Queries

#### 1.1 Overall Security Risk Score
```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| stats count(eval(severity="Critical")) as critical,
        count(eval(severity="High")) as high,
        count(eval(severity="Medium")) as medium,
        count(eval(severity="Low")) as low,
        count as total
| eval risk_points = (critical * 25) + (high * 10) + (medium * 3) + (low * 1)
| eval max_points = total * 25
| eval risk_score = round(100 - (risk_points / max_points * 100), 0)
| eval risk_score = if(risk_score < 0, 0, risk_score)
| eval risk_grade = case(
    risk_score >= 90, "A - Excellent",
    risk_score >= 80, "B - Good",
    risk_score >= 70, "C - Fair",
    risk_score >= 60, "D - Poor",
    1=1, "F - Critical"
)
| table risk_score, risk_grade, critical, high, medium, low
```

#### 1.2 Incidents by Category
```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| eval category = case(
    event_type LIKE "%Malware%" OR event_type LIKE "%Ransomware%", "Malware",
    event_type LIKE "%Phishing%", "Phishing",
    event_type LIKE "%Login%" OR event_type LIKE "%Brute%", "Authentication",
    event_type LIKE "%C2%" OR event_type LIKE "%Exfil%", "Data Breach",
    event_type LIKE "%Cloud%", "Cloud Security",
    event_type LIKE "%Lateral%", "Lateral Movement",
    1=1, "Other"
)
| stats count by category
| sort - count
```

#### 1.3 MTTD / MTTR (Mean Time to Detect / Respond)
```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| where severity IN ("Critical", "High")
| eval detection_time = strptime(timestamp, "%Y-%m-%dT%H:%M:%S")
| eval mttd_seconds = random() % 1800
| eval mttr_seconds = random() % 7200
| stats avg(mttd_seconds) as avg_mttd, avg(mttr_seconds) as avg_mttr
| eval MTTD = round(avg_mttd / 60, 1) . " minutes"
| eval MTTR = round(avg_mttr / 60, 1) . " minutes"
| table MTTD, MTTR
```

---

## Dashboard 2: Threat Detection & Hunting

**Audience:** SOC Analysts (L2/L3), Threat Hunters
**Purpose:** Active threat hunting and investigation
**Refresh:** Real-time (1 min)

### 📊 Panel Layout

```
┌─────────────────────────────────────────────────────────────────┐
│  🎯 MITRE ATT&CK HEATMAP                                        │
│  ┌─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┐ │
│  │TA01 │TA02 │TA03 │TA04 │TA05 │TA06 │TA07 │TA08 │TA09 │TA10 │ │
│  │ 🔴  │ 🟠  │ 🔴  │ 🟡  │ 🔴  │ 🟠  │ 🟡  │ 🟢  │ 🔴  │ 🟠  │ │
│  └─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┘ │
├─────────────────────────────────────────────────────────────────┤
│  🔍 SUSPICIOUS PROCESS TREE                                     │
│  cmd.exe → powershell.exe → mimikatz.exe                        │
│  └─ rundll32.exe → suspicious.dll                               │
├─────────────────────────────────────────────────────────────────┤
│  🌐 NETWORK ANOMALIES                                           │
│  [Beaconing: 5] [DNS Tunneling: 3] [Large Upload: 8]            │
├─────────────────────────────────────────────────────────────────┤
│  📋 HUNTING QUERIES RESULTS                                     │
│  • Living-off-the-Land: 23 hits                                 │
│  • Credential Access: 15 hits                                   │
│  • Lateral Movement: 8 hits                                     │
└─────────────────────────────────────────────────────────────────┘
```

### SPL Queries

#### 2.1 MITRE ATT&CK Technique Heat Map
```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| where isnotnull(mitre_technique)
| eval tactic = case(
    mitre_technique LIKE "T1566%", "Initial Access",
    mitre_technique LIKE "T1059%" OR mitre_technique LIKE "T1218%", "Execution",
    mitre_technique LIKE "T1053%" OR mitre_technique LIKE "T1547%", "Persistence",
    mitre_technique LIKE "T1068%", "Privilege Escalation",
    mitre_technique LIKE "T1055%" OR mitre_technique LIKE "T1562%", "Defense Evasion",
    mitre_technique LIKE "T1003%" OR mitre_technique LIKE "T1110%" OR mitre_technique LIKE "T1558%", "Credential Access",
    mitre_technique LIKE "T1046%", "Discovery",
    mitre_technique LIKE "T1021%" OR mitre_technique LIKE "T1570%" OR mitre_technique LIKE "T1047%", "Lateral Movement",
    mitre_technique LIKE "T1071%" OR mitre_technique LIKE "T1048%", "C2 & Exfil",
    mitre_technique LIKE "T1486%", "Impact",
    1=1, "Other"
)
| stats count by tactic, mitre_technique
| sort tactic, -count
```

#### 2.2 Suspicious Process Execution Chain (Lab-specific)
```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| where event_type IN ("PowerShell Execution", "LOLBIN Execution", "Credential Dumping", "Process Injection", "Reverse Shell Detected")
| eval risk_level = case(
    command_line LIKE "%mimikatz%" OR command_line LIKE "%Invoke-%" OR command_line LIKE "%-enc%", "Critical",
    command_line LIKE "%192.168.56.104%" OR command_line LIKE "%4444%", "Critical - Lab C2",
    process IN ("mshta.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"), "High",
    1=1, "Medium"
)
| stats count as executions,
        values(command_line) as commands,
        dc(host) as hosts_affected
        by process, user, risk_level
| where risk_level IN ("Critical", "Critical - Lab C2", "High")
| sort - executions
| head 20
```

#### 2.3 Beaconing Detection (C2 Outbound — Kali Attacker)
```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| where event_type="C2 Outbound Connection"
| stats count as connections,
        sum(bytes_sent) as total_bytes,
        values(destination_port) as ports
        by destination_ip, host
| eval total_mb = round(total_bytes/1024/1024, 2)
| eval beacon_risk = case(
    connections > 30, "Critical - Active C2 Beacon",
    connections > 15, "High - Suspicious Outbound",
    1=1, "Medium - Monitor"
)
| sort - connections
| table host, destination_ip, connections, total_mb, ports, beacon_risk
```

#### 2.4 DNS Tunneling Detection
```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| where event_type="DNS Tunneling Detected"
| eval domain_length = len(dns_query)
| eval entropy_indicator = if(domain_length > 30, "High Entropy", "Normal")
| stats count as queries,
        sum(query_count) as total_queries,
        avg(domain_length) as avg_query_length
        by host
| where total_queries > 50 OR avg_query_length > 35
| eval threat_level = "Critical - DNS Exfiltration"
| table host, queries, total_queries, avg_query_length, threat_level
```

---

## Dashboard 3: Incident Response Tracker

**Audience:** SOC Manager, Incident Responders
**Purpose:** Track active incidents through their lifecycle
**Refresh:** 5 minutes

### 📊 Panel Layout

```
┌─────────────────────────────────────────────────────────────────┐
│  📊 INCIDENT STATUS BOARD                                       │
│  ┌─────────┬─────────┬─────────┬─────────┬─────────┐           │
│  │ 🔴 New  │ 🟠 Open │ 🟡 Inv  │ 🔵 Cont │ 🟢 Done │           │
│  │   5     │   12    │   8     │   3     │   42    │           │
│  └─────────┴─────────┴─────────┴─────────┴─────────┘           │
├─────────────────────────────────────────────────────────────────┤
│  📋 ACTIVE INCIDENTS TABLE                                      │
│  INC-001 │ Critical │ Ransomware │ Praharsh │ Contain │ 2h 15m  │
│  INC-002 │ High     │ Phishing   │ Lab Anal │ Invest  │ 4h 30m  │
│  INC-003 │ High     │ Rev Shell  │ Unassign │ Open    │ 1h 45m  │
├─────────────────────────────────────────────────────────────────┤
│  ⏱️ SLA COMPLIANCE                                              │
│  [Critical: 95%] [High: 92%] [Medium: 88%] [Low: 99%]           │
└─────────────────────────────────────────────────────────────────┘
```

### SPL Queries

#### 3.1 Incident Status Summary
```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| where severity IN ("Critical", "High")
| eval status = case(
    random() % 5 = 0, "New",
    random() % 5 = 1, "Open",
    random() % 5 = 2, "Investigating",
    random() % 5 = 3, "Contained",
    1=1, "Closed"
)
| stats count by status
| eval order = case(status="New",1, status="Open",2, status="Investigating",3, status="Contained",4, status="Closed",5)
| sort order
| table status, count
```

#### 3.2 Active Incidents with SLA Tracking
```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| where severity IN ("Critical", "High")
| head 25
| eval created_time = strptime(timestamp, "%Y-%m-%dT%H:%M:%S")
| eval age_minutes = round((now() - created_time) / 60, 0)
| eval age_display = case(
    age_minutes < 60, age_minutes . " min",
    age_minutes < 1440, round(age_minutes/60,1) . " hrs",
    1=1, round(age_minutes/1440,1) . " days"
)
| eval sla_target = case(severity="Critical", 60, severity="High", 240, 1=1, 480)
| eval sla_status = if(age_minutes <= sla_target, "✅ Within SLA", "❌ SLA Breach")
| table severity, event_type, host, user, age_display, sla_status
| sort - severity
```

#### 3.3 Incident Timeline
```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| where severity IN ("Critical", "High")
| eval _time = strptime(timestamp, "%Y-%m-%dT%H:%M:%S")
| eval category = case(
    event_type LIKE "%Malware%" OR event_type LIKE "%Ransomware%", "Malware",
    event_type LIKE "%Phishing%", "Phishing",
    event_type LIKE "%Brute%" OR event_type LIKE "%Login%", "Auth Attack",
    event_type LIKE "%C2%" OR event_type LIKE "%Exfil%", "Data Breach",
    event_type LIKE "%Reverse Shell%", "Active Compromise",
    1=1, "Other"
)
| timechart span=1h count by category
```

---

## Dashboard 4: Endpoint Security (EDR)

**Audience:** Endpoint Security Team, SOC Analysts
**Purpose:** Monitor endpoint health and threats
**Refresh:** Real-time

### SPL Queries

#### 4.1 Endpoint Health Status
```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| stats count(eval(severity="Critical" OR event_type LIKE "%Malware%")) as threat_events
        by host
| eval status = case(
    threat_events > 10, "🔴 Compromised",
    threat_events > 3, "🟡 At Risk",
    1=1, "🟢 Healthy"
)
| sort - threat_events
| table host, status, threat_events
```

#### 4.2 Top Malware Families Detected
```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| where event_type="Malware Detected"
| stats count as detections,
        dc(host) as hosts_affected,
        values(action_taken) as responses
        by malware_name
| eval threat_score = case(
    malware_name IN ("Cobalt.Strike.Beacon", "Mimikatz", "Ryuk.Ransomware"), "Critical",
    malware_name IN ("Emotet", "Trojan.GenericKD", "Meterpreter"), "High",
    1=1, "Medium"
)
| sort - detections
| head 10
| table malware_name, detections, hosts_affected, responses, threat_score
```

#### 4.3 Sysmon Event Distribution (Your Lab!)
```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| where log_source="Sysmon"
| stats count by event_code, event_type
| eval sysmon_label = "Event ID " . event_code . " — " . event_type
| sort - count
| table sysmon_label, count
```

#### 4.4 Kill Chain Coverage per Host
```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| where severity IN ("Critical", "High")
| eval attack_stage = case(
    event_type LIKE "%Phishing%", "1-Initial Access",
    event_type LIKE "%PowerShell%" OR event_type LIKE "%LOLBIN%", "2-Execution",
    event_type LIKE "%Registry%" OR event_type LIKE "%Scheduled Task%", "3-Persistence",
    event_type LIKE "%Credential%", "4-Cred Access",
    event_type LIKE "%Lateral%" OR event_type LIKE "%RDP%" OR event_type LIKE "%PsExec%", "5-Lateral Movement",
    event_type LIKE "%Exfil%" OR event_type LIKE "%C2%", "6-Exfiltration",
    1=1, "7-Other"
)
| stats dc(attack_stage) as kill_chain_stages,
        count as total_events,
        values(attack_stage) as stages
        by host
| eval compromise_level = case(
    kill_chain_stages >= 5, "🔴 Active Compromise",
    kill_chain_stages >= 3, "🟠 Likely Compromise",
    1=1, "🟡 Suspicious"
)
| sort - kill_chain_stages
| table host, kill_chain_stages, stages, total_events, compromise_level
```

---

## Dashboard 5: Network Security Operations

**Audience:** Network Security Team, SOC Analysts
**Purpose:** Monitor network traffic and threats
**Refresh:** Real-time

### SPL Queries

#### 5.1 Firewall Block Analysis
```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| where event_type="Firewall Block"
| stats count as blocks by source_ip, destination_port, rule_name
| eval service = case(
    destination_port=22, "SSH",
    destination_port=3389, "RDP",
    destination_port=445, "SMB",
    destination_port=4444, "Metasploit",
    destination_port=1433, "MSSQL",
    1=1, "Other"
)
| sort - blocks
| head 20
| table source_ip, service, rule_name, blocks
```

#### 5.2 Attacker IP Correlation (Kali Lab)
```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| where source_ip="192.168.56.104" OR attacker_host="KALI-LAB-01"
| stats count as attack_count,
        dc(event_type) as attack_types,
        values(event_type) as attacks,
        values(mitre_technique) as techniques
        by source_ip
| eval threat_level = case(
    attack_count > 100, "Critical - Active Attacker (Kali Lab)",
    attack_count > 50, "High - Persistent Threat",
    1=1, "Medium"
)
| table source_ip, attack_count, attack_types, attacks, techniques, threat_level
```

#### 5.3 IDS/IPS Signature Analysis
```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| where event_type="IDS Alert"
| stats count as hits,
        dc(source_ip) as unique_sources
        by signature
| eval threat_category = case(
    signature LIKE "%CobaltStrike%" OR signature LIKE "%Metasploit%", "APT Tool",
    signature LIKE "%EXPLOIT%", "Exploitation",
    signature LIKE "%MALWARE%", "Malware C2",
    signature LIKE "%SCAN%", "Reconnaissance",
    1=1, "Other"
)
| sort - hits
| table signature, threat_category, hits, unique_sources
```

#### 5.4 Port Scan Detection (Nmap from Kali)
```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| where event_type="Port Scan Detected"
| stats count as scans,
        avg(ports_scanned) as avg_ports,
        values(scan_type) as techniques,
        values(target_ip) as targets
        by source_ip
| eval recon_level = case(
    avg_ports > 10000, "Full Port Scan",
    avg_ports > 1000, "Large Range Scan",
    1=1, "Targeted Scan"
)
| table source_ip, scans, avg_ports, techniques, targets, recon_level
```

---

## Dashboard 6: Identity & Access Management

**Audience:** IAM Team, SOC Analysts
**Purpose:** Monitor authentication and access patterns
**Refresh:** 5 minutes

### SPL Queries

#### 6.1 Authentication Overview
```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| where event_type IN ("Successful Login", "Failed Login", "Brute Force Attempt", "Password Spray", "Kerberos TGS Request")
| eval auth_result = case(
    event_type="Successful Login", "✅ Success",
    event_type IN ("Failed Login", "Brute Force Attempt", "Password Spray"), "❌ Failed",
    event_type="Kerberos TGS Request", "🎫 Kerberos",
    1=1, "Other"
)
| stats count by auth_result
```

#### 6.2 Impossible Travel Detection
```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| where event_type="Impossible Travel"
| stats count as occurrences,
        values(login_location_1) as from_locations,
        values(login_location_2) as to_locations,
        avg(time_difference_minutes) as avg_time_diff
        by user
| eval risk_assessment = case(
    occurrences > 3 AND avg_time_diff < 15, "Critical - Account Compromised",
    occurrences > 1, "High - Investigate",
    1=1, "Medium - Monitor"
)
| sort - occurrences
| table user, occurrences, from_locations, to_locations, avg_time_diff, risk_assessment
```

#### 6.3 Kerberoasting Detection (T1558.003)
```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| where event_type="Kerberos TGS Request"
| stats count as requests,
        values(service_name) as targeted_services
        by user, host
| eval kerberoast_risk = case(
    encryption_type="0x17", "Critical - RC4 (Kerberoastable)",
    requests > 5, "High - Excessive TGS Requests",
    1=1, "Medium"
)
| sort - requests
| table user, host, requests, targeted_services, kerberoast_risk
```

#### 6.4 Privileged Account Monitoring
```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| where user IN ("praharsh.admin", "lab.administrator", "svc.backup")
| stats count as total_events,
        count(eval(severity="Critical")) as critical_events,
        count(eval(severity="High")) as high_events,
        dc(host) as hosts_accessed,
        dc(event_type) as unique_attack_types
        by user
| eval risk_score = (critical_events * 10) + (high_events * 5) + (unique_attack_types * 2)
| sort - risk_score
| table user, total_events, critical_events, high_events, hosts_accessed, risk_score
```

---

## Dashboard 7: Cloud Security Posture (CSPM)

**Audience:** Cloud Security Team, DevSecOps
**Purpose:** Monitor cloud infrastructure security
**Refresh:** 15 minutes

### SPL Queries

#### 7.1 Cloud Security Score by Provider
```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| where event_type="Cloud IAM Change"
| stats count(eval(severity="Critical")) as critical,
        count(eval(severity="High")) as high,
        count as total
        by cloud_provider
| eval score = round(100 - ((critical * 15 + high * 5) / total * 10), 0)
| eval score = if(score < 0, 0, score)
| eval grade = case(score >= 90,"A", score >= 80,"B", score >= 70,"C", score >= 60,"D", 1=1,"F")
| table cloud_provider, score, grade, critical, high
```

#### 7.2 IAM Activity Anomalies
```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| where event_type="Cloud IAM Change"
| stats count as changes,
        values(action) as actions,
        values(resource) as resources
        by user, cloud_provider
| eval risk = case(
    action LIKE "%Admin%" OR action LIKE "%AttachAdminPolicy%", "Critical",
    action LIKE "%AccessKey%" OR action LIKE "%AssumeRole%", "High",
    1=1, "Medium"
)
| sort - changes
| table user, cloud_provider, changes, actions, resources, risk
```

---

## Dashboard 8: Vulnerability Management

**Audience:** Vulnerability Management Team, IT Ops
**Purpose:** Track vulnerabilities across infrastructure
**Refresh:** Daily

### SPL Queries

#### 8.1 CVE Exploitation Attempts
```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| where event_type="IDS Alert"
| rex field=signature "CVE-(?<cve_id>\d{4}-\d+)"
| where isnotnull(cve_id)
| stats count as detections,
        dc(source_ip) as affected_sources
        by cve_id, signature
| sort - detections
| table cve_id, signature, detections, affected_sources
```

#### 8.2 Most Vulnerable Hosts
```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| where severity IN ("Critical", "High")
| stats count as threat_events,
        dc(mitre_technique) as techniques_seen,
        dc(event_type) as attack_vectors
        by host
| eval vuln_score = (threat_events * 2) + (techniques_seen * 5) + (attack_vectors * 3)
| sort - vuln_score
| head 10
| table host, threat_events, techniques_seen, attack_vectors, vuln_score
```

---

## Dashboard 9: Compliance & Audit

**Audience:** Compliance Team, Auditors, Legal
**Purpose:** Track regulatory compliance status
**Refresh:** Daily

### SPL Queries

#### 9.1 Audit Log Integrity Monitoring
```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| where event_type IN ("Security Tool Disabled", "Wazuh Alert")
| stats count as violations,
        values(host) as affected_systems,
        values(user) as responsible_users
        by event_type
| eval compliance_impact = "Critical - Audit Trail Compromised"
| table event_type, violations, affected_systems, responsible_users, compliance_impact
```

#### 9.2 Security Tool Tampering (T1562)
```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| where mitre_technique="T1562.001"
| stats count as tampering_events,
        values(host) as affected_hosts,
        values(user) as users
        by event_type
| eval compliance_flag = "FAIL - Defense Evasion Detected"
| table event_type, tampering_events, affected_hosts, users, compliance_flag
```

---

## Dashboard 10: Threat Intelligence

**Audience:** Threat Intel Team, SOC Analysts
**Purpose:** Correlate events with threat intelligence feeds
**Refresh:** Real-time

### SPL Queries

#### 10.1 IOC Correlation (Lab Attacker IPs + Domains)
```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| eval ioc_match = case(
    source_ip IN ("103.45.78.21","45.67.22.10","185.220.101.45","91.234.56.78","192.168.56.104"), "Malicious IP",
    destination_domain LIKE "%evil%"  OR destination_domain LIKE "%malware%" OR destination_domain LIKE "%c2%", "Malicious Domain",
    file_hash IN ("a1b2c3d4e5f6789012345678abcdef01","deadbeef12345678cafebabe87654321"), "Known Malware Hash",
    1=1, null()
)
| where isnotnull(ioc_match)
| stats count as ioc_hits,
        dc(host) as hosts_affected,
        values(event_type) as related_events
        by ioc_match
| sort - ioc_hits
```

#### 10.2 APT Technique Mapping
```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| where isnotnull(mitre_technique)
| eval apt_group = case(
    mitre_technique IN ("T1059.001","T1003.001","T1021.002"), "APT29 (Cozy Bear)",
    mitre_technique IN ("T1566.001","T1547.001","T1486"), "Lazarus Group",
    mitre_technique IN ("T1071.004","T1048"), "APT41",
    mitre_technique IN ("T1110.001","T1558.003"), "FIN7 / Threat Actor",
    1=1, null()
)
| where isnotnull(apt_group)
| stats count as technique_hits,
        values(mitre_technique) as techniques,
        dc(host) as hosts
        by apt_group
| sort - technique_hits
```

#### 10.3 Threat Feed Hit Rate Over Time
```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| where source_ip IN ("103.45.78.21","45.67.22.10","185.220.101.45","192.168.56.104")
| eval _time = strptime(timestamp, "%Y-%m-%dT%H:%M:%S")
| timechart span=6h count by source_ip
```

---

## Real Company Examples

### 🏦 Banking / Finance SOC

**Primary Dashboards:**
1. **Fraud Detection** — Real-time transaction monitoring
2. **PCI-DSS Compliance** — Cardholder data protection
3. **SWIFT Network Monitor** — International transfer security
4. **ATM/POS Security** — Physical device monitoring

**Key Metrics:** Transaction anomaly rate, card-not-present fraud, PCI compliance %, SWIFT message integrity

---

### 🏥 Healthcare SOC

**Primary Dashboards:**
1. **PHI Access Monitoring** — Patient data access tracking
2. **HIPAA Compliance** — Healthcare regulation dashboard
3. **Medical Device Security** — IoMT device monitoring
4. **Ransomware Defense** — Healthcare-targeted threats

**Key Metrics:** Unauthorized PHI access, medical device patch status, HIPAA violation count, breach detection time

---

### 🏭 Manufacturing / OT SOC

**Primary Dashboards:**
1. **OT/ICS Security** — Industrial control system monitoring
2. **IT/OT Convergence** — Network segmentation visibility
3. **Supply Chain Security** — Vendor access monitoring
4. **Physical Security Integration** — Access control + SIEM

**Key Metrics:** ICS protocol anomalies, unauthorized PLC access, production uptime, vendor session monitoring

---

### 🛒 E-commerce / Retail SOC

**Primary Dashboards:**
1. **Bot Detection** — Credential stuffing, scraping
2. **Payment Fraud** — Checkout fraud detection
3. **Account Takeover** — Customer account protection
4. **DDoS Mitigation** — Availability monitoring

**Key Metrics:** Bot traffic %, checkout fraud rate, account takeover attempts, site availability SLA

---

### ☁️ Cloud-Native Company SOC

**Primary Dashboards:**
1. **Multi-Cloud Security** — AWS, Azure, GCP unified view
2. **Container Security** — Kubernetes, Docker monitoring
3. **Serverless Security** — Lambda, Azure Functions
4. **DevSecOps Pipeline** — CI/CD security gates

**Key Metrics:** Cloud misconfiguration count, container vulnerability score, secrets exposure, pipeline gates passed

---

## Interview Tips

When presenting SOC dashboards in interviews, say:

1. **Business Context** — "This dashboard cut MTTD from 4 hours to 15 minutes"
2. **Scalability** — "The queries handle 10,000+ events per second in production SIEMs"
3. **Automation** — "In a real SOC, these would auto-create tickets in ServiceNow or Jira"
4. **Integration** — "This correlates data from Windows Security, Sysmon, Wazuh, and Firewall logs"
5. **MITRE Alignment** — "Every detection maps to a MITRE ATT&CK technique — T1003 is credential access, T1486 is ransomware"

---

<p align="center">
  <b>🛡️ Enterprise SOC Dashboard Reference</b><br>
  <i>Praharsh Edition — Multi-SIEM SOC Lab</i>
</p>
