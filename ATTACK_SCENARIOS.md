# ⚔️ Attack Scenarios — Real-World Lab Walkthroughs

<p align="center">
  <b>How Each Attack Was Simulated in Praharsh's SOC Lab</b><br>
  <i>Every scenario maps to MITRE ATT&CK | Detectable via Splunk, Wazuh & Sentinel</i>
</p>

---

## 📋 Table of Contents

1. [Scenario 1 — Ransomware Attack Chain](#scenario-1--ransomware-attack-chain)
2. [Scenario 2 — Phishing → Credential Theft](#scenario-2--phishing--credential-theft)
3. [Scenario 3 — Lateral Movement via PsExec & RDP](#scenario-3--lateral-movement-via-psexec--rdp)
4. [Scenario 4 — Kerberoasting (AD Attack)](#scenario-4--kerberoasting-ad-attack)
5. [Scenario 5 — C2 Beaconing & Data Exfiltration](#scenario-5--c2-beaconing--data-exfiltration)
6. [Scenario 6 — Insider Threat / DLP Violation](#scenario-6--insider-threat--dlp-violation)
7. [Scenario 7 — Living-off-the-Land (LOLBIN)](#scenario-7--living-off-the-land-lolbin)
8. [Scenario 8 — Cloud IAM Privilege Escalation](#scenario-8--cloud-iam-privilege-escalation)
9. [Detection Coverage Matrix](#detection-coverage-matrix)

---

## Scenario 1 — Ransomware Attack Chain

**Threat Actor:** Simulated Ryuk/LockBit-style ransomware  
**Target:** Windows workstation → Domain Controller  
**Tools Used (Lab):** Metasploit, PowerShell Empire, custom batch scripts  
**Risk Level:** 🔴 Critical

### Attack Flow

```
[Phishing Email]
      │
      ▼
[User Opens Malicious Attachment]  ← T1566.001
      │
      ▼
[PowerShell Dropper Executes]      ← T1059.001
      │
      ▼
[Persistence via Scheduled Task]   ← T1053.005
      │
      ▼
[Credential Dumping (Mimikatz)]    ← T1003.001
      │
      ▼
[Lateral Movement to DC]           ← T1021.002
      │
      ▼
[Shadow Copy Deletion]             ← T1490
      │
      ▼
[File Encryption — Ransomware]     ← T1486
```

### MITRE ATT&CK Techniques

| Technique ID | Name | Tactic |
|---|---|---|
| T1566.001 | Spearphishing Attachment | Initial Access |
| T1059.001 | PowerShell | Execution |
| T1053.005 | Scheduled Task | Persistence |
| T1003.001 | LSASS Memory Dump | Credential Access |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement |
| T1490 | Inhibit System Recovery | Impact |
| T1486 | Data Encrypted for Impact | Impact |

### Log Events Generated (in your CSV)

```
event_type: "Phishing Email Detected"
event_type: "PowerShell Execution"
event_type: "Scheduled Task Created"
event_type: "Credential Dumping"
event_type: "Lateral Movement Detected"
event_type: "Ransomware Detected"
severity: "Critical"
```

### Splunk Detection Query

```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| eval attack_stage = case(
    event_type="Phishing Email Detected", "1 - Initial Access",
    event_type="PowerShell Execution", "2 - Execution",
    event_type="Scheduled Task Created", "3 - Persistence",
    event_type="Credential Dumping", "4 - Cred Access",
    event_type="Lateral Movement Detected", "5 - Lateral Movement",
    event_type="Ransomware Detected", "6 - Impact",
    1=1, null()
)
| where isnotnull(attack_stage)
| stats count by attack_stage, host, user
| sort attack_stage
```

### How to Detect It — SOC Analyst Checklist

- [ ] Alert on `powershell.exe` spawned from `outlook.exe` or `winword.exe`
- [ ] Monitor for `vssadmin delete shadows` command (shadow copy deletion)
- [ ] Alert on mass file rename events (`.locked`, `.ryuk`, `.enc` extensions)
- [ ] Watch for LSASS memory access by non-system processes
- [ ] Detect lateral SMB connections from workstations to DC

---

## Scenario 2 — Phishing → Credential Theft

**Threat Actor:** Generic phishing campaign (FIN7-style)  
**Target:** Finance department users  
**Tools Used (Lab):** GoPhish simulation, Mimikatz  
**Risk Level:** 🟠 High

### Attack Flow

```
[Mass Phishing Email]              ← T1566.002
      │
      ▼
[User Clicks Malicious Link]
      │
      ▼
[Fake Login Page — Credential Harvest] ← T1056.003
      │
      ▼
[Attacker Logs In with Stolen Creds]   ← T1078
      │
      ▼
[MFA Bypass / Token Theft]             ← T1528
      │
      ▼
[Email Forwarding Rule Created]        ← T1114.003
```

### MITRE ATT&CK Techniques

| Technique ID | Name | Tactic |
|---|---|---|
| T1566.002 | Spearphishing Link | Initial Access |
| T1056.003 | Web Portal Capture | Credential Access |
| T1078 | Valid Accounts | Defense Evasion |
| T1528 | Steal Application Access Token | Credential Access |
| T1114.003 | Email Forwarding Rule | Collection |

### Splunk Detection Query

```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| where event_type IN ("Phishing Email Detected", "Credential Harvesting", "Suspicious Login")
| stats count as events,
        dc(host) as hosts_hit,
        values(user) as targeted_users
        by event_type
| eval risk = "High — Phishing Campaign Active"
| sort - events
```

### How to Detect It — SOC Analyst Checklist

- [ ] Alert on login from new geolocation within 30 minutes of a failed login
- [ ] Monitor for email forwarding rules created outside business hours
- [ ] Alert on OAuth token creation for new third-party apps
- [ ] Watch for successful login immediately after phishing alert on same user

---

## Scenario 3 — Lateral Movement via PsExec & RDP

**Threat Actor:** APT29-style post-compromise movement  
**Target:** Internal servers after initial foothold  
**Tools Used (Lab):** PsExec, RDP brute force, Impacket  
**Risk Level:** 🔴 Critical

### Attack Flow

```
[Initial Foothold on WORKSTATION-01]
      │
      ▼
[Port Scan — Discover Internal Hosts] ← T1046
      │
      ▼
[RDP Brute Force on SERVER-02]        ← T1110.001
      │
      ▼
[PsExec Remote Execution on DC]       ← T1021.002 / T1047
      │
      ▼
[Dump Domain Hashes (secretsdump)]    ← T1003.002
      │
      ▼
[Pass-the-Hash to Admin Shares]       ← T1550.002
```

### MITRE ATT&CK Techniques

| Technique ID | Name | Tactic |
|---|---|---|
| T1046 | Network Service Discovery | Discovery |
| T1110.001 | Password Guessing | Credential Access |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement |
| T1047 | Windows Management Instrumentation | Execution |
| T1003.002 | Security Account Manager | Credential Access |
| T1550.002 | Pass the Hash | Defense Evasion |

### Splunk Detection Query

```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| where event_type IN ("Port Scan Detected", "RDP Brute Force", "Lateral Movement Detected", "PsExec Execution")
| eval _time = strptime(timestamp, "%Y-%m-%dT%H:%M:%S")
| sort _time
| stats count as events,
        values(host) as hosts_involved,
        values(destination_ip) as targets,
        dc(host) as hops
        by user
| where hops >= 2
| eval lateral_movement_confirmed = "YES — " . hops . " hops detected"
| table user, events, hops, hosts_involved, targets, lateral_movement_confirmed
```

### How to Detect It — SOC Analyst Checklist

- [ ] Alert on PsExec service installation (Event ID 7045)
- [ ] Monitor RDP (port 3389) connections between workstations — not just to servers
- [ ] Alert on `net use \<IP>dmin$` commands
- [ ] Watch for NTLM authentication from unexpected sources
- [ ] Detect port scans from internal IPs (Nmap signatures)

---

## Scenario 4 — Kerberoasting (AD Attack)

**Threat Actor:** Insider / low-privileged attacker  
**Target:** Active Directory service accounts  
**Tools Used (Lab):** Rubeus, Impacket GetUserSPNs  
**Risk Level:** 🟠 High

### Attack Flow

```
[Low-Privileged Domain User Access]
      │
      ▼
[Enumerate Service Principal Names]  ← T1558.003
      │
      ▼
[Request TGS Tickets for SPNs]       ← T1558.003
      │
      ▼
[Offline Brute Force of RC4 Hashes]  ← T1110.002
      │
      ▼
[Gain Service Account Credentials]
      │
      ▼
[Privilege Escalation to Admin]      ← T1078.002
```

### MITRE ATT&CK Techniques

| Technique ID | Name | Tactic |
|---|---|---|
| T1558.003 | Kerberoasting | Credential Access |
| T1110.002 | Password Cracking | Credential Access |
| T1078.002 | Domain Accounts | Defense Evasion |

### Splunk Detection Query

```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| where event_type="Kerberos TGS Request"
| stats count as tgs_requests,
        dc(service_name) as unique_spns,
        values(service_name) as targeted_spns
        by user, host
| where tgs_requests > 3
| eval kerberoast_risk = case(
    tgs_requests > 10, "Critical — Mass Kerberoasting",
    tgs_requests > 3, "High — Suspicious TGS Volume",
    1=1, "Monitor"
)
| sort - tgs_requests
| table user, host, tgs_requests, unique_spns, targeted_spns, kerberoast_risk
```

### How to Detect It — SOC Analyst Checklist

- [ ] Alert on Event ID 4769 with RC4 encryption (0x17) — a Kerberoasting signature
- [ ] Monitor for a single user requesting TGS for 5+ service accounts
- [ ] Watch for unusual Kerberos activity outside business hours
- [ ] Alert on `Rubeus.exe` or `GetUserSPNs.py` process names

---

## Scenario 5 — C2 Beaconing & Data Exfiltration

**Threat Actor:** APT41 / Cobalt Strike-style operation  
**Target:** Corporate file servers  
**Tools Used (Lab):** Metasploit reverse shell, Netcat, DNS tunneling  
**Risk Level:** 🔴 Critical

### Attack Flow

```
[Malware Installed on Endpoint]
      │
      ▼
[Periodic C2 Beacon to Attacker]    ← T1071.001
      │
      ▼
[Attacker Issues Commands]
      │
      ▼
[Internal Reconnaissance]           ← T1083 / T1057
      │
      ▼
[Sensitive Files Staged]            ← T1074.001
      │
      ▼
[DNS Tunneling Exfiltration]        ← T1048.003 / T1071.004
      │
      ▼
[Data Sent to Attacker C2 Server]
```

### MITRE ATT&CK Techniques

| Technique ID | Name | Tactic |
|---|---|---|
| T1071.001 | Web Protocols (C2) | Command & Control |
| T1083 | File and Directory Discovery | Discovery |
| T1074.001 | Local Data Staging | Collection |
| T1048.003 | Exfil Over Unencrypted Protocol | Exfiltration |
| T1071.004 | DNS (C2) | Command & Control |

### Splunk Detection Query

```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| where event_type IN ("C2 Outbound Connection", "DNS Tunneling Detected", "Data Exfiltration")
| eval _time = strptime(timestamp, "%Y-%m-%dT%H:%M:%S")
| stats count as connections,
        sum(bytes_sent) as total_bytes,
        dc(destination_ip) as c2_servers,
        values(event_type) as stages
        by host, user
| eval total_mb = round(total_bytes/1024/1024, 2)
| eval exfil_risk = case(
    total_mb > 100, "Critical — Large Data Exfil",
    total_mb > 10, "High — Suspicious Transfer",
    1=1, "Medium — Monitor"
)
| sort - total_bytes
| table host, user, connections, total_mb, c2_servers, stages, exfil_risk
```

### How to Detect It — SOC Analyst Checklist

- [ ] Alert on regular outbound connections at fixed intervals (beaconing pattern)
- [ ] Monitor DNS query length — anything over 50 chars is suspicious
- [ ] Alert on large outbound data transfers to unknown IPs
- [ ] Watch for port 4444, 4445, 8080, 8443 outbound connections
- [ ] Detect `nc.exe` (Netcat) usage via process monitoring

---

## Scenario 6 — Insider Threat / DLP Violation

**Threat Actor:** Malicious or careless insider employee  
**Target:** Sensitive HR/Finance documents  
**Tools Used (Lab):** Simulated file copy + email exfil  
**Risk Level:** 🟠 High

### Attack Flow

```
[Legitimate User Access]
      │
      ▼
[Access Sensitive Files Outside Role] ← T1078
      │
      ▼
[Mass File Download / USB Copy]       ← T1052.001
      │
      ▼
[Email to Personal Account]           ← T1114.003 / T1048
      │
      ▼
[DLP Policy Violation Triggered]
```

### MITRE ATT&CK Techniques

| Technique ID | Name | Tactic |
|---|---|---|
| T1078 | Valid Accounts | Defense Evasion |
| T1052.001 | Exfiltration over USB | Exfiltration |
| T1114.003 | Email Forwarding Rule | Collection |

### Splunk Detection Query

```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| where event_type="DLP Violation"
| stats count as violations,
        dc(user) as unique_users,
        values(policy_violated) as policies,
        values(file_name) as files
        by recipient_domain
| eval risk = case(
    recipient_domain LIKE "%gmail%" OR recipient_domain LIKE "%yahoo%", "High — Personal Email Exfil",
    violations > 10, "Critical — Mass DLP Violation",
    1=1, "Medium"
)
| sort - violations
| table recipient_domain, violations, unique_users, policies, files, risk
```

### How to Detect It — SOC Analyst Checklist

- [ ] Alert on file access volume exceeding user's baseline (UBA)
- [ ] Monitor USB device connections on sensitive workstations
- [ ] Alert on emails with attachments sent to personal domains (gmail, yahoo)
- [ ] Watch for access to HR/Finance shares from non-HR/Finance users

---

## Scenario 7 — Living-off-the-Land (LOLBIN)

**Threat Actor:** Red team / fileless malware  
**Target:** Any Windows endpoint  
**Tools Used (Lab):** certutil, mshta, regsvr32, bitsadmin  
**Risk Level:** 🟠 High

### What is LOLBIN?

Attackers use **legitimate Windows binaries** to execute malicious code — no malware dropped on disk, so AV misses it completely.

### Attack Flow

```
[Attacker Uses certutil.exe]          ← T1105
      │
      ▼
[Downloads payload from internet]
      │
      ▼
[mshta.exe runs remote HTA script]    ← T1218.005
      │
      ▼
[regsvr32.exe loads malicious DLL]    ← T1218.010
      │
      ▼
[bitsadmin schedules persistence]     ← T1197
```

### MITRE ATT&CK Techniques

| Technique ID | Name | Tactic |
|---|---|---|
| T1105 | Ingress Tool Transfer | Command & Control |
| T1218.005 | Mshta | Defense Evasion |
| T1218.010 | Regsvr32 | Defense Evasion |
| T1197 | BITS Jobs | Defense Evasion / Persistence |

### Splunk Detection Query

```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| where event_type="LOLBIN Execution"
| stats count as executions,
        values(command_line) as commands,
        dc(host) as hosts_affected
        by process, user
| eval lolbin_risk = case(
    process IN ("certutil.exe", "mshta.exe"), "Critical — Known Malicious LOLBIN",
    process IN ("regsvr32.exe", "bitsadmin.exe"), "High — Suspicious LOLBIN",
    process IN ("wscript.exe", "cscript.exe"), "High — Script Host Abuse",
    1=1, "Medium"
)
| sort - executions
| table process, user, executions, hosts_affected, commands, lolbin_risk
```

### How to Detect It — SOC Analyst Checklist

- [ ] Alert on `certutil.exe -urlcache -f http://` commands
- [ ] Monitor `mshta.exe` spawned from Office apps
- [ ] Watch for `regsvr32.exe /s /n /u /i:http://` (squiblydoo)
- [ ] Alert on `bitsadmin /transfer` with external URLs

---

## Scenario 8 — Cloud IAM Privilege Escalation

**Threat Actor:** Cloud-focused APT / compromised developer  
**Target:** AWS/Azure cloud environment  
**Tools Used (Lab):** Simulated CloudTrail/AuditLogs events  
**Risk Level:** 🔴 Critical

### Attack Flow

```
[Leaked AWS Access Key on GitHub]     ← T1552.001
      │
      ▼
[Attacker Enumerates IAM Permissions] ← T1069.003
      │
      ▼
[Attach AdministratorAccess Policy]   ← T1098.001
      │
      ▼
[Create New Admin User as Backdoor]   ← T1136.003
      │
      ▼
[Spin Up Crypto Mining Instances]     ← T1496
```

### MITRE ATT&CK Techniques

| Technique ID | Name | Tactic |
|---|---|---|
| T1552.001 | Credentials in Files | Credential Access |
| T1069.003 | Cloud Groups | Discovery |
| T1098.001 | Additional Cloud Credentials | Persistence |
| T1136.003 | Cloud Account Creation | Persistence |
| T1496 | Resource Hijacking | Impact |

### Splunk Detection Query

```spl
index="praharsh_soc_lab" source="praharsh_siem_logs_3000.csv" sourcetype="csv"
| where event_type="Cloud IAM Change"
| stats count as changes,
        values(action) as actions,
        values(resource) as resources
        by user, cloud_provider
| eval priv_esc_risk = case(
    action LIKE "%AttachAdminPolicy%" OR action LIKE "%CreateUser%", "Critical — Privilege Escalation",
    action LIKE "%AssumeRole%" OR action LIKE "%CreateAccessKey%", "High — Credential Creation",
    1=1, "Medium"
)
| where priv_esc_risk != "Medium"
| sort - changes
| table user, cloud_provider, changes, actions, resources, priv_esc_risk
```

### How to Detect It — SOC Analyst Checklist

- [ ] Alert on `AttachUserPolicy` with `AdministratorAccess` ARN
- [ ] Monitor for new IAM user creation outside change management window
- [ ] Alert on root account usage (should be zero in normal operations)
- [ ] Watch for access key creation by non-admin users

---

## Detection Coverage Matrix

This shows which SIEM in your lab detects each scenario:

| Scenario | Splunk | Wazuh | Sentinel | Key Log Source |
|----------|--------|-------|----------|----------------|
| Ransomware Chain | ✅ | ✅ | ✅ | Sysmon, Windows Security |
| Phishing → Cred Theft | ✅ | ✅ | ✅ | Email Gateway, Auth Logs |
| Lateral Movement | ✅ | ✅ | ✅ | Sysmon EventID 3, 7045 |
| Kerberoasting | ✅ | ⚠️ Partial | ✅ | Windows EventID 4769 |
| C2 Beaconing | ✅ | ✅ | ✅ | Firewall, DNS, Zeek |
| Insider Threat / DLP | ✅ | ⚠️ Partial | ✅ | DLP Logs, File Audit |
| LOLBIN Abuse | ✅ | ✅ | ✅ | Sysmon EventID 1, 11 |
| Cloud IAM Escalation | ✅ | ❌ | ✅ | CloudTrail, AuditLogs |

> ⚠️ Partial = requires additional rule tuning
> ❌ = not supported natively without custom integration

---

## 🎯 Interview Talking Points

When asked *"Tell me about a security incident you investigated"* — use these scenarios:

> *"In my lab, I simulated a Kerberoasting attack where a low-privileged user requested TGS tickets for 8 service accounts within 2 minutes. I wrote a Splunk SPL rule to detect bulk TGS requests with RC4 encryption (Event ID 4769), which maps to MITRE T1558.003. The detection fired within 60 seconds of the attack starting."*

That's a complete, specific, interview-winning answer. Every scenario above gives you one of those. 🔥

---

<p align="center">
  <b>⚔️ Attack Scenarios Reference — Praharsh SOC Lab</b><br>
  <i>8 Real-World Scenarios | 30+ MITRE Techniques | Full SPL Coverage</i>
</p>
