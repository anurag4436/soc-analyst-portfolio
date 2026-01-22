This repository represents a complete SOC Analyst (L1/L2) portfolio demonstrating real-world blue team skills including alert monitoring, log analysis, incident response, detection engineering, and MITRE ATT&CK mapping

# 🛡️ SOC Analyst (L1/L2) Blue Team Portfolio

This repository represents a **complete SOC Analyst (L1/L2) portfolio** demonstrating **real-world Blue Team operations** including alert monitoring, log analysis, incident response, detection engineering, MITRE ATT&CK mapping, SOC documentation, and escalation workflows.



---

## 📂 Repository Structure

```
soc-analyst-portfolio/
│
├── README.md
│
├── incident-response/
│   ├── phishing-investigation.md
│   ├── malware-incident.md
│   ├── brute-force-attack.md
│   └── ransomware-response.md
│
├── detection-rules/
│   ├── splunk/
│   │   └── failed-logon-detection.spl
│   ├── elastic/
│   │   └── suspicious-process.kql
│   └── sigma/
│       └── powershell-abuse.yml
│
├── log-analysis/
│   ├── windows-event-logs.md
│   ├── linux-auth-log.md
│   └── firewall-logs.md
│
├── mitre-mapping/
│   ├── attack-techniques.md
│   └── real-incident-mapping.md
│
├── soc-playbooks/
│   ├── phishing-playbook.md
│   ├── brute-force-playbook.md
│   └── malware-playbook.md
│
├── threat-intel/
│   ├── ioc-collection.md
│   └── threat-feeds.md
│
├── scripts/
│   ├── log-parser.py
│   └── hash-checker.py
│
└── dashboards/
    ├── soc-dashboard-examples.md
    └── alert-triage-workflow.md
```

---

## 🧠 Skills Demonstrated

* Alert triage & escalation (SOC L1 → L2)
* Windows & Linux log analysis
* SIEM detections (Splunk, Elastic, Sigma)
* MITRE ATT&CK mapping
* Incident response lifecycle
* Threat intelligence & IOC handling
* SOC documentation & reporting
* SOC ticketing & handoff notes

---

## 🚨 Incident Response Cases

### 📧 Phishing Investigation

**Alert Type:** Phishing Email
**Source:** Secure Email Gateway
**Severity:** Medium

**Investigation Steps**

1. Collected email headers
2. Verified sender domain reputation
3. Extracted URLs and attachments
4. Checked URLs on VirusTotal
5. Analyzed attachment hash

**Findings**

* Spoofed sender domain
* Malicious URL leading to credential harvesting

**MITRE ATT&CK**

* T1566.001 – Spearphishing Attachment

**Response Actions**

* Blocked sender domain
* Quarantined email
* Reset affected user password
* User awareness training

**Final Status:** Incident Contained

---

### 🦠 Malware Incident

**Alert:** Suspicious executable detected by EDR

**Investigation**

* Checked process tree
* Collected SHA256 hash
* Verified hash on VirusTotal

**Result**

* Trojan malware confirmed

**Response**

* Endpoint isolated
* Malicious file deleted
* Full system scan performed

---

### 🔐 Brute Force Attack

**Alert:** Multiple failed login attempts

**Log Evidence**

* Windows Event ID 4625
* Repeated login attempts from same source IP

**Response**

* Source IP blocked on firewall
* Forced password reset

---

### 🧨 Ransomware Response

**Indicators**

* Encrypted files
* Ransom note detected

**Response**

* Machine isolated
* Network access disabled
* Systems restored from backup

---

## 📊 Detection Rules

### 🔎 Splunk – Failed Login Detection

```spl
index=windows EventCode=4625
| stats count by Account_Name, src_ip
| where count > 5
```

### 🔎 Elastic (KQL) – Suspicious Process

```kql
process.name : "powershell.exe" and process.command_line : "*-enc*"
```

### 🔎 Sigma – PowerShell Abuse

```yaml
title: Suspicious PowerShell Execution
logsource:
  product: windows
  service: security
selection:
  CommandLine|contains: "-enc"
condition: selection
level: medium
```

---

## 📁 Log Analysis

### Windows Event Logs

| Event ID | Description          |
| -------- | -------------------- |
| 4624     | Successful logon     |
| 4625     | Failed logon         |
| 4688     | Process creation     |
| 4720     | User account created |

### Linux Authentication Logs

* File: `/var/log/auth.log`
* Tracks SSH logins
* Detects brute-force attempts

### Firewall Logs

* Source IP
* Destination IP
* Port & protocol
* Action (Allow/Deny)

---

## 🧠 MITRE ATT&CK Mapping

### Techniques

| Technique ID | Name         | Description                 |
| ------------ | ------------ | --------------------------- |
| T1566        | Phishing     | Initial access via email    |
| T1059        | Command-Line | Malicious command execution |

### Real Incident Mapping

* Phishing → T1566
* PowerShell abuse → T1059.001
* Brute force → T1110

---

## 📜 SOC Playbooks (L1/L2)

Each playbook follows:
**Alert → Triage →





