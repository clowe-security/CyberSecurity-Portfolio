# SIEM Home Lab – Splunk Enterprise Threat Detection

## Overview

Built a functional home SIEM environment using Splunk Enterprise 10.2.1 installed on a Windows Server 2022 Active Directory domain controller. Ingested real Windows Security event logs and engineered three detection rules mapped to MITRE ATT&CK techniques. Validated end-to-end detection pipeline through live triggered alerts.

**The goal:** Demonstrate practical SOC analyst skills — log ingestion, SPL query writing, alert engineering, and detection validation — using the same tools and event sources used in enterprise security operations.

---

## Lab Architecture

```
Windows Server 2022 (LAB-DC01.lab.local)
├── Active Directory Domain Services (lab.local)
├── Splunk Enterprise 10.2.1 (localhost:8000)
└── Windows Security Event Log → Splunk WinEventLog:Security
```

**Why a domain controller as the log source?**  
Domain controllers generate the highest-value security events in any Windows environment — authentication events, account creation, group membership changes, and privilege use. Using LAB-DC01 as both the Splunk host and log source maximizes detection relevance from day one.

---

## Tools Used

| Tool | Version | Purpose |
|---|---|---|
| Splunk Enterprise | 10.2.1 | SIEM platform, search, alerting |
| Windows Server 2022 | Standard Evaluation | Log source and Splunk host |
| Active Directory | lab.local domain | Authentication and IAM event generation |
| SPL (Search Processing Language) | — | Detection query development |

---

## Detection Rules Built

### Detection 1 — Brute Force / Multiple Failed Logons
**MITRE ATT&CK:** T1110 – Brute Force  
**Severity:** Critical | **Mode:** Real-time, Per Result

```spl
index=main source="WinEventLog:Security" EventCode=4625
| stats count by Account_Name, IpAddress, ComputerName
| where count >= 5
| sort -count
```

EventCode 4625 fires on every failed Windows logon attempt. This detection surfaces accounts accumulating 5+ failures as priority brute force or password spray targets. Validated through a controlled simulation generating 7 live 4625 events against domain account jsmith.

---

### Detection 2 — New User Account Created
**MITRE ATT&CK:** T1136 – Create Account  
**Severity:** High | **Mode:** Real-time, Per Result

```spl
index=main source="WinEventLog:Security" EventCode=4720
| table _time, Account_Name, ComputerName, Message
```

EventCode 4720 fires whenever a new Active Directory user account is created. Detection captures full AD attributes including SAM Account Name, UPN, Display Name, and the creating administrator — providing complete attribution for every account creation event.

---

### Detection 3 — Privileged Group Membership Change
**MITRE ATT&CK:** T1098 – Account Manipulation  
**Severity:** High | **Mode:** Real-time, Per Result

```spl
index=main source="WinEventLog:Security"
    EventCode=4728 OR EventCode=4732 OR EventCode=4756
| table _time, Account_Name, ComputerName, Message
```

Covers additions to security-enabled global (4728), local (4732), and universal (4756) groups. Detects privilege escalation via unauthorized group manipulation. Returned 22 events documenting all RBAC assignments in the lab environment.

---

## Validation Results

| Alert | Events Detected | Live Triggers | Confirmed |
|---|---|---|---|
| Brute Force - Multiple Failed Logons | 7 EventCode 4625 events | 4 real-time triggers fired | ✅ |
| New User Account Created | 5 EventCode 4720 events | Historical capture | ✅ |
| Privileged Group Membership Change | 22 EventCode 4728/4732/4756 events | Historical capture | ✅ |

---

## Framework Alignment

| Framework | Control | Coverage |
|---|---|---|
| MITRE ATT&CK | T1110, T1136, T1098 | All three detections map to documented adversary techniques |
| NIST CSF | Detect (DE.CM, DE.AE) | Continuous real-time monitoring across authentication and IAM |
| NIST SP 800-53 | AC-2, AC-6, AC-7, AU-2, SI-4 | Account management, least privilege, logon attempt monitoring |

---

## Key Lessons Learned

- **Scheduled vs real-time alerts:** Stats-based SPL aggregation is incompatible with real-time per-result alerting — use event-match queries for real-time alerts and aggregation logic in dashboards
- **Domain controller logs are highest-value:** Authentication, IAM, and group events are present immediately with no simulation required
- **Alert severity calibration:** Mapping severity to business impact (Critical for auth failures, High for account/group changes) matches real SOC triage priorities

---

## Full Lab Documentation

📄 [SIEM_Home_Lab_Book.docx](./SIEM_Home_Lab_Book.docx) — Complete lab book with screenshots, SPL queries, event analysis, MITRE and NIST mappings, and analyst notes
