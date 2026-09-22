# SIEM Home Lab – Splunk Enterprise Threat Detection

## Overview

Built a home SIEM using Splunk Enterprise 10.2.1 on a Windows Server 2022 Active Directory domain controller. Ingested real Windows Security event logs and built three detection rules mapped to MITRE ATT&CK techniques, then validated the pipeline end to end through live triggered alerts.

The goal was practical SOC analyst skill: log ingestion, SPL query writing, alert engineering, and detection validation, using the same tools and event sources found in real security operations.

---

## Lab Architecture

```
Windows Server 2022 (LAB-DC01.lab.local)
├── Active Directory Domain Services (lab.local)
├── Splunk Enterprise 10.2.1 (localhost:8000)
└── Windows Security Event Log → Splunk WinEventLog:Security
```

**Why a domain controller as the log source?** Domain controllers generate the highest-value security events in any Windows environment: authentication, account creation, group membership changes, and privilege use. Using LAB-DC01 as both the Splunk host and the log source meant those events were available from day one, with no simulation needed to generate them.

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
**MITRE ATT&CK:** T1110 – Brute Force | **Severity:** Critical | **Mode:** Real-time, Per Result

```spl
index=main source="WinEventLog:Security" EventCode=4625
```

EventCode 4625 fires on every failed Windows logon attempt. The alert itself uses a simple per-event match so it fires in real time; a separate stats-based search (grouping by account and IP, filtering to 5+ failures) is used for manual investigation, since aggregation queries don't work with real-time per-result alerting. Validated through a controlled simulation generating 7 live 4625 events against domain account jsmith, with 4 real-time alerts firing during the test.

---

### Detection 2 — New User Account Created
**MITRE ATT&CK:** T1136 – Create Account | **Severity:** High | **Mode:** Real-time, Per Result

```spl
index=main source="WinEventLog:Security" EventCode=4720
| table _time, Account_Name, ComputerName, Message
```

EventCode 4720 fires whenever a new Active Directory user account is created. The detection captures full AD attributes, including SAM Account Name, UPN, Display Name, and the creating administrator, so every creation event has a complete attribution trail.

---

### Detection 3 — Privileged Group Membership Change
**MITRE ATT&CK:** T1098 – Account Manipulation | **Severity:** High | **Mode:** Real-time, Per Result

```spl
index=main source="WinEventLog:Security"
    EventCode=4728 OR EventCode=4732 OR EventCode=4756
| table _time, Account_Name, ComputerName, Message
```

Covers additions to security-enabled global (4728), local (4732), and universal (4756) groups, catching privilege escalation through unauthorized group changes. Returned 22 events documenting all RBAC assignments in the lab environment.

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

- Scheduled alerts and real-time alerts behave differently: aggregation-based SPL (`stats`) doesn't fire in real-time per-result mode, since that mode evaluates individual events, not aggregates. Real-time alerts need a simple event-match query; aggregation logic belongs in a dashboard or scheduled search instead.
- Domain controller logs are high-value immediately: authentication, IAM, and group events are present with no simulation required.
- Mapping severity to business impact (Critical for auth failures, High for account or group changes) matches how real SOC teams triage.

---

## Full Lab Documentation

📄 [LAB_BOOK.md](./LAB_BOOK.md) – View the full lab book directly on GitHub, with SPL queries, event analysis, and MITRE/NIST mappings.
📄 [SIEM_Home_Lab_Book.docx](./SIEM_Home_Lab_Book.docx) – Original Word document, for download.
