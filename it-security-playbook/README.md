# IT & Security Operations Playbook

## Overview

A comprehensive applied lab playbook demonstrating technical competencies across IT support, networking, and security operations. Seven labs executed in a live home lab environment — Windows Server 2022 Active Directory domain, Kali Linux, and GPG/SCP — with all findings documented, NIST-aligned, and mapped to CompTIA A+, Network+, and Security+ certification objectives.

**The goal:** Demonstrate practical, enterprise-relevant IT and security skills through documented lab evidence rather than theoretical knowledge alone.

---

## Lab Environment

| Component | Technology |
|---|---|
| Domain Controller | Windows Server 2022 Standard – LAB-DC01.lab.local |
| Domain | Active Directory – lab.local |
| Attack / Analysis Platform | Kali Linux |
| Virtualization | VMware Fusion |
| Tooling | Nmap, Wireshark, GPG, SCP, AD Users & Computers, Group Policy Management |

---

## Labs Completed

### Lab 1 – Network Discovery and Exposure Analysis (Nmap)
**Tools:** Kali Linux, Nmap  
**NIST:** ID.AM, ID.RA | RA-5, CM-7

Conducted host discovery, TCP SYN scans, service enumeration, and OS detection against the lab network. Identified exposed services and evaluated associated attack surface risks.

```bash
nmap -sn 192.168.x.0/24          # Host discovery
nmap -sS -sV 192.168.x.x         # Service detection
nmap -O 192.168.x.x              # OS fingerprinting
```

---

### Lab 2 – Packet Capture and Traffic Analysis (Wireshark)
**Tools:** Wireshark  
**NIST:** PR.DS, DE.CM | SC-7, IA-7

Captured live network traffic and applied protocol filters to observe unencrypted HTTP sessions and DNS queries. Demonstrated the risk of cleartext data in transit and the need for TLS enforcement.

---

### Lab 3 – Endpoint Troubleshooting and OS Recovery
**Tools:** Windows Recovery Environment, Windows Server 2022  
**NIST:** PR.IP, RC.RP | CP-10, SI-7

Executed disk integrity checks and boot record repair commands. Documented the full recovery procedure for corrupted boot sector scenarios.

```cmd
sfc /scannow
chkdsk C: /f /r
bootrec /fixmbr
bootrec /fixboot
bootrec /rebuildbcd
```

---

### Lab 4 – Identity and Access Management (Active Directory)
**Tools:** Active Directory Users and Computers, Group Policy Management Editor  
**NIST:** PR.AC | AC-2, AC-6

Full AD DS deployment from server preparation through domain promotion, OU structure, user provisioning, RBAC group assignment, and policy configuration. All steps executed on live Windows Server 2022 infrastructure.

**What was built:**
- Domain promoted: LAB-DC01 → lab.local forest root
- OUs created: IT_Staff, Help_Desk
- Users provisioned: jsmith (IT_Staff), jdoe (Help_Desk)
- RBAC groups: IT_Staff (elevated), HD_ReadOnly (least privilege)
- Password policy: 12-char minimum, complexity enabled, 90-day max age, 24-password history
- Lockout policy: 5 invalid attempts, 10-minute lockout duration

---

### Lab 5 – Encryption at Rest and In Transit
**Tools:** GPG, SCP (Kali Linux)  
**NIST:** PR.DS | SC-12, SC-13

Encrypted files at rest using GPG key pairs and transferred data securely using SCP over SSH. Demonstrated replacement of insecure transfer methods (FTP, HTTP) with encrypted alternatives.

```bash
gpg --gen-key
gpg --output file.gpg --encrypt --recipient user@lab.local file.txt
scp file.txt user@192.168.x.x:/destination/
```

---

### Lab 6 – Incident Response Simulation (Ransomware Tabletop)
**Tools:** Windows Event Viewer, Task Manager, Registry Editor, VM Snapshot  
**NIST:** RS, RC | IR-4, IR-8  
**Scenario:** NIST SP 800-61 lifecycle tabletop – simulated ransomware infection

| Phase | Action | Tool | Time |
|---|---|---|---|
| Identification | Anomalous process detected | Event Viewer / Task Manager | T+0 |
| Containment | Host isolated from network | VM network adapter disabled | T+10 min |
| Eradication | Process terminated, persistence checked | Task Manager, Registry Editor | T+25 min |
| Recovery | Snapshot restored, integrity verified | VM Snapshot Manager | T+45 min |
| Lessons Learned | Gaps documented, checklist updated | Written report | T+60 min |

---

### Lab 7 – Risk Assessment and Documentation
**NIST:** ID.RA | RA-3, PM-9

Translated technical lab findings into a business risk register with likelihood, impact, existing controls, and mitigation strategies — demonstrating GRC documentation skills relevant to analyst and compliance roles.

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| RDP exposed externally | High | High | Restrict to VPN/jump host |
| HTTP in use (unencrypted) | Medium | Medium | Enforce TLS |
| Weak password policy | Medium | High | GPO: 12+ char + MFA |
| No centralized logging | High | High | Deploy SIEM |
| No EDR coverage | Medium | High | Evaluate EDR solution |

---

## ITIL 4 Integration

Service management principles are integrated throughout the playbook via Service Value Chain mapping, key practice documentation (Incident Management, Problem Management, Change Enablement), and ITIL artifacts including a Change Record Template and Continual Improvement Register.

---

## Framework Alignment Summary

| Framework | Role |
|---|---|
| NIST CSF | Security risk management across all five functions |
| NIST SP 800-53 | Specific control references per lab |
| ITIL 4 | Service management and governance structure |
| CompTIA A+ / Network+ / Security+ | Technical execution competencies |

---

## Full Lab Documentation

📄 [IT_Playbook_Updated.docx](./IT_Playbook_Updated.docx) — Complete playbook with lab screenshots, findings, NIST alignment tables, ITIL artifacts, and risk register
