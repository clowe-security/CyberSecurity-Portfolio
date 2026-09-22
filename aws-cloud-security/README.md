# AWS Cloud Security Lab

## Overview

This lab covers the design, build, and validation of a secure AWS environment, done in two rounds: an initial build through the AWS Management Console, then a full rebuild via the AWS CLI as Infrastructure-as-Code after the original account was closed when its Free Tier credits ran out. The current environment reflects the CLI rebuild described in the full lab book below.

Rebuilding as code instead of re-clicking through the console was a deliberate choice. It produces a reusable, reproducible build process and demonstrates the ability to stand up cloud security infrastructure programmatically, a skill increasingly expected even at entry-level GRC and SOC Analyst roles. The lab covers the full lifecycle: infrastructure design, control implementation, threat modeling, monitoring, and validation, using AWS-native services aligned to NIST and CIS frameworks.

---

## Lab Architecture

```
AWS Account (us-west-2)
├── Lab-VPC (10.0.0.0/16)
│   ├── Public Subnet (10.0.1.0/24)
│   │   └── EC2 Instance – Amazon Linux 2023 (t3.micro)
│   ├── Private Subnet (10.0.2.0/24)
│   └── Internet Gateway → Public Route Table (public subnet only)
├── IAM
│   ├── Root account – MFA enabled
│   └── Dedicated IAM role for CloudTrail → CloudWatch Logs integration
└── Monitoring Stack
    ├── CloudTrail (aws-cloudtrail-lab) – multi-region
    ├── CloudWatch Logs (/aws/cloudtrail/lab-trail)
    ├── CloudWatch Metric Filters + Alarms
    └── SNS – email alert delivery
```

---

## Confirmed Infrastructure IDs

*Current environment, rebuilt via AWS CLI (see the full lab book for the exact commands used to create each resource).*

| Resource | ID |
|---|---|
| VPC | vpc-06e1a3e8267ec9477 (Lab-VPC, 10.0.0.0/16) |
| Public Subnet | subnet-0f127eb233c5d6a35 (10.0.1.0/24) |
| Private Subnet | subnet-0dec64aed1d1dbb8d (10.0.2.0/24) |
| Internet Gateway | igw-023a2414a2be8c93f |
| Public Route Table | rtb-053a33eeb5c7e6c79 |
| Security Group | sg-0b5ddd68e9c3c1ff2 (SSH restricted to a single /32) |
| EC2 Instance | i-0535cb84f33d52162 (Lab-EC2, t3.micro, Amazon Linux 2023) |
| CloudTrail | aws-cloudtrail-lab (multi-region) |
| CloudWatch Log Group | /aws/cloudtrail/lab-trail |
| IAM Service Role | CloudTrail-CloudWatch-Role |
| SNS Topic | Lab-Security-Alerts |

---

## Tools & Services Used

| Service | Purpose |
|---|---|
| AWS VPC | Network isolation and segmentation |
| AWS EC2 | Linux compute instance with restricted access |
| AWS IAM | Least-privilege identity and access management |
| AWS CloudTrail | API activity logging across all regions |
| AWS CloudWatch Logs | Real-time log ingestion and metric filtering |
| AWS CloudWatch Alarms | Threshold-based alerting on security events |
| AWS SNS | Email notification delivery |
| AWS CLI | Infrastructure provisioning and verification |

---

## Phases Completed

### Phase 1 – Core Infrastructure Build
Custom VPC with public/private subnet segmentation. Internet Gateway with a route table scoped to the public subnet only. EC2 instance with a security group restricting SSH to a single analyst IP (/32). Key-based authentication enforced.

### Phase 2A – Control Mapping & Threat Modeling
Five threat scenarios evaluated: credential compromise, unauthorized SSH access, internet scanning, lateral movement, and undetected malicious API activity. Risk register below documents likelihood, impact, existing controls, and mitigations for each.

### Phase 2B – Logging & Detection Analysis
CloudTrail identified as the primary logging source. A host-level logging gap was documented, with the CloudWatch Unified Agent noted as the remediation path.

### Phase 3 – Monitoring Design
Detection strategy built around two high-impact, low-noise use cases: root account console login, and IAM privilege escalation via policy attachment or modification.

### Phase 4 – Alert Implementation

**Root Login Detection:**
```json
{ ($.eventName = "ConsoleLogin") && ($.userIdentity.type = "Root") }
```
Alarm: `Root-Login-Detected` | Threshold: ≥ 1 within 5 min | Action: SNS email

**IAM Privilege Change Detection:**
```json
{ ($.eventName = "AttachUserPolicy") || ($.eventName = "PutUserPolicy") ||
  ($.eventName = "CreatePolicyVersion") || ($.eventName = "AttachRolePolicy") }
```
Alarm: `IAM-Privilege-Change-Detected` | Threshold: ≥ 1 within 5 min | Action: SNS email

### Phase 5 – Validation & Testing
Both alarms were validated through controlled testing: a root login test and an IAM policy attachment test each triggered SNS email delivery. Disabling CloudTrail's own log-delivery SNS notifications separated informational noise from actionable alerts.

---

## Risk Register

| ID | Threat | Likelihood | Impact | Existing Control | Mitigation |
|---|---|---|---|---|---|
| R1 | Credential compromise | Low | Critical | MFA + IAM separation | Monitor all login activity |
| R2 | Unauthorized SSH | Low | High | Security group /32 | Migrate to SSM Session Manager |
| R3 | Internet scanning | Low | Medium | Minimal open ports | Maintain least privilege |
| R4 | Lateral movement | Low | High | Subnet segmentation | Deploy NACLs |
| R5 | Undetected API activity | Medium | High | CloudTrail logging | CloudWatch alerting |

---

## Framework Alignment

| Framework | Control | Coverage |
|---|---|---|
| NIST CSF | Identify, Protect, Detect, Respond | All five functions addressed across phases |
| NIST SP 800-53 | AC-2, AC-6, AU-2, AU-6, CA-7, IR-4, RA-3, SC-7, SI-4 | Specific controls mapped per phase |
| CIS AWS Benchmark | MFA on root, CloudTrail multi-region, least-privilege IAM | Core foundational controls implemented |

---

## Key Lessons Learned

- CloudTrail Event History can lag up to 15 minutes; CloudWatch Logs is the better source for real-time detection.
- AWS timestamps are UTC. Document the timezone offset in any incident timeline built from this data.
- Keep CloudTrail's own log-delivery SNS notifications separate from security alert SNS topics, or the inbox fills with noise.
- Validate a detection through a deliberate, controlled test before treating it as production-ready.

---

## Full Lab Documentation

📄 [LAB_BOOK.md](./LAB_BOOK.md) – View the full lab book directly on GitHub, with phase-by-phase commands, screenshots, the risk register, and analyst notes.
📄 [AWS_Cloud_Security_Lab_Book.docx](./AWS_Cloud_Security_Lab_Book.docx) – Original Word document, for download.
- EC2 instance with security group restricting SSH to analyst IP /32
- Key-based authentication enforced

### Phase 2A – Control Mapping & Threat Modeling
Five threat scenarios evaluated: credential compromise, unauthorized SSH access, internet scanning, lateral movement, and undetected malicious API activity. Risk register produced with likelihood, impact, existing controls, and mitigations.

### Phase 2B – Logging & Detection Analysis
CloudTrail identified as primary logging source. Host-level logging gap documented with remediation plan (CloudWatch Unified Agent).

### Phase 3 – Monitoring Design
Detection strategy designed around two high-impact, low-noise use cases:
- Root account console login
- IAM privilege escalation (policy attachment/modification)

### Phase 4 – Alert Implementation

**Root Login Detection:**
```json
{ ($.eventName = "ConsoleLogin") && ($.userIdentity.type = "Root") }
```
Alarm: `Root-Login-Detected` | Threshold: ≥ 1 within 5 min | Action: SNS email

**IAM Privilege Change Detection:**
```json
{ ($.eventName = "AttachUserPolicy") || ($.eventName = "PutUserPolicy") ||
  ($.eventName = "CreatePolicyVersion") || ($.eventName = "AttachRolePolicy") }
```
Alarm: `IAM-Privilege-Change-Detected` | Threshold: ≥ 1 within 5 min | Action: SNS email

### Phase 5 – Validation & Testing
Both alarms validated through controlled testing. Root login test and IAM policy attachment test both triggered SNS email delivery. Alert noise reduced by disabling CloudTrail log-delivery SNS notifications — separating informational from actionable alerts.

---

## Risk Register

| ID | Threat | Likelihood | Impact | Existing Control | Mitigation |
|---|---|---|---|---|---|
| R1 | Credential compromise | Low | Critical | MFA + IAM separation | Monitor all login activity |
| R2 | Unauthorized SSH | Low | High | Security group /32 | Migrate to SSM Session Manager |
| R3 | Internet scanning | Low | Medium | Minimal open ports | Maintain least privilege |
| R4 | Lateral movement | Low | High | Subnet segmentation | Deploy NACLs |
| R5 | Undetected API activity | Medium | High | CloudTrail logging | CloudWatch alerting |

---

## Framework Alignment

| Framework | Control | Coverage |
|---|---|---|
| NIST CSF | Identify, Protect, Detect, Respond | All five functions addressed across phases |
| NIST SP 800-53 | AC-2, AC-6, AU-2, AU-6, CA-7, IR-4, RA-3, SC-7, SI-4 | Specific controls mapped per phase |
| CIS AWS Benchmark | MFA on root, CloudTrail multi-region, least-privilege IAM | Core foundational controls implemented |

---

## Key Lessons Learned

- CloudTrail Event History has up to 15-minute latency — use CloudWatch Logs for real-time detection
- AWS timestamps are UTC — document timezone offset in all incident timelines
- Separate CloudTrail log-delivery SNS notifications from security alert SNS to prevent inbox flooding
- Always validate detection capability through deliberate controlled tests before considering a control production-ready

---

## Full Lab Documentation

📄 [AWS_Cloud_Security_Lab_Book.docx](./AWS_Cloud_Security_Lab_Book.docx) — Complete lab book with phase-by-phase documentation, infrastructure IDs, metric filter patterns, risk register, threat model, and analyst notes
