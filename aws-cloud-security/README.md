# AWS Cloud Security Lab

## Overview

Designed, implemented, and validated a secure AWS cloud environment following a phased security engineering approach. Built a segmented VPC infrastructure, configured least-privilege IAM controls, enabled multi-region CloudTrail logging, and implemented real-time detection and alerting for high-risk identity events using CloudWatch and SNS.

**The goal:** Demonstrate cloud security engineering skills across the full lifecycle — infrastructure design, control implementation, threat modeling, monitoring, and validation — using AWS-native services aligned to NIST and CIS frameworks.

---

## Lab Architecture

```
AWS Account (us-west-2)
├── Lab-VPC (10.10.0.0/16)
│   ├── Lab-Public-Subnet (10.10.1.0/24)
│   │   └── EC2 Instance – Amazon Linux 2023 (t2.micro)
│   ├── Lab-Private-Subnet (10.10.2.0/24)
│   └── Internet Gateway → Route Table (public subnet only)
├── IAM
│   ├── Root account – MFA enabled
│   └── Non-root IAM user – daily operations
└── Monitoring Stack
    ├── CloudTrail (aws-cloudtrail-lab) – multi-region
    ├── CloudWatch Logs (/aws/cloudtrail/lab)
    ├── CloudWatch Metric Filters + Alarms
    └── SNS – email alert delivery
```

---

## Confirmed Infrastructure IDs

| Resource | ID |
|---|---|
| VPC | vpc-036d53432fc27b0a9 |
| Public Subnet | subnet-0dd8a4cc9a767d0a1 |
| Private Subnet | subnet-0eff05b87f2780adb |
| Route Table | rtb-0602eeab6189fa2f |
| Internet Gateway | igw-0a3021bd536800137 |
| EC2 Instance | i-04c8a51c3dd935e61 |
| CloudTrail | aws-cloudtrail-lab |

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
| AWS CLI v2.32.34 | Infrastructure provisioning and verification |

---

## Phases Completed

### Phase 1 – Core Infrastructure Build
- Custom VPC with public/private subnet segmentation
- Internet Gateway with route table scoped to public subnet only
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
