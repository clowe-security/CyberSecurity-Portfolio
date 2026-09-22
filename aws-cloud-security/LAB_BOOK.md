# AWS Cloud Security Lab Book

*Cameron Lowe | Rebuilt as Infrastructure-as-Code | July 2026*

## Overview

This lab book covers a secure AWS environment built entirely through the AWS CLI. The original version of this lab was built through the AWS Management Console; that account was later closed by AWS after its Free Tier credits ran out. This is a full rebuild in a new account, done as Infrastructure-as-Code rather than manual console configuration.

Rebuilding as code was a deliberate choice. It's reproducible, and it demonstrates the ability to stand up cloud security infrastructure programmatically, a skill increasingly expected even at entry-level GRC and SOC Analyst roles.

## Environment Details

| Resource | Identifier |
|---|---|
| AWS Region | us-west-2 (Oregon) |
| VPC ID | vpc-06e1a3e8267ec9477 (Lab-VPC, 10.0.0.0/16) |
| Public Subnet | subnet-0f127eb233c5d6a35 (10.0.1.0/24, us-west-2a) |
| Private Subnet | subnet-0dec64aed1d1dbb8d (10.0.2.0/24, us-west-2a) |
| Internet Gateway | igw-023a2414a2be8c93f (Lab-IGW) |
| Public Route Table | rtb-053a33eeb5c7e6c79 (Public-RT) |
| Security Group | sg-0b5ddd68e9c3c1ff2 (Lab-SG) |
| EC2 Instance | i-0535cb84f33d52162 (Lab-EC2, t3.micro, Amazon Linux 2023) |
| CloudTrail Trail | aws-cloudtrail-lab (multi-region) |
| CloudTrail S3 Bucket | cameron-lab-cloudtrail-logs-371442978944 |
| CloudWatch Log Group | /aws/cloudtrail/lab-trail |
| IAM Service Role | CloudTrail-CloudWatch-Role |
| SNS Topic | Lab-Security-Alerts |

## Phase 1 — Core Network Infrastructure

Goal: a segmented VPC with public and private subnets, an Internet Gateway, and explicit routing, so the network has least-exposure architecture before any compute goes in.

```
aws ec2 create-vpc --cidr-block 10.0.0.0/16 \
--tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=Lab-VPC}]'

aws ec2 create-subnet --vpc-id vpc-06e1a3e8267ec9477 --cidr-block 10.0.1.0/24 \
--tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=Public-Subnet}]'

aws ec2 create-subnet --vpc-id vpc-06e1a3e8267ec9477 --cidr-block 10.0.2.0/24 \
--tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=Private-Subnet}]'

aws ec2 create-internet-gateway \
--tag-specifications 'ResourceType=internet-gateway,Tags=[{Key=Name,Value=Lab-IGW}]'
aws ec2 attach-internet-gateway --internet-gateway-id igw-023a2414a2be8c93f \
--vpc-id vpc-06e1a3e8267ec9477

aws ec2 create-route-table --vpc-id vpc-06e1a3e8267ec9477 \
--tag-specifications 'ResourceType=route-table,Tags=[{Key=Name,Value=Public-RT}]'
aws ec2 create-route --route-table-id rtb-053a33eeb5c7e6c79 \
--destination-cidr-block 0.0.0.0/0 --gateway-id igw-023a2414a2be8c93f
aws ec2 associate-route-table --route-table-id rtb-053a33eeb5c7e6c79 \
--subnet-id subnet-0f127eb233c5d6a35
```

A subnet is public or private only because of the route table attached to it. The private subnet stayed on the VPC's default route table, with no route to the Internet Gateway. The public subnet got its own route table with an explicit 0.0.0.0/0 route to the IGW.

*Screenshot 1 — VPC resource map: Lab-VPC, both subnets, and route table associations*

*Screenshot 2 — Public-RT route table showing the active 0.0.0.0/0 → igw route and the local VPC route*

## Phase 2 — Access Control (Security Group)

Goal: restrict inbound access to the EC2 instance to a single trusted source IP, closing off the common mistake of open (0.0.0.0/0) SSH access.

```
aws ec2 create-security-group --group-name Lab-SG \
--description "Lab security group - SSH restricted" --vpc-id vpc-06e1a3e8267ec9477

aws ec2 authorize-security-group-ingress --group-id sg-0b5ddd68e9c3c1ff2 \
--protocol tcp --port 22 --cidr 203.0.113.10/32
```

The /32 suffix scopes the rule to one host address instead of a range, which is what least-privilege network access actually looks like.

*Screenshot 3 — Lab-SG inbound rules: SSH (TCP/22) restricted to a single /32 source IP (IP redacted for portfolio)*

## Phase 3 — Compute Deployment

Goal: launch a hardened EC2 instance into the public subnet, resolving the AMI dynamically rather than hardcoding an image ID.

```
aws ssm get-parameter \
--name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
--region us-west-2 --query "Parameter.Value" --output text

aws ec2 create-key-pair --key-name Lab-Key --query 'KeyMaterial' --output text \
> ~/.ssh/Lab-Key.pem
chmod 400 ~/.ssh/Lab-Key.pem

aws ec2 run-instances \
--image-id ami-0f6de954b71901fb8 \
--instance-type t3.micro \
--key-name Lab-Key \
--security-group-ids sg-0b5ddd68e9c3c1ff2 \
--subnet-id subnet-0f127eb233c5d6a35 \
--associate-public-ip-address \
--tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=Lab-EC2}]'
```

Resolving the AMI ID through SSM Parameter Store instead of hardcoding it keeps the build current, the same pattern used in Terraform or CloudFormation rather than a value that goes stale.

*Screenshot 4 — Lab-EC2 instance running, 3/3 status checks passed, public IP assigned*

## Phase 4 — Logging: CloudTrail

Goal: full account-level audit logging across all regions, writing to both S3 for durable storage and CloudWatch Logs for real-time alerting.

```
aws s3api create-bucket --bucket cameron-lab-cloudtrail-logs-371442978944 \
--region us-west-2 --create-bucket-configuration LocationConstraint=us-west-2

aws s3api put-bucket-policy --bucket cameron-lab-cloudtrail-logs-371442978944 \
--policy file://cloudtrail-policy.json

aws cloudtrail create-trail --name aws-cloudtrail-lab \
--s3-bucket-name cameron-lab-cloudtrail-logs-371442978944 --is-multi-region-trail
aws cloudtrail start-logging --name aws-cloudtrail-lab
```

Multi-region logging captures API activity account-wide instead of just one region, closing a visibility gap attackers commonly exploit by operating in unmonitored regions.

*Screenshot 5 — aws-cloudtrail-lab trail: multi-region enabled, logging active, S3 destination configured*

## Phase 5 — Detection: CloudWatch Metric Filters, Alarms, and SNS

Goal: turn raw CloudTrail activity into real-time alerts for two high-risk event types: root account console logins and IAM privilege changes.

CloudWatch metric filters read from CloudWatch Logs, not directly from S3. A dedicated IAM role, not the CLI administrative user, was created for CloudTrail to assume, since a person's IAM user can't be used by an AWS service. Services authenticate by assuming a role, not by borrowing a user's credentials.

```
aws logs create-log-group --log-group-name /aws/cloudtrail/lab-trail

# Trust policy: who may assume the role (CloudTrail service only)
aws iam create-role --role-name CloudTrail-CloudWatch-Role \
--assume-role-policy-document file://cloudtrail-trust-policy.json

# Permissions policy: what the role can do once assumed
aws iam put-role-policy --role-name CloudTrail-CloudWatch-Role \
--policy-name CloudTrail-CWL-Policy \
--policy-document file://cloudtrail-cwl-permissions.json

aws cloudtrail update-trail --name aws-cloudtrail-lab \
--cloud-watch-logs-log-group-arn "arn:aws:logs:us-west-2:371442978944:log-group:/aws/cloudtrail/lab-trail:*" \
--cloud-watch-logs-role-arn "arn:aws:iam::371442978944:role/CloudTrail-CloudWatch-Role"
```

**SNS notification topic:**
```
aws sns create-topic --name Lab-Security-Alerts
aws sns subscribe --topic-arn arn:aws:sns:us-west-2:371442978944:Lab-Security-Alerts \
--protocol email --notification-endpoint camdlowe@gmail.com
```

**Detection 1 — Root Account Login**
```
aws logs put-metric-filter --log-group-name /aws/cloudtrail/lab-trail \
--filter-name RootLoginFilter \
--filter-pattern '{ ($.eventName = "ConsoleLogin") && ($.userIdentity.type = "Root") }' \
--metric-transformations metricName=RootLoginCount,metricNamespace=LabSecurityMetrics,metricValue=1

aws cloudwatch put-metric-alarm --alarm-name RootLoginAlarm \
--metric-name RootLoginCount --namespace LabSecurityMetrics \
--statistic Sum --period 300 --threshold 1 \
--comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 \
--alarm-actions arn:aws:sns:us-west-2:371442978944:Lab-Security-Alerts \
--treat-missing-data notBreaching
```

**Detection 2 — IAM Privilege Change**
```
aws logs put-metric-filter --log-group-name /aws/cloudtrail/lab-trail \
--filter-name IAMChangeFilter \
--filter-pattern '{ ($.eventName = "AttachUserPolicy") || ($.eventName = "PutUserPolicy") || ($.eventName = "CreatePolicyVersion") || ($.eventName = "AttachRolePolicy") }' \
--metric-transformations metricName=IAMChangeCount,metricNamespace=LabSecurityMetrics,metricValue=1

aws cloudwatch put-metric-alarm --alarm-name IAMChangeAlarm \
--metric-name IAMChangeCount --namespace LabSecurityMetrics \
--statistic Sum --period 300 --threshold 1 \
--comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 \
--alarm-actions arn:aws:sns:us-west-2:371442978944:Lab-Security-Alerts \
--treat-missing-data notBreaching
```

*Screenshot 6 — Both alarms configured: RootLoginAlarm and IAMChangeAlarm, actions enabled*

*Screenshot 7 — SNS topic Lab-Security-Alerts with confirmed email subscription*

## Phase 6 — Validation & Testing

Goal: prove each detection fires on real, deliberately triggered activity rather than trusting the configuration alone.

**Test 1: IAM Privilege Change.** A disposable IAM user was created and a managed policy attached to it, a real `AttachUserPolicy` call that matches `IAMChangeFilter`.

```
aws iam create-user --user-name test-validation-user
aws iam attach-user-policy --user-name test-validation-user \
--policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
```

`IAMChangeAlarm` went from OK to ALARM within one 5-minute evaluation period, then back to OK once the window passed with no further matching events. The confirmation email came through via SNS.

**Test 2: Root Account Login.** A manual root console login and logout produced a genuine `ConsoleLogin` event with `userIdentity.type = Root`. This event type can't be generated through the CLI, so this had to be done by hand.

`RootLoginAlarm` went from OK to ALARM within one evaluation period, then reset to OK. The confirmation email came through via SNS.

A note on alarm behavior: these alarms are point-in-time, not sticky. With a single evaluation period and `treat-missing-data` set to `notBreaching`, an alarm returns to OK once the window passes without a new matching event. The CloudWatch alarm history is the actual evidence here, not whatever state the alarm happens to show if you check it later.

*Screenshot 8a — RootLoginAlarm history graph: clear transition into ALARM (red) following the root login, then reset to OK*

*Screenshot 8b — IAMChangeAlarm history graph: clear transition into ALARM (red) following the test policy attachment, then reset to OK*

The disposable `test-validation-user` and its attached policy were deleted after the test so no orphaned artifacts were left in the account.

## Final Assessment

This lab covers the full lifecycle of cloud security engineering: network design, least-privilege access control, compute deployment, account-wide audit logging, detection engineering, and validated alerting, rebuilt as Infrastructure-as-Code after the original console-built environment was lost to account closure.

**The AWS Cloud Security Lab is complete. Every phase was executed through the AWS CLI, and both detections (root account login, IAM privilege change) were independently triggered and confirmed through CloudWatch alarm history and SNS email delivery.**
