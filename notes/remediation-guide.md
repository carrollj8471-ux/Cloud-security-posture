# Cloud Security Remediation Guide

## IAM Remediation

### Enable Root MFA

Enable MFA for the AWS root account and avoid using root for daily operations.

### Require IAM User MFA

For IAM users, require MFA or migrate human access to centralized identity.

### Strengthen Password Policy

Recommended controls:

- Minimum password length of 12 or higher
- Require uppercase characters
- Require lowercase characters
- Require numbers
- Require symbols
- Rotate or remove unused access keys

### Review Overly Permissive IAM Policies

Avoid IAM policies that allow all actions against all resources.

Risky pattern:

- Effect: Allow
- Action: *
- Resource: *

Use least privilege permissions scoped to required services, actions, and resources.

---

## S3 Remediation

### Enable Block Public Access

Enable account-level and bucket-level S3 Block Public Access unless there is a documented exception.

### Enable Encryption

Enable default encryption for all S3 buckets.

---

## Network Remediation

### Restrict Security Groups

Avoid unrestricted inbound rules from:

- 0.0.0.0/0
- ::/0

Especially for:

- 22 SSH
- 3389 RDP
- 3306 MySQL
- 5432 PostgreSQL
- All traffic

Restrict access to trusted IP ranges, VPNs, or private networks.

---

## Logging Remediation

### Enable CloudTrail

Enable CloudTrail and confirm that logging is active.

Recommended practices:

- Multi-region trail
- Log file validation
- Centralized S3 log bucket
- Restricted access to logs
- Integration with SIEM or detection platform

---

## Governance Remediation

### Review Default VPCs

Remove unused default VPC resources or document approved usage.

### Repeat Assessments

Run the auditor after remediation to validate improvement.
