# Cloud Security Posture Assessment Report

## Executive Summary

This report summarizes a read-only AWS cloud security posture assessment.

The assessment reviewed identity, access management, storage exposure, encryption, network exposure, logging, and default cloud resource posture.

**Assessment Time:** 2026-06-28 01:09:37  
**Overall Risk Score:** 1.8  
**Overall Risk Rating:** Low  

## Findings Summary

- Passed controls: 9
- Failed controls: 0
- Warning controls: 1
- Error controls: 0

## Detailed Findings

| Control ID | Control | Service | Status | Risk | Evidence | Recommendation |
|---|---|---|---|---|---|---|
| AWS-001 | AWS identity validated | STS | PASS | Info | Authenticated as ARN arn:aws:iam::323643916892:root; Account 323643916892 | No action required. Redact account identifiers before publishing screenshots. |
| IAM-001 | Root account MFA enabled | IAM | PASS | Critical | AccountMFAEnabled = 1 | No action required. |
| IAM-002 | IAM user MFA reviewed | IAM | PASS | High | No IAM users found | No action required. |
| IAM-003 | Strong IAM password policy configured | IAM | PASS | Medium | Minimum length 12; complexity enabled | No action required. |
| IAM-004 | Customer-managed IAM policies avoid full admin wildcards | IAM | PASS | High | No local customer-managed policies with Action * and Resource * were found | No action required. |
| S3-001 | S3 public access block enabled | S3 | PASS | High | All reviewed buckets have public access block controls | No action required. |
| S3-002 | S3 default encryption enabled | S3 | PASS | Medium | All reviewed buckets have default encryption | No action required. |
| EC2-001 | Security groups avoid unrestricted inbound access | EC2 | PASS | Critical | No unrestricted inbound security group rules found in reviewed regions | No action required. |
| EC2-002 | Default VPCs reviewed | EC2 | WARN | Low | Default VPCs found: ap-south-1:vpc-07256cf148bebefc1, eu-north-1:vpc-0220c7a4fb950bd47, eu-west-3:vpc-098f933126a239c72, eu-west-2:vpc-0849d099b44cf9f4c, eu-west-1:vpc-05217da35b1d68a1c, ap-northeast-3:vpc-08e92955d846d4681, ap-northeast-2:vpc-0e3069099fa9cee6b, ap-northeast-1:vpc-0825559ff9b1af28f, ca-central-1:vpc-028c826672eab34a0, sa-east-1:vpc-08501eccc2a404c89, ap-southeast-1:vpc-0eb1a0a4f132b2870, ap-southeast-2:vpc-0e4dbd20f47787962, eu-central-1:vpc-07a4db3611bbae1dd, us-east-1:vpc-0fa1e2f3bdd2b287a, us-east-2:vpc-0c910bc77b8b921f9, us-west-1:vpc-0c7c5e5e0c9f0f210, us-west-2:vpc-0a07237f50fac5c90 | Review default VPC usage and remove unused default resources where appropriate. |
| LOG-001 | CloudTrail logging enabled | CloudTrail | PASS | High | Active trails: management-events-trail | No action required. |

## Remediation Priorities

### Priority 1: Critical and High Risk Findings

- Resolve unrestricted inbound security group access.
- Enable root account MFA.
- Require MFA for IAM users.
- Validate CloudTrail logging.

### Priority 2: Medium Risk Findings

- Strengthen IAM password policy.
- Enable S3 default encryption.
- Review IAM policies for least privilege.

### Priority 3: Governance Improvements

- Review default VPC usage.
- Maintain tagging standards.
- Repeat cloud posture assessments regularly.

## Security Engineering Value

This assessment demonstrates a repeatable cloud security management workflow: enumerate resources, validate controls, identify misconfigurations, assign risk, and produce remediation guidance.