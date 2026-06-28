\# Cloud Security Remediation Guide



\## IAM Remediation



\### Enable Root MFA



Enable MFA for the AWS root account and avoid using root for daily operations.



\### Require IAM User MFA



For IAM users, require MFA or migrate human access to centralized identity.



\### Strengthen Password Policy



Recommended controls:



\- Minimum password length of 12 or higher

\- Require uppercase characters

\- Require lowercase characters

\- Require numbers

\- Require symbols

\- Rotate or remove unused access keys



\### Review Overly Permissive IAM Policies



Avoid:



```json

{

&#x20; "Effect": "Allow",

&#x20; "Action": "\*",

&#x20; "Resource": "\*"

}

