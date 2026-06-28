import csv
import json
from datetime import datetime
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound


REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(exist_ok=True)

CSV_REPORT = REPORTS_DIR / "cloud-security-findings.csv"
MD_REPORT = REPORTS_DIR / "cloud-security-assessment-report.md"


def add_finding(findings, control_id, control, service, status, risk, evidence, recommendation):
    findings.append({
        "control_id": control_id,
        "control": control,
        "service": service,
        "status": status,
        "risk": risk,
        "evidence": str(evidence).replace("\n", " ").strip(),
        "recommendation": recommendation,
    })


def risk_points(risk):
    return {
        "Critical": 25,
        "High": 15,
        "Medium": 8,
        "Low": 3,
        "Info": 0,
    }.get(risk, 0)


def status_weight(status):
    return {
        "FAIL": 1,
        "WARN": 0.6,
        "PASS": 0,
        "INFO": 0,
        "ERROR": 0.5,
    }.get(status, 0)


def calculate_risk_score(findings):
    score = 0
    for finding in findings:
        score += risk_points(finding["risk"]) * status_weight(finding["status"])
    return round(score, 1)


def overall_rating(score):
    if score >= 80:
        return "Critical"
    if score >= 45:
        return "High"
    if score >= 20:
        return "Medium"
    return "Low"


def safe_client(service, region_name=None):
    if region_name:
        return boto3.client(service, region_name=region_name)
    return boto3.client(service)


def check_caller_identity(findings):
    try:
        sts = safe_client("sts")
        identity = sts.get_caller_identity()
        arn = identity.get("Arn", "Unknown")
        account = identity.get("Account", "Unknown")

        add_finding(
            findings,
            "AWS-001",
            "AWS identity validated",
            "STS",
            "PASS",
            "Info",
            f"Authenticated as ARN {arn}; Account {account}",
            "No action required. Redact account identifiers before publishing screenshots.",
        )
    except Exception as error:
        add_finding(
            findings,
            "AWS-001",
            "AWS identity validated",
            "STS",
            "ERROR",
            "High",
            error,
            "Confirm AWS CLI credentials are configured and valid.",
        )


def check_iam_account_summary(findings):
    try:
        iam = safe_client("iam")
        summary = iam.get_account_summary().get("SummaryMap", {})

        account_mfa_enabled = summary.get("AccountMFAEnabled", 0)

        if account_mfa_enabled == 1:
            add_finding(
                findings,
                "IAM-001",
                "Root account MFA enabled",
                "IAM",
                "PASS",
                "Critical",
                "AccountMFAEnabled = 1",
                "No action required.",
            )
        else:
            add_finding(
                findings,
                "IAM-001",
                "Root account MFA enabled",
                "IAM",
                "FAIL",
                "Critical",
                "AccountMFAEnabled = 0",
                "Enable MFA on the AWS root account.",
            )

    except ClientError as error:
        add_finding(
            findings,
            "IAM-001",
            "Root account MFA enabled",
            "IAM",
            "ERROR",
            "Critical",
            error,
            "Ensure the auditing identity has IAM read permissions.",
        )


def check_iam_users_mfa(findings):
    try:
        iam = safe_client("iam")
        paginator = iam.get_paginator("list_users")
        users = []

        for page in paginator.paginate():
            users.extend(page.get("Users", []))

        if not users:
            add_finding(
                findings,
                "IAM-002",
                "IAM user MFA reviewed",
                "IAM",
                "PASS",
                "High",
                "No IAM users found",
                "No action required.",
            )
            return

        users_without_mfa = []

        for user in users:
            username = user["UserName"]
            devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
            if not devices:
                users_without_mfa.append(username)

        if users_without_mfa:
            add_finding(
                findings,
                "IAM-002",
                "IAM users have MFA enabled",
                "IAM",
                "FAIL",
                "High",
                f"Users without MFA: {', '.join(users_without_mfa)}",
                "Require MFA for IAM users or migrate human access to IAM Identity Center.",
            )
        else:
            add_finding(
                findings,
                "IAM-002",
                "IAM users have MFA enabled",
                "IAM",
                "PASS",
                "High",
                "All IAM users reviewed have MFA devices",
                "No action required.",
            )

    except ClientError as error:
        add_finding(
            findings,
            "IAM-002",
            "IAM users have MFA enabled",
            "IAM",
            "ERROR",
            "High",
            error,
            "Ensure the auditing identity has IAM ListUsers and ListMFADevices permissions.",
        )


def check_password_policy(findings):
    try:
        iam = safe_client("iam")
        policy = iam.get_account_password_policy().get("PasswordPolicy", {})
        min_length = policy.get("MinimumPasswordLength", 0)
        require_symbols = policy.get("RequireSymbols", False)
        require_numbers = policy.get("RequireNumbers", False)
        require_uppercase = policy.get("RequireUppercaseCharacters", False)
        require_lowercase = policy.get("RequireLowercaseCharacters", False)

        if (
            min_length >= 12
            and require_symbols
            and require_numbers
            and require_uppercase
            and require_lowercase
        ):
            add_finding(
                findings,
                "IAM-003",
                "Strong IAM password policy configured",
                "IAM",
                "PASS",
                "Medium",
                f"Minimum length {min_length}; complexity enabled",
                "No action required.",
            )
        else:
            add_finding(
                findings,
                "IAM-003",
                "Strong IAM password policy configured",
                "IAM",
                "WARN",
                "Medium",
                json.dumps(policy, default=str),
                "Strengthen password policy or reduce reliance on IAM users.",
            )

    except ClientError as error:
        error_code = error.response.get("Error", {}).get("Code", "")
        if error_code == "NoSuchEntity":
            add_finding(
                findings,
                "IAM-003",
                "Strong IAM password policy configured",
                "IAM",
                "WARN",
                "Medium",
                "No account password policy configured",
                "Configure an IAM password policy or use federated access.",
            )
        else:
            add_finding(
                findings,
                "IAM-003",
                "Strong IAM password policy configured",
                "IAM",
                "ERROR",
                "Medium",
                error,
                "Ensure the auditing identity has IAM password policy read permissions.",
            )


def policy_allows_star(policy_document):
    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        effect = statement.get("Effect", "")
        action = statement.get("Action", [])
        resource = statement.get("Resource", [])

        if isinstance(action, str):
            action = [action]
        if isinstance(resource, str):
            resource = [resource]

        if effect == "Allow" and "*" in action and "*" in resource:
            return True

    return False


def check_overly_permissive_iam_policies(findings):
    try:
        iam = safe_client("iam")
        risky_policies = []

        paginator = iam.get_paginator("list_policies")

        for page in paginator.paginate(Scope="Local"):
            for policy in page.get("Policies", []):
                arn = policy["Arn"]
                version_id = policy["DefaultVersionId"]
                version = iam.get_policy_version(
                    PolicyArn=arn,
                    VersionId=version_id
                )
                document = version["PolicyVersion"]["Document"]

                if policy_allows_star(document):
                    risky_policies.append(policy["PolicyName"])

        if risky_policies:
            add_finding(
                findings,
                "IAM-004",
                "Customer-managed IAM policies avoid full admin wildcards",
                "IAM",
                "FAIL",
                "High",
                f"Policies with Action * and Resource *: {', '.join(risky_policies)}",
                "Replace wildcard permissions with least-privilege actions and resources.",
            )
        else:
            add_finding(
                findings,
                "IAM-004",
                "Customer-managed IAM policies avoid full admin wildcards",
                "IAM",
                "PASS",
                "High",
                "No local customer-managed policies with Action * and Resource * were found",
                "No action required.",
            )

    except ClientError as error:
        add_finding(
            findings,
            "IAM-004",
            "Customer-managed IAM policies avoid full admin wildcards",
            "IAM",
            "ERROR",
            "High",
            error,
            "Ensure IAM policy read permissions are available.",
        )


def check_s3_public_access_and_encryption(findings):
    try:
        s3 = safe_client("s3")
        buckets = s3.list_buckets().get("Buckets", [])

        if not buckets:
            add_finding(
                findings,
                "S3-001",
                "S3 bucket security reviewed",
                "S3",
                "PASS",
                "Medium",
                "No S3 buckets found",
                "No action required.",
            )
            return

        public_access_issues = []
        encryption_issues = []

        for bucket in buckets:
            name = bucket["Name"]

            try:
                pab = s3.get_public_access_block(Bucket=name)
                config = pab.get("PublicAccessBlockConfiguration", {})
                required_flags = [
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                ]

                if not all(config.get(flag, False) for flag in required_flags):
                    public_access_issues.append(name)

            except ClientError:
                public_access_issues.append(name)

            try:
                s3.get_bucket_encryption(Bucket=name)
            except ClientError:
                encryption_issues.append(name)

        if public_access_issues:
            add_finding(
                findings,
                "S3-001",
                "S3 public access block enabled",
                "S3",
                "FAIL",
                "High",
                f"Buckets missing full public access block: {', '.join(public_access_issues)}",
                "Enable S3 Block Public Access on all buckets unless a documented exception exists.",
            )
        else:
            add_finding(
                findings,
                "S3-001",
                "S3 public access block enabled",
                "S3",
                "PASS",
                "High",
                "All reviewed buckets have public access block controls",
                "No action required.",
            )

        if encryption_issues:
            add_finding(
                findings,
                "S3-002",
                "S3 default encryption enabled",
                "S3",
                "WARN",
                "Medium",
                f"Buckets without default encryption detected: {', '.join(encryption_issues)}",
                "Enable default encryption for S3 buckets.",
            )
        else:
            add_finding(
                findings,
                "S3-002",
                "S3 default encryption enabled",
                "S3",
                "PASS",
                "Medium",
                "All reviewed buckets have default encryption",
                "No action required.",
            )

    except ClientError as error:
        add_finding(
            findings,
            "S3-001",
            "S3 bucket security reviewed",
            "S3",
            "ERROR",
            "Medium",
            error,
            "Ensure S3 read permissions are available.",
        )


def get_enabled_regions():
    try:
        ec2 = safe_client("ec2", region_name="us-east-1")
        regions = ec2.describe_regions(AllRegions=False).get("Regions", [])
        return [region["RegionName"] for region in regions]
    except Exception:
        return ["us-east-1"]


def check_security_groups(findings):
    risky_rules = []

    for region in get_enabled_regions():
        try:
            ec2 = safe_client("ec2", region_name=region)
            groups = ec2.describe_security_groups().get("SecurityGroups", [])

            for group in groups:
                group_name = group.get("GroupName", "")
                group_id = group.get("GroupId", "")

                for permission in group.get("IpPermissions", []):
                    from_port = permission.get("FromPort", "All")
                    to_port = permission.get("ToPort", "All")
                    protocol = permission.get("IpProtocol", "Unknown")

                    open_ipv4 = any(
                        ip_range.get("CidrIp") == "0.0.0.0/0"
                        for ip_range in permission.get("IpRanges", [])
                    )
                    open_ipv6 = any(
                        ip_range.get("CidrIpv6") == "::/0"
                        for ip_range in permission.get("Ipv6Ranges", [])
                    )

                    if open_ipv4 or open_ipv6:
                        risky_rules.append(
                            f"{region} {group_name}/{group_id} protocol={protocol} ports={from_port}-{to_port}"
                        )

        except ClientError:
            continue

    if risky_rules:
        add_finding(
            findings,
            "EC2-001",
            "Security groups avoid unrestricted inbound access",
            "EC2",
            "FAIL",
            "Critical",
            "; ".join(risky_rules[:15]),
            "Restrict inbound security group rules to trusted CIDR ranges and required ports only.",
        )
    else:
        add_finding(
            findings,
            "EC2-001",
            "Security groups avoid unrestricted inbound access",
            "EC2",
            "PASS",
            "Critical",
            "No unrestricted inbound security group rules found in reviewed regions",
            "No action required.",
        )


def check_default_vpcs(findings):
    default_vpcs = []

    for region in get_enabled_regions():
        try:
            ec2 = safe_client("ec2", region_name=region)
            vpcs = ec2.describe_vpcs(
                Filters=[{"Name": "isDefault", "Values": ["true"]}]
            ).get("Vpcs", [])

            for vpc in vpcs:
                default_vpcs.append(f"{region}:{vpc.get('VpcId')}")

        except ClientError:
            continue

    if default_vpcs:
        add_finding(
            findings,
            "EC2-002",
            "Default VPCs reviewed",
            "EC2",
            "WARN",
            "Low",
            f"Default VPCs found: {', '.join(default_vpcs)}",
            "Review default VPC usage and remove unused default resources where appropriate.",
        )
    else:
        add_finding(
            findings,
            "EC2-002",
            "Default VPCs reviewed",
            "EC2",
            "PASS",
            "Low",
            "No default VPCs found in reviewed regions",
            "No action required.",
        )


def check_cloudtrail(findings):
    try:
        cloudtrail = safe_client("cloudtrail", region_name="us-east-1")
        trails = cloudtrail.describe_trails(includeShadowTrails=True).get("trailList", [])

        if not trails:
            add_finding(
                findings,
                "LOG-001",
                "CloudTrail configured",
                "CloudTrail",
                "FAIL",
                "High",
                "No CloudTrail trails found",
                "Enable CloudTrail with multi-region logging.",
            )
            return

        active_trails = []
        inactive_trails = []

        for trail in trails:
            name = trail.get("Name")
            arn = trail.get("TrailARN")

            try:
                status = cloudtrail.get_trail_status(Name=arn)
                if status.get("IsLogging", False):
                    active_trails.append(name)
                else:
                    inactive_trails.append(name)
            except ClientError:
                inactive_trails.append(name)

        if active_trails:
            add_finding(
                findings,
                "LOG-001",
                "CloudTrail logging enabled",
                "CloudTrail",
                "PASS",
                "High",
                f"Active trails: {', '.join(active_trails)}",
                "No action required.",
            )
        else:
            add_finding(
                findings,
                "LOG-001",
                "CloudTrail logging enabled",
                "CloudTrail",
                "FAIL",
                "High",
                f"Trails not logging: {', '.join(inactive_trails)}",
                "Start CloudTrail logging and validate log delivery.",
            )

    except ClientError as error:
        add_finding(
            findings,
            "LOG-001",
            "CloudTrail logging enabled",
            "CloudTrail",
            "ERROR",
            "High",
            error,
            "Ensure CloudTrail read permissions are available.",
        )


def write_csv(findings):
    with CSV_REPORT.open("w", newline="", encoding="utf-8") as file:
        fieldnames = [
            "control_id",
            "control",
            "service",
            "status",
            "risk",
            "evidence",
            "recommendation",
        ]
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(findings)


def write_markdown(findings):
    score = calculate_risk_score(findings)
    rating = overall_rating(score)

    counts = {}
    for finding in findings:
        counts[finding["status"]] = counts.get(finding["status"], 0) + 1

    lines = [
        "# Cloud Security Posture Assessment Report",
        "",
        "## Executive Summary",
        "",
        "This report summarizes a read-only AWS cloud security posture assessment.",
        "",
        "The assessment reviewed identity, access management, storage exposure, encryption, network exposure, logging, and default cloud resource posture.",
        "",
        f"**Assessment Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"**Overall Risk Score:** {score}  ",
        f"**Overall Risk Rating:** {rating}  ",
        "",
        "## Findings Summary",
        "",
        f"- Passed controls: {counts.get('PASS', 0)}",
        f"- Failed controls: {counts.get('FAIL', 0)}",
        f"- Warning controls: {counts.get('WARN', 0)}",
        f"- Error controls: {counts.get('ERROR', 0)}",
        "",
        "## Detailed Findings",
        "",
        "| Control ID | Control | Service | Status | Risk | Evidence | Recommendation |",
        "|---|---|---|---|---|---|---|",
    ]

    for finding in findings:
        evidence = finding["evidence"].replace("|", "-")
        recommendation = finding["recommendation"].replace("|", "-")

        lines.append(
            f"| {finding['control_id']} | {finding['control']} | {finding['service']} | "
            f"{finding['status']} | {finding['risk']} | {evidence} | {recommendation} |"
        )

    lines.extend([
        "",
        "## Remediation Priorities",
        "",
        "### Priority 1: Critical and High Risk Findings",
        "",
        "- Resolve unrestricted inbound security group access.",
        "- Enable root account MFA.",
        "- Require MFA for IAM users.",
        "- Validate CloudTrail logging.",
        "",
        "### Priority 2: Medium Risk Findings",
        "",
        "- Strengthen IAM password policy.",
        "- Enable S3 default encryption.",
        "- Review IAM policies for least privilege.",
        "",
        "### Priority 3: Governance Improvements",
        "",
        "- Review default VPC usage.",
        "- Maintain tagging standards.",
        "- Repeat cloud posture assessments regularly.",
        "",
        "## Security Engineering Value",
        "",
        "This assessment demonstrates a repeatable cloud security management workflow: enumerate resources, validate controls, identify misconfigurations, assign risk, and produce remediation guidance.",
    ])

    MD_REPORT.write_text("\n".join(lines), encoding="utf-8")


def main():
    findings = []

    try:
        boto3.session.Session()
        check_caller_identity(findings)
        check_iam_account_summary(findings)
        check_iam_users_mfa(findings)
        check_password_policy(findings)
        check_overly_permissive_iam_policies(findings)
        check_s3_public_access_and_encryption(findings)
        check_security_groups(findings)
        check_default_vpcs(findings)
        check_cloudtrail(findings)

    except (NoCredentialsError, ProfileNotFound) as error:
        add_finding(
            findings,
            "AWS-000",
            "AWS credentials configured",
            "AWS",
            "ERROR",
            "Critical",
            error,
            "Configure AWS CLI credentials before running the auditor.",
        )

    write_csv(findings)
    write_markdown(findings)

    print("\n=== Cloud Security Posture Management Audit ===\n")
    print(f"Findings generated: {len(findings)}")
    print(f"Risk score: {calculate_risk_score(findings)}")
    print(f"Risk rating: {overall_rating(calculate_risk_score(findings))}")
    print("\nReports created:")
    print(f"- {CSV_REPORT}")
    print(f"- {MD_REPORT}")

    print("\nFindings:")
    for finding in findings:
        print(
            f"{finding['status']} | {finding['risk']} | "
            f"{finding['control_id']} | {finding['control']}"
        )


if __name__ == "__main__":
    main()