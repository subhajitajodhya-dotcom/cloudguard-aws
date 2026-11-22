"""Account-level rules (root user and audit logging)."""

from __future__ import annotations

from app.scanner.models import Finding
from app.scanner.registry import ScanContext, rule


@rule("ACC-001", "Root user has no access keys")
def root_access_keys(ctx: ScanContext) -> list[Finding]:
    summary = ctx.client("iam").get_account_summary()["SummaryMap"]
    if summary.get("AccountAccessKeysPresent", 0) > 0:
        return [
            Finding(
                rule_id="ACC-001",
                title="Root account has access keys",
                severity="CRITICAL",
                resource="account:root",
                description="Root keys have unlimited power and cannot be restricted.",
                remediation="Delete the root access keys and use IAM users or roles instead.",
            )
        ]
    return []


@rule("ACC-002", "Root user has MFA enabled")
def root_mfa(ctx: ScanContext) -> list[Finding]:
    summary = ctx.client("iam").get_account_summary()["SummaryMap"]
    if summary.get("AccountMFAEnabled", 0) == 0:
        return [
            Finding(
                rule_id="ACC-002",
                title="Root account has no MFA",
                severity="CRITICAL",
                resource="account:root",
                description="The root user can sign in with a password only.",
                remediation="Enable MFA on the root user.",
            )
        ]
    return []


@rule("ACC-003", "CloudTrail is enabled and logging")
def cloudtrail_enabled(ctx: ScanContext) -> list[Finding]:
    cloudtrail = ctx.client("cloudtrail")
    trails = cloudtrail.describe_trails()["trailList"]
    for trail in trails:
        status = cloudtrail.get_trail_status(Name=trail["TrailARN"])
        if status.get("IsLogging"):
            return []
    return [
        Finding(
            rule_id="ACC-003",
            title="No active CloudTrail trail",
            severity="HIGH",
            resource="account:cloudtrail",
            description="Without CloudTrail, API activity in the account is not recorded.",
            remediation="Create a trail that logs all regions and turn logging on.",
        )
    ]
