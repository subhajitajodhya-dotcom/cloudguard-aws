"""IAM rules (users, keys, policies, MFA)."""

from __future__ import annotations

from datetime import datetime, timezone

from botocore.exceptions import ClientError

from app.scanner.models import Finding
from app.scanner.registry import ScanContext, rule

MAX_KEY_AGE_DAYS = 90
ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def _users(ctx: ScanContext) -> list[dict]:
    iam = ctx.client("iam")
    users = []
    for page in iam.get_paginator("list_users").paginate():
        users.extend(page["Users"])
    return users


@rule("IAM-001", f"Access keys are rotated within {MAX_KEY_AGE_DAYS} days")
def old_access_keys(ctx: ScanContext) -> list[Finding]:
    iam = ctx.client("iam")
    now = datetime.now(timezone.utc)
    findings = []
    for user in _users(ctx):
        for key in iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]:
            if key["Status"] != "Active":
                continue
            age = (now - key["CreateDate"]).days
            if age > MAX_KEY_AGE_DAYS:
                findings.append(
                    Finding(
                        rule_id="IAM-001",
                        title="Access key has not been rotated",
                        severity="MEDIUM",
                        resource=f"iam:user/{user['UserName']}/{key['AccessKeyId']}",
                        description=f"The key is {age} days old (limit {MAX_KEY_AGE_DAYS}).",
                        remediation="Create a new key, switch your tools to it, then delete the old key.",
                    )
                )
    return findings


@rule("IAM-002", "Permissions are given through groups or roles, not directly to users")
def policies_on_users(ctx: ScanContext) -> list[Finding]:
    iam = ctx.client("iam")
    findings = []
    for user in _users(ctx):
        name = user["UserName"]
        attached = iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]
        inline = iam.list_user_policies(UserName=name)["PolicyNames"]
        count = len(attached) + len(inline)
        if count:
            findings.append(
                Finding(
                    rule_id="IAM-002",
                    title="Policies are attached directly to a user",
                    severity="LOW",
                    resource=f"iam:user/{name}",
                    description=f"{count} polic{'y is' if count == 1 else 'ies are'} attached straight to this user.",
                    remediation="Move the permissions to a group or role and add the user to it.",
                )
            )
    return findings


@rule("IAM-003", "No user has full administrator access")
def admin_users(ctx: ScanContext) -> list[Finding]:
    iam = ctx.client("iam")
    findings = []
    for user in _users(ctx):
        name = user["UserName"]
        attached = iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]
        if any(p["PolicyArn"] == ADMIN_POLICY_ARN for p in attached):
            findings.append(
                Finding(
                    rule_id="IAM-003",
                    title="User has the AdministratorAccess policy",
                    severity="HIGH",
                    resource=f"iam:user/{name}",
                    description="Full administrator rights make this user a high-value target.",
                    remediation="Give only the permissions the user needs (least privilege).",
                )
            )
    return findings


@rule("IAM-004", "Console users have MFA enabled")
def console_users_without_mfa(ctx: ScanContext) -> list[Finding]:
    iam = ctx.client("iam")
    findings = []
    for user in _users(ctx):
        name = user["UserName"]
        try:
            iam.get_login_profile(UserName=name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "NoSuchEntity":
                continue  # no console password, so MFA does not apply
            raise
        if not iam.list_mfa_devices(UserName=name)["MFADevices"]:
            findings.append(
                Finding(
                    rule_id="IAM-004",
                    title="Console user has no MFA device",
                    severity="HIGH",
                    resource=f"iam:user/{name}",
                    description="The user can sign in with a password only.",
                    remediation="Enable a virtual or hardware MFA device for the user.",
                )
            )
    return findings
