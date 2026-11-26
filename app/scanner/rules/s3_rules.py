"""S3 rules."""

from __future__ import annotations

import json

from botocore.exceptions import ClientError

from app.scanner.models import Finding
from app.scanner.registry import ScanContext, rule

PUBLIC_ACCESS_KEYS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)


def _buckets(ctx: ScanContext) -> list[str]:
    s3 = ctx.client("s3")
    return [b["Name"] for b in s3.list_buckets().get("Buckets", [])]


@rule("S3-001", "S3 bucket blocks all public access")
def block_public_access(ctx: ScanContext) -> list[Finding]:
    s3 = ctx.client("s3")
    findings = []
    for name in _buckets(ctx):
        try:
            config = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            missing = [k for k in PUBLIC_ACCESS_KEYS if not config.get(k)]
        except ClientError as err:
            if err.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
                raise
            missing = list(PUBLIC_ACCESS_KEYS)
        if missing:
            findings.append(
                Finding(
                    rule_id="S3-001",
                    title="S3 bucket does not block all public access",
                    severity="HIGH",
                    resource=f"s3://{name}",
                    description=f"Public access protection is off for: {', '.join(missing)}.",
                    remediation="Enable all four Block Public Access settings on the bucket.",
                )
            )
    return findings


def _enforces_https(policy_text: str) -> bool:
    policy = json.loads(policy_text)
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for st in statements:
        if st.get("Effect") != "Deny":
            continue
        condition = st.get("Condition", {})
        bool_cond = condition.get("Bool", {})
        secure = bool_cond.get("aws:SecureTransport")
        if str(secure).lower() == "false":
            return True
    return False


@rule("S3-002", "S3 bucket policy enforces HTTPS")
def enforce_https(ctx: ScanContext) -> list[Finding]:
    s3 = ctx.client("s3")
    findings = []
    for name in _buckets(ctx):
        try:
            policy_text = s3.get_bucket_policy(Bucket=name)["Policy"]
            ok = _enforces_https(policy_text)
        except ClientError as err:
            if err.response["Error"]["Code"] != "NoSuchBucketPolicy":
                raise
            ok = False
        if not ok:
            findings.append(
                Finding(
                    rule_id="S3-002",
                    title="S3 bucket does not enforce HTTPS",
                    severity="MEDIUM",
                    resource=f"s3://{name}",
                    description="No policy denies requests that use plain HTTP.",
                    remediation="Add a bucket policy that denies requests when aws:SecureTransport is false.",
                )
            )
    return findings
