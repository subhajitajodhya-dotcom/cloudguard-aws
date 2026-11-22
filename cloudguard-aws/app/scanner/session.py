"""Build the AWS session a scan uses, optionally in another account."""

from __future__ import annotations

import boto3


def make_session(role_arn: str | None = None, external_id: str | None = None,
                 region: str | None = None) -> boto3.Session:
    """Return a session for this account, or for another account when role_arn is given.

    The role in the other account must trust this account and have read-only access
    (for example the AWS managed policy SecurityAudit).
    """
    base = boto3.Session(region_name=region)
    if not role_arn:
        return base
    params = {"RoleArn": role_arn, "RoleSessionName": "cloudguard-scan", "DurationSeconds": 900}
    if external_id:
        params["ExternalId"] = external_id
    creds = base.client("sts").assume_role(**params)["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region or base.region_name,
    )


def account_id_of(session: boto3.Session) -> str:
    return session.client("sts").get_caller_identity()["Account"]
