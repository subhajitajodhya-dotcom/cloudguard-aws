import json

import boto3
import pytest
from moto import mock_aws

from app.scanner import rules  # noqa: F401
from app.scanner.models import Finding, compute_score
from app.scanner.registry import RULES, ScanContext
from app.scanner.rules import iam_rules, network_rules
from app.scanner.runner import run_scan

REGION = "us-east-1"


@pytest.fixture
def ctx():
    with mock_aws():
        yield ScanContext(session=boto3.Session(region_name=REGION), regions=[REGION])


@pytest.fixture
def ctx_managed(monkeypatch):
    """Like ctx, but moto also loads the AWS managed policies (for AdministratorAccess)."""
    monkeypatch.setenv("MOTO_IAM_LOAD_MANAGED_POLICIES", "true")
    with mock_aws():
        yield ScanContext(session=boto3.Session(region_name=REGION), regions=[REGION])


def run(rule_id, ctx):
    return RULES[rule_id].fn(ctx)


# ---------- S3 ----------

def test_s3_bucket_without_protection_is_flagged(ctx):
    ctx.client("s3").create_bucket(Bucket="open-bucket")
    assert [f.resource for f in run("S3-001", ctx)] == ["s3://open-bucket"]
    assert [f.resource for f in run("S3-002", ctx)] == ["s3://open-bucket"]


def test_s3_bucket_with_protection_and_https_policy_is_clean(ctx):
    s3 = ctx.client("s3")
    s3.create_bucket(Bucket="safe-bucket")
    s3.put_public_access_block(
        Bucket="safe-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": ["arn:aws:s3:::safe-bucket", "arn:aws:s3:::safe-bucket/*"],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            }
        ],
    }
    s3.put_bucket_policy(Bucket="safe-bucket", Policy=json.dumps(policy))
    assert run("S3-001", ctx) == []
    assert run("S3-002", ctx) == []


# ---------- Network ----------

def _group(ctx, name, permissions):
    ec2 = ctx.client("ec2")
    group_id = ec2.create_security_group(GroupName=name, Description=name)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=group_id, IpPermissions=permissions)
    return group_id


def test_ssh_open_to_world_is_high(ctx):
    _group(ctx, "ssh-open", [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                              "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    findings = run("NET-001", ctx)
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert "SSH" in findings[0].description


def test_all_traffic_open_is_critical(ctx):
    _group(ctx, "all-open", [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    assert [f.severity for f in run("NET-001", ctx)] == ["CRITICAL"]


def test_https_open_to_world_is_fine(ctx):
    _group(ctx, "web", [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                         "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    assert run("NET-001", ctx) == []


def test_ssh_from_private_range_is_fine(ctx):
    _group(ctx, "private", [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                             "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}])
    assert run("NET-001", ctx) == []


def test_exposed_ports_range_logic():
    perm = {"IpProtocol": "tcp", "FromPort": 20, "ToPort": 25}
    assert network_rules.exposed_ports(perm) == [22]
    assert network_rules.exposed_ports({"IpProtocol": "udp", "FromPort": 22, "ToPort": 22}) == []


def test_subnet_with_public_ip_is_flagged(ctx):
    ec2 = ctx.client("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.1.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.1.1.0/24")["Subnet"]["SubnetId"]
    ec2.modify_subnet_attribute(SubnetId=subnet, MapPublicIpOnLaunch={"Value": True})
    found = [f.resource for f in run("NET-002", ctx)]
    assert found == [subnet]


# ---------- IAM ----------

def test_old_access_key_is_flagged(ctx, monkeypatch):
    iam = ctx.client("iam")
    iam.create_user(UserName="alice")
    iam.create_access_key(UserName="alice")
    assert run("IAM-001", ctx) == []  # a brand new key is fine
    monkeypatch.setattr(iam_rules, "MAX_KEY_AGE_DAYS", -1)  # now every key counts as old
    assert len(run("IAM-001", ctx)) == 1


def test_inline_and_attached_policies_on_user(ctx_managed):
    iam = ctx_managed.client("iam")
    iam.create_user(UserName="bob")
    iam.attach_user_policy(UserName="bob", PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    assert len(run("IAM-002", ctx_managed)) == 1
    assert len(run("IAM-003", ctx_managed)) == 1


def test_clean_user_has_no_findings(ctx):
    ctx.client("iam").create_user(UserName="carol")
    assert run("IAM-002", ctx) == []
    assert run("IAM-003", ctx) == []
    assert run("IAM-004", ctx) == []


def test_console_user_without_mfa_is_flagged(ctx):
    iam = ctx.client("iam")
    iam.create_user(UserName="dave")
    iam.create_login_profile(UserName="dave", Password="Str0ng-Passw0rd!", PasswordResetRequired=False)
    assert [f.resource for f in run("IAM-004", ctx)] == ["iam:user/dave"]


# ---------- Account ----------

def test_root_mfa_missing_is_flagged(ctx):
    assert [f.rule_id for f in run("ACC-002", ctx)] == ["ACC-002"]
    assert run("ACC-001", ctx) == []


def test_no_cloudtrail_is_flagged_and_logging_trail_is_clean(ctx):
    assert [f.rule_id for f in run("ACC-003", ctx)] == ["ACC-003"]
    ctx.client("s3").create_bucket(Bucket="trail-logs")
    cloudtrail = ctx.client("cloudtrail")
    cloudtrail.create_trail(Name="main", S3BucketName="trail-logs")
    cloudtrail.start_logging(Name="main")
    assert run("ACC-003", ctx) == []


# ---------- Runner and models ----------

def test_runner_collects_findings_and_survives_a_broken_rule(ctx, monkeypatch):
    ctx.client("s3").create_bucket(Bucket="open-bucket")

    def broken(_ctx):
        raise RuntimeError("boom")

    from app.scanner.registry import Rule

    monkeypatch.setitem(RULES, "TEST-999", Rule("TEST-999", "broken rule", broken))
    result = run_scan(ctx.session, [REGION])
    assert result.rules_run == len(RULES)
    assert "TEST-999" in result.errors
    assert any(f.rule_id == "S3-001" for f in result.findings)


def test_runner_can_limit_rules(ctx):
    result = run_scan(ctx.session, [REGION], only=["ACC-002"])
    assert result.rules_run == 1


def test_finding_id_is_stable_and_account_specific():
    f = Finding("S3-001", "t", "HIGH", "s3://x", "d", "r")
    assert f.finding_id("111") == f.finding_id("111")
    assert f.finding_id("111") != f.finding_id("222")


def test_every_rule_has_a_unique_id_and_description():
    assert len(RULES) >= 10
    assert all(r.description for r in RULES.values())


def test_score_goes_down_with_severity_and_never_below_zero():
    assert compute_score([]) == 100
    assert compute_score(["LOW", "CRITICAL"]) == 89
    assert compute_score(["CRITICAL"] * 20) == 0
