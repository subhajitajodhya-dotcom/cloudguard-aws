import json
import time

import boto3
import jwt
import pytest
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.asymmetric import rsa
from moto import mock_aws

from app.api import handlers, worker, ws
from app.api.store import Store
from app.scanner.models import Finding

ISSUER = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TEST"
CLIENT = "client123"
ALLOWED = "arn:aws:iam::123456789012:role/CloudGuardScanner"


@pytest.fixture
def table():
    with mock_aws():
        db = boto3.resource("dynamodb", region_name="us-east-1")
        db.create_table(
            TableName="cg",
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                                  {"AttributeName": "sk", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        yield db


@pytest.fixture
def store(table):
    return Store("cg", table)


def finding(rule="S3-001", resource="bucket-a", severity="HIGH", region="global"):
    return Finding(rule, "t", severity, resource, "d", "r", region)


# ---------- store ----------

def test_save_findings_new_seen_fixed(store):
    a, b = finding(resource="a"), finding(resource="b", severity="LOW")
    first = store.save_scan_findings("111", "s1", [a, b], {"S3-001"}, ["us-east-1"])
    assert len(first["new_ids"]) == 2
    second = store.save_scan_findings("111", "s2", [a], {"S3-001"}, ["us-east-1"])
    assert second["new_ids"] == [] and second["fixed"] == 1
    statuses = {i["resource"]: i["status"] for i in store.list_findings()}
    assert statuses == {"a": "open", "b": "fixed"}


def test_failed_rule_does_not_mark_fixed(store):
    store.save_scan_findings("111", "s1", [finding()], {"S3-001"}, ["us-east-1"])
    result = store.save_scan_findings("111", "s2", [], set(), ["us-east-1"])  # rule failed
    assert result["fixed"] == 0
    assert store.list_findings()[0]["status"] == "open"


def test_unscanned_region_not_marked_fixed(store):
    store.save_scan_findings("111", "s1", [finding(region="eu-west-1")], {"S3-001"}, ["eu-west-1"])
    result = store.save_scan_findings("111", "s2", [], {"S3-001"}, ["us-east-1"])
    assert result["fixed"] == 0


def test_resolved_finding_reopens_when_seen_again(store):
    f = finding()
    store.save_scan_findings("111", "s1", [f], {"S3-001"}, ["us-east-1"])
    fid = f.finding_id("111")
    assert store.resolve_finding(fid, "ann", "accepted")["status"] == "resolved"
    store.save_scan_findings("111", "s2", [f], {"S3-001"}, ["us-east-1"])
    assert store.get_finding(fid)["status"] == "open"


def test_connections_roundtrip(store):
    store.add_connection("c1", "ann", "admin")
    assert store.list_connections() == ["c1"]
    assert store.table.get_item(Key={"pk": "CONN", "sk": "c1"})["Item"]["ttl"] > time.time()
    store.remove_connection("c1")
    assert store.list_connections() == []


# ---------- REST handlers ----------

def event(route, groups=None, path=None, body=None, query=None):
    claims = {"email": "ann@example.com"}
    if groups is not None:
        claims["cognito:groups"] = groups
    return {
        "routeKey": route,
        "pathParameters": path,
        "queryStringParameters": query,
        "body": json.dumps(body) if body is not None else None,
        "requestContext": {"authorizer": {"jwt": {"claims": claims}}},
    }


@pytest.fixture
def api(store, monkeypatch):
    monkeypatch.setattr(handlers, "_store", store)
    monkeypatch.setenv("ALLOWED_ROLE_ARNS", ALLOWED)
    monkeypatch.setenv("SCAN_QUEUE_URL", "q")
    sent = []

    class FakeSqs:
        def send_message(self, **kw):
            sent.append(kw)

    monkeypatch.setattr(handlers, "_sqs", FakeSqs())
    return sent


def call(e):
    res = handlers.handler(e)
    return res["statusCode"], json.loads(res["body"]) if res.get("body") else None


def test_no_role_is_forbidden(api):
    assert call(event("GET /findings", groups="[]"))[0] == 403
    assert call(event("GET /findings", groups=None))[0] == 403


def test_viewer_can_read_but_not_write(api):
    assert call(event("GET /findings", groups="[viewer]"))[0] == 200
    assert call(event("GET /score", groups="[viewer]"))[0] == 200
    assert call(event("POST /scans", groups="[viewer]"))[0] == 403
    assert call(event("POST /findings/{id}/resolve", groups="[viewer]", path={"id": "a" * 16}))[0] == 403


def test_admin_can_scan_and_message_is_queued(api):
    status, body = call(event("POST /scans", groups="[admin viewer]"))
    assert status == 202 and body["status"] == "QUEUED"
    assert json.loads(api[0]["MessageBody"])["scan_id"] == body["scan_id"]
    assert call(event("GET /scans", groups="[viewer]"))[1]["scans"][0]["scan_id"] == body["scan_id"]


def test_role_arn_must_be_allowlisted(api):
    ok = call(event("POST /scans", groups="[admin]", body={"role_arn": ALLOWED}))
    bad = call(event("POST /scans", groups="[admin]", body={"role_arn": "arn:aws:iam::999999999999:role/Evil"}))
    assert ok[0] == 202 and bad[0] == 400


def test_validation_and_errors(api):
    assert call(event("GET /findings", groups="viewer", query={"severity": "BAD"}))[0] == 400
    assert call(event("GET /findings/{id}", groups="viewer", path={"id": "../etc"}))[0] == 400
    assert call(event("GET /findings/{id}", groups="viewer", path={"id": "a" * 16}))[0] == 404
    assert call(event("GET /nothing", groups="viewer"))[0] == 404
    bad = event("POST /scans", groups="admin")
    bad["body"] = "{not json"
    assert call(bad)[0] == 400


def test_resolve_flow_and_score(api, store):
    f = finding()
    store.save_scan_findings("111", "s1", [f, finding(resource="x", severity="CRITICAL")], {"S3-001"}, ["us-east-1"])
    assert call(event("GET /score", groups="viewer"))[1]["score"] == 100 - 7 - 10
    fid = f.finding_id("111")
    status, body = call(event("POST /findings/{id}/resolve", groups="admin", path={"id": fid}, body={"note": "ok"}))
    assert status == 200 and body["status"] == "resolved"
    assert call(event("GET /score", groups="viewer"))[1]["score"] == 90
    assert call(event("GET /findings", groups="viewer", query={"severity": "critical"}))[1]["count"] == 1


# ---------- WebSocket: token check ----------

@pytest.fixture(scope="module")
def keys():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class FakeJwks:
    def __init__(self, public_key):
        self.public_key = public_key

    def get_signing_key_from_jwt(self, token):
        class K:
            key = self.public_key
        return K()


def make_token(private_key, **over):
    claims = {"sub": "u1", "iss": ISSUER, "aud": CLIENT, "token_use": "id", "email": "ann@example.com",
              "cognito:groups": ["admin"], "exp": int(time.time()) + 600}
    claims.update(over)
    return jwt.encode({k: v for k, v in claims.items() if v is not None}, private_key, algorithm="RS256")


def verify(keys, **over):
    token = make_token(keys, **over)
    return ws.verify_token(token, ISSUER, CLIENT, FakeJwks(keys.public_key()))


def test_valid_token_passes(keys):
    assert verify(keys)["_groups"] == ["admin"]


@pytest.mark.parametrize("over", [
    {"exp": int(time.time()) - 10},
    {"iss": "https://evil.example.com"},
    {"aud": "other-app"},
    {"token_use": "refresh"},
    {"cognito:groups": []},
    {"cognito:groups": ["somethingelse"]},
])
def test_bad_tokens_rejected(keys, over):
    with pytest.raises(ws.InvalidToken):
        verify(keys, **over)


def test_token_signed_by_other_key_rejected(keys):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = make_token(other)
    with pytest.raises(ws.InvalidToken):
        ws.verify_token(token, ISSUER, CLIENT, FakeJwks(keys.public_key()))


def test_alg_none_rejected(keys):
    token = jwt.encode({"sub": "u", "iss": ISSUER, "aud": CLIENT, "exp": int(time.time()) + 60}, None, algorithm="none")
    with pytest.raises(ws.InvalidToken):
        ws.verify_token(token, ISSUER, CLIENT, FakeJwks(keys.public_key()))


def test_authorizer_denies_without_token(monkeypatch):
    out = ws.authorizer_handler({"methodArn": "arn:x", "queryStringParameters": None})
    assert out["policyDocument"]["Statement"][0]["Effect"] == "Deny"


def test_authorizer_allows_valid_token(keys, monkeypatch):
    monkeypatch.setenv("COGNITO_ISSUER", ISSUER)
    monkeypatch.setenv("COGNITO_CLIENT_ID", CLIENT)
    monkeypatch.setattr(ws, "_jwks_client", FakeJwks(keys.public_key()))
    out = ws.authorizer_handler({"methodArn": "arn:x", "queryStringParameters": {"token": make_token(keys)}})
    assert out["policyDocument"]["Statement"][0]["Effect"] == "Allow"
    assert out["context"] == {"username": "ann@example.com", "groups": "admin"}


# ---------- WebSocket: connections and broadcast ----------

class FakeWs:
    def __init__(self, gone=()):
        self.sent, self.gone = [], set(gone)

    def post_to_connection(self, ConnectionId, Data):
        if ConnectionId in self.gone:
            raise ClientError({"Error": {"Code": "GoneException"}, "ResponseMetadata": {"HTTPStatusCode": 410}}, "Post")
        self.sent.append((ConnectionId, json.loads(Data)))


def test_connect_disconnect_handlers(store, monkeypatch):
    monkeypatch.setattr(ws, "_store", store)
    ev = {"requestContext": {"connectionId": "c9", "authorizer": {"username": "ann", "groups": "admin"}}}
    ws.connect_handler(ev)
    assert store.list_connections() == ["c9"]
    ws.disconnect_handler(ev)
    assert store.list_connections() == []


def test_broadcast_removes_gone_connections(store):
    store.add_connection("live", "a", "admin")
    store.add_connection("dead", "b", "viewer")
    client = FakeWs(gone={"dead"})
    assert ws.broadcast(store, client, {"type": "x"}) == 1
    assert store.list_connections() == ["live"]


# ---------- worker ----------

def fake_session_factory(findings, fail=False):
    """Replaces make_session and the scan itself via monkeypatching run_scan."""
    def factory(role_arn=None, region=None):
        if fail:
            raise RuntimeError("cannot assume role")
        return boto3.Session(region_name="us-east-1")
    return factory


class FakeSfn:
    def __init__(self):
        self.calls = []

    def start_execution(self, **kw):
        self.calls.append(kw)


def patch_scan(monkeypatch, findings, errors=None):
    from app.scanner.runner import ScanResult
    monkeypatch.setattr(worker, "run_scan", lambda session, regions: ScanResult(
        findings=findings, errors=errors or {}, rules_run=11, rules_ok=["S3-001", "NET-001"]))
    monkeypatch.setattr(worker, "account_id_of", lambda s: "111122223333")


def test_worker_happy_path(store, monkeypatch):
    patch_scan(monkeypatch, [finding(severity="CRITICAL"), finding(resource="z", severity="LOW")])
    store.add_connection("c1", "ann", "admin")
    client, sfn = FakeWs(), FakeSfn()
    summary = worker.process_scan({"scan_id": "20260101T000000Z-abcdef"}, store, client, sfn, "arn:sfn",
                                  ["us-east-1"], fake_session_factory([]))
    assert summary["new"] == 2 and summary["score"] == 100 - 10 - 1
    types = [m["type"] for _, m in client.sent]
    assert types[0] == "scan.started" and types[-1] == "scan.completed" and types.count("finding.created") == 2
    assert store.get_scan("20260101T000000Z-abcdef")["status"] == "COMPLETED"
    assert json.loads(sfn.calls[0]["input"])["new_high"] == 1


def test_worker_creates_record_for_scheduled_scan(store, monkeypatch):
    patch_scan(monkeypatch, [])
    worker.process_scan({}, store, FakeWs(), regions=["us-east-1"], session_factory=fake_session_factory([]))
    scan = store.list_scans()[0]
    assert scan["requested_by"] == "schedule" and scan["status"] == "COMPLETED"


def test_worker_failure_marks_failed_and_reraises(store):
    client = FakeWs()
    store.add_connection("c1", "ann", "admin")
    with pytest.raises(RuntimeError):
        worker.process_scan({"scan_id": "20260101T000000Z-abcdef"}, store, client, regions=["us-east-1"],
                            session_factory=fake_session_factory([], fail=True))
    assert store.get_scan("20260101T000000Z-abcdef")["status"] == "FAILED"
    assert client.sent[-1][1]["type"] == "scan.failed"


def test_worker_second_scan_is_idempotent(store, monkeypatch):
    patch_scan(monkeypatch, [finding()])
    sfn = FakeSfn()
    for sid in ("20260101T000000Z-aaaaaa", "20260102T000000Z-bbbbbb"):
        worker.process_scan({"scan_id": sid}, store, FakeWs(), sfn, "arn", ["us-east-1"], fake_session_factory([]))
    assert len(store.list_findings()) == 1
    assert [json.loads(c["input"])["new_high"] for c in sfn.calls] == [1, 0]
