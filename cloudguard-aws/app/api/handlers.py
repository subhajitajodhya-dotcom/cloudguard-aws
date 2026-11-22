"""REST API (API Gateway HTTP API, payload format 2.0).

Each route is checked for a role:
    viewer  can read   (admin can too)
    admin   can start scans and resolve findings
"""

from __future__ import annotations

import json
import logging
import os
import re

import boto3

from app.api.auth import ADMIN, VIEWER, Forbidden, Unauthorized, get_groups, get_username, require_role
from app.api.common import new_scan_id, response
from app.api.store import Store
from app.scanner.models import compute_score

logger = logging.getLogger()
logger.setLevel(logging.INFO)

FINDING_ID = re.compile(r"^[0-9a-f]{16}$")
SCAN_ID = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{6}$")
ROLE_ARN = re.compile(r"^arn:aws:iam::\d{12}:role/[\w+=,.@/-]{1,200}$")
SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
STATUSES = {"open", "resolved", "fixed"}

_store: Store | None = None
_sqs = None


def get_store() -> Store:
    global _store
    if _store is None:
        _store = Store(os.environ["TABLE_NAME"])
    return _store


def get_sqs():
    global _sqs
    if _sqs is None:
        _sqs = boto3.client("sqs")
    return _sqs


def _body(event: dict) -> dict:
    raw = event.get("body")
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as err:
        raise ValueError("Body must be valid JSON") from err
    if not isinstance(data, dict):
        raise ValueError("Body must be a JSON object")
    return data


def _allowed_roles() -> set[str]:
    return {r.strip() for r in os.environ.get("ALLOWED_ROLE_ARNS", "").split(",") if r.strip()}


# ---------- routes ----------

def me(event, store):
    user = require_role(event, VIEWER)
    return response(200, {"user": user, "roles": sorted(get_groups(event))})


def list_findings(event, store):
    require_role(event, VIEWER)
    params = event.get("queryStringParameters") or {}
    severity = (params.get("severity") or "").upper() or None
    status = (params.get("status") or "").lower() or None
    if severity and severity not in SEVERITIES:
        return response(400, {"error": "severity must be LOW, MEDIUM, HIGH or CRITICAL"})
    if status and status not in STATUSES:
        return response(400, {"error": "status must be open, resolved or fixed"})
    items = store.list_findings(severity=severity, status=status)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    items.sort(key=lambda i: (order.get(i["severity"], 9), i["resource"]))
    return response(200, {"count": len(items), "findings": items})


def get_finding(event, store):
    require_role(event, VIEWER)
    fid = event["pathParameters"]["id"]
    if not FINDING_ID.match(fid):
        return response(400, {"error": "Invalid finding id"})
    item = store.get_finding(fid)
    return response(200, item) if item else response(404, {"error": "Finding not found"})


def resolve_finding(event, store):
    user = require_role(event, ADMIN)
    fid = event["pathParameters"]["id"]
    if not FINDING_ID.match(fid):
        return response(400, {"error": "Invalid finding id"})
    note = str(_body(event).get("note", ""))
    item = store.resolve_finding(fid, user, note)
    return response(200, item) if item else response(404, {"error": "Finding not found"})


def start_scan(event, store):
    user = require_role(event, ADMIN)
    role_arn = _body(event).get("role_arn")
    if role_arn:
        if not ROLE_ARN.match(str(role_arn)) or role_arn not in _allowed_roles():
            return response(400, {"error": "role_arn is not on the list of allowed accounts"})
    scan_id = new_scan_id()
    store.create_scan(scan_id, requested_by=user, role_arn=role_arn)
    message = {"scan_id": scan_id, "role_arn": role_arn}
    get_sqs().send_message(QueueUrl=os.environ["SCAN_QUEUE_URL"], MessageBody=json.dumps(message))
    return response(202, {"scan_id": scan_id, "status": "QUEUED"})


def list_scans(event, store):
    require_role(event, VIEWER)
    return response(200, {"scans": store.list_scans(limit=10)})


def get_scan(event, store):
    require_role(event, VIEWER)
    sid = event["pathParameters"]["id"]
    if not SCAN_ID.match(sid):
        return response(400, {"error": "Invalid scan id"})
    item = store.get_scan(sid)
    return response(200, item) if item else response(404, {"error": "Scan not found"})


def get_score(event, store):
    require_role(event, VIEWER)
    severities = store.open_severities()
    counts = {s: severities.count(s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    return response(200, {"score": compute_score(severities), "open": len(severities), "by_severity": counts})


ROUTES = {
    "GET /me": me,
    "GET /findings": list_findings,
    "GET /findings/{id}": get_finding,
    "POST /findings/{id}/resolve": resolve_finding,
    "POST /scans": start_scan,
    "GET /scans": list_scans,
    "GET /scans/{id}": get_scan,
    "GET /score": get_score,
}


def handler(event, context=None):
    route = event.get("routeKey")
    fn = ROUTES.get(route)
    if fn is None:
        return response(404, {"error": "Route not found"})
    try:
        return fn(event, get_store())
    except Unauthorized as err:
        return response(401, {"error": str(err)})
    except Forbidden as err:
        logger.info("Forbidden: user=%s route=%s", get_username(event), route)
        return response(403, {"error": str(err)})
    except ValueError as err:
        return response(400, {"error": str(err)})
    except Exception:  # never leak internals to the caller
        logger.exception("Unhandled error on %s", route)
        return response(500, {"error": "Internal error"})
