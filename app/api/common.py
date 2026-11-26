"""Small helpers shared by all Lambda handlers."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from decimal import Decimal


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_scan_id() -> str:
    """Sortable id: time first, so the newest scan sorts last."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{uuid.uuid4().hex[:6]}"


def _json_default(value):
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, set):
        return sorted(value)
    raise TypeError(f"Cannot serialise {type(value)}")


def dumps(data) -> str:
    return json.dumps(data, default=_json_default)


def response(status: int, body=None) -> dict:
    """HTTP API (payload v2) response. CORS headers are added by API Gateway."""
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": dumps(body if body is not None else {}),
    }
