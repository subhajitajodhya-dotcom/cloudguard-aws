"""Scan worker: reads a scan job from SQS, runs the rules, stores and broadcasts results.

If anything fails the exception is raised, SQS retries the message, and after
three tries it moves to the dead-letter queue. Scans are safe to re-run, because
finding ids are stable (see Finding.finding_id).
"""

from __future__ import annotations

import json
import logging
import os

import boto3

from app.api.common import new_scan_id, now_iso
from app.api.store import Store
from app.api.ws import broadcast, management_client
from app.scanner.models import compute_score
from app.scanner.runner import run_scan
from app.scanner.session import account_id_of, make_session

logger = logging.getLogger()
logger.setLevel(logging.INFO)

MAX_FINDING_EVENTS = 50  # do not flood the dashboard on a first scan
HIGH = {"HIGH", "CRITICAL"}


def process_scan(message: dict, store: Store, ws_client, sfn_client=None,
                 sfn_arn: str | None = None, regions: list[str] | None = None,
                 session_factory=make_session) -> dict:
    scan_id = message.get("scan_id") or new_scan_id()
    role_arn = message.get("role_arn")
    regions = regions or [os.environ.get("AWS_REGION", "us-east-1")]

    if store.get_scan(scan_id) is None:  # scheduled scans have no record yet
        store.create_scan(scan_id, requested_by="schedule", role_arn=role_arn)

    store.update_scan(scan_id, status="RUNNING", started_at=now_iso())
    broadcast(store, ws_client, {"type": "scan.started", "scan_id": scan_id})

    try:
        session = session_factory(role_arn=role_arn, region=regions[0])
        account_id = account_id_of(session)
        result = run_scan(session, regions)
        saved = store.save_scan_findings(
            account_id, scan_id, result.findings, trusted_rules=set(result.rules_ok), regions=regions
        )
    except Exception as err:
        store.update_scan(scan_id, status="FAILED", finished_at=now_iso(), error=str(err)[:300])
        broadcast(store, ws_client, {"type": "scan.failed", "scan_id": scan_id})
        raise

    new_ids = set(saved["new_ids"])
    new_findings = [f for f in result.findings if f.finding_id(account_id) in new_ids]
    for finding in new_findings[:MAX_FINDING_EVENTS]:
        broadcast(store, ws_client, {
            "type": "finding.created", "scan_id": scan_id,
            "finding": {**finding.to_dict(), "finding_id": finding.finding_id(account_id)},
        })

    severities = store.open_severities(account_id)
    summary = {
        "account_id": account_id,
        "rules_run": result.rules_run,
        "rules_failed": len(result.errors),
        "findings_found": len(result.findings),
        "new": len(new_ids),
        "fixed": saved["fixed"],
        "open_total": len(severities),
        "score": compute_score(severities),
    }
    store.update_scan(scan_id, status="COMPLETED", finished_at=now_iso(), summary=summary,
                      errors=result.errors)
    broadcast(store, ws_client, {"type": "scan.completed", "scan_id": scan_id, "summary": summary})

    new_high = sum(1 for f in new_findings if f.severity in HIGH)
    if sfn_client and sfn_arn:
        sfn_client.start_execution(
            stateMachineArn=sfn_arn,
            input=json.dumps({"scan_id": scan_id, "account_id": account_id, "new_high": new_high,
                              "open_total": summary["open_total"], "score": summary["score"]}),
        )
    return summary


def handler(event, context=None):
    store = Store(os.environ["TABLE_NAME"])
    ws_client = management_client(os.environ["WS_ENDPOINT"])
    sfn_arn = os.environ.get("SFN_ARN")
    sfn_client = boto3.client("stepfunctions") if sfn_arn else None
    regions = [r.strip() for r in os.environ.get("SCAN_REGIONS", "").split(",") if r.strip()] or None
    for record in event.get("Records", []):
        message = json.loads(record["body"])
        logger.info("Scan job %s", message.get("scan_id"))
        process_scan(message, store, ws_client, sfn_client, sfn_arn, regions)
    return {"processed": len(event.get("Records", []))}
