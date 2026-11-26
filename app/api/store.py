"""DynamoDB access. One table, three kinds of items:

    pk=FINDING  sk=<finding id>        a security finding
    pk=SCAN     sk=<scan id>           a scan and its result
    pk=CONN     sk=<connection id>     an open WebSocket connection

Design note: all findings share one partition key. That is fine for the size of
this project (thousands of items). At larger scale, split the key per account.
"""

from __future__ import annotations

import time

import boto3
from boto3.dynamodb.conditions import Key

from app.api.common import now_iso
from app.scanner.models import Finding

OPEN = "open"
RESOLVED = "resolved"
FIXED = "fixed"


class Store:
    def __init__(self, table_name: str, resource=None):
        resource = resource or boto3.resource("dynamodb")
        self.table = resource.Table(table_name)

    # ----- helpers -----
    def _query_all(self, pk: str, forward: bool = True, limit: int | None = None) -> list[dict]:
        items: list[dict] = []
        kwargs = {"KeyConditionExpression": Key("pk").eq(pk), "ScanIndexForward": forward}
        if limit:
            kwargs["Limit"] = limit
        while True:
            page = self.table.query(**kwargs)
            items.extend(page["Items"])
            if limit and len(items) >= limit:
                return items[:limit]
            if "LastEvaluatedKey" not in page:
                return items
            kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]

    def _update(self, pk: str, sk: str, fields: dict) -> None:
        names = {f"#f{i}": k for i, k in enumerate(fields)}
        values = {f":v{i}": v for i, v in enumerate(fields.values())}
        expression = "SET " + ", ".join(f"#f{i} = :v{i}" for i in range(len(fields)))
        self.table.update_item(
            Key={"pk": pk, "sk": sk},
            UpdateExpression=expression,
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
        )

    # ----- scans -----
    def create_scan(self, scan_id: str, requested_by: str, role_arn: str | None = None) -> dict:
        item = {
            "pk": "SCAN",
            "sk": scan_id,
            "scan_id": scan_id,
            "status": "QUEUED",
            "requested_by": requested_by,
            "created_at": now_iso(),
        }
        if role_arn:
            item["role_arn"] = role_arn
        self.table.put_item(Item=item)
        return item

    def update_scan(self, scan_id: str, **fields) -> None:
        self._update("SCAN", scan_id, fields)

    def get_scan(self, scan_id: str) -> dict | None:
        return self.table.get_item(Key={"pk": "SCAN", "sk": scan_id}).get("Item")

    def list_scans(self, limit: int = 10) -> list[dict]:
        return self._query_all("SCAN", forward=False, limit=limit)

    # ----- findings -----
    def list_findings(self, severity: str | None = None, status: str | None = None,
                      account_id: str | None = None) -> list[dict]:
        items = self._query_all("FINDING")
        if severity:
            items = [i for i in items if i["severity"] == severity]
        if status:
            items = [i for i in items if i["status"] == status]
        if account_id:
            items = [i for i in items if i.get("account_id") == account_id]
        return items

    def get_finding(self, finding_id: str) -> dict | None:
        return self.table.get_item(Key={"pk": "FINDING", "sk": finding_id}).get("Item")

    def resolve_finding(self, finding_id: str, user: str, note: str = "") -> dict | None:
        if not self.get_finding(finding_id):
            return None
        self._update("FINDING", finding_id, {
            "status": RESOLVED, "resolved_by": user, "resolved_at": now_iso(), "note": note[:500],
        })
        return self.get_finding(finding_id)

    def save_scan_findings(self, account_id: str, scan_id: str, findings: list[Finding],
                           trusted_rules: set[str], regions: list[str]) -> dict:
        """Store the results of one scan.

        - new problems are added
        - problems seen again stay open (or are re-opened if someone marked them resolved)
        - problems that were open but are gone now are marked "fixed",
          but only for rules that ran successfully and regions that were scanned
        """
        now = now_iso()
        existing = {i["sk"]: i for i in self.list_findings(account_id=account_id)}
        seen: set[str] = set()
        new_ids: list[str] = []

        for finding in findings:
            fid = finding.finding_id(account_id)
            seen.add(fid)
            old = existing.get(fid)
            if old is None:
                new_ids.append(fid)
                self.table.put_item(Item={
                    "pk": "FINDING", "sk": fid, "finding_id": fid, "account_id": account_id,
                    **finding.to_dict(),
                    "status": OPEN, "first_seen": now, "last_seen": now, "last_scan_id": scan_id,
                })
            else:
                self._update("FINDING", fid, {
                    "status": OPEN, "last_seen": now, "last_scan_id": scan_id,
                    "severity": finding.severity, "description": finding.description,
                })

        fixed = 0
        scanned = set(regions) | {"global"}
        for fid, old in existing.items():
            if fid in seen or old["status"] != OPEN:
                continue
            if old["rule_id"] in trusted_rules and old.get("region", "global") in scanned:
                self._update("FINDING", fid, {"status": FIXED, "fixed_at": now, "last_scan_id": scan_id})
                fixed += 1

        return {"new_ids": new_ids, "fixed": fixed}

    def open_severities(self, account_id: str | None = None) -> list[str]:
        return [i["severity"] for i in self.list_findings(status=OPEN, account_id=account_id)]

    # ----- websocket connections -----
    def add_connection(self, connection_id: str, username: str, groups: str) -> None:
        self.table.put_item(Item={
            "pk": "CONN", "sk": connection_id, "username": username, "groups": groups,
            "connected_at": now_iso(),
            "ttl": int(time.time()) + 3 * 3600,  # DynamoDB TTL cleans up lost connections
        })

    def remove_connection(self, connection_id: str) -> None:
        self.table.delete_item(Key={"pk": "CONN", "sk": connection_id})

    def list_connections(self) -> list[str]:
        return [i["sk"] for i in self._query_all("CONN")]
