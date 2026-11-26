"""Data models shared by the scanner and the API."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

# How much each open finding lowers the security score (score starts at 100).
SEVERITY_WEIGHT = {"LOW": 1, "MEDIUM": 3, "HIGH": 7, "CRITICAL": 10}


@dataclass
class Finding:
    """One security problem found on one resource."""

    rule_id: str
    title: str
    severity: str
    resource: str
    description: str
    remediation: str
    region: str = "global"

    def finding_id(self, account_id: str) -> str:
        """Stable id: the same problem on the same resource always gets the same id.

        This makes scans idempotent: running a scan twice never creates duplicates.
        """
        raw = f"{account_id}|{self.rule_id}|{self.resource}|{self.region}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return asdict(self)


def compute_score(open_severities: list[str]) -> int:
    """Security score from 0 to 100. Every open finding subtracts its weight."""
    penalty = sum(SEVERITY_WEIGHT.get(sev, 0) for sev in open_severities)
    return max(0, 100 - penalty)
