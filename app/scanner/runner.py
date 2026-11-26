"""Run every registered rule and collect the results."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import boto3

from app.scanner import rules  # noqa: F401  (registers the rules)
from app.scanner.models import Finding
from app.scanner.registry import RULES, ScanContext

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    # Rules that could not run (for example missing permissions). The scan still finishes.
    errors: dict[str, str] = field(default_factory=dict)
    rules_run: int = 0
    # Rules that finished without an error. Only these may mark old findings as fixed.
    rules_ok: list[str] = field(default_factory=list)


def run_scan(session: boto3.Session, regions: list[str], only: list[str] | None = None) -> ScanResult:
    ctx = ScanContext(session=session, regions=regions)
    result = ScanResult()
    for rule_id, rule in sorted(RULES.items()):
        if only and rule_id not in only:
            continue
        result.rules_run += 1
        try:
            result.findings.extend(rule.fn(ctx))
            result.rules_ok.append(rule_id)
        except Exception as err:  # one broken rule must not stop the whole scan
            logger.exception("Rule %s failed", rule_id)
            result.errors[rule_id] = str(err)[:300]
    return result
