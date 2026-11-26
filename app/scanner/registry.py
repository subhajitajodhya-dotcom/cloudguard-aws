"""Rule registry: a new security check is one small function with a decorator."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

import boto3

from app.scanner.models import Finding


@dataclass
class ScanContext:
    """What every rule receives: an AWS session and the regions to look at."""

    session: boto3.Session
    regions: list[str]

    def client(self, service: str, region: str | None = None):
        return self.session.client(service, region_name=region or self.regions[0])


RuleFn = Callable[[ScanContext], list[Finding]]


@dataclass
class Rule:
    rule_id: str
    description: str
    fn: RuleFn


RULES: dict[str, Rule] = {}


def rule(rule_id: str, description: str):
    """Register a rule. Usage:

        @rule("S3-001", "S3 bucket blocks public access")
        def check(ctx): ...
    """

    def decorator(fn: RuleFn) -> RuleFn:
        if rule_id in RULES:
            raise ValueError(f"Duplicate rule id {rule_id}")
        RULES[rule_id] = Rule(rule_id, description, fn)
        return fn

    return decorator
