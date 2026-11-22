"""Importing this package registers every rule."""

from app.scanner.rules import account_rules, iam_rules, network_rules, s3_rules  # noqa: F401
