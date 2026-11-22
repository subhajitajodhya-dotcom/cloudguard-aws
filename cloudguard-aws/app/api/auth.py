"""Authorization: who is calling, and which role do they have?

Authentication (is the token real?) is done by API Gateway with the Cognito JWT
authorizer. This module only reads the verified claims and checks the role.
"""

from __future__ import annotations

import re

ADMIN = "admin"
VIEWER = "viewer"
VALID_ROLES = {ADMIN, VIEWER}

# admin can do everything a viewer can do.
ROLE_ALLOWS = {
    VIEWER: {VIEWER, ADMIN},
    ADMIN: {ADMIN},
}


class Forbidden(Exception):
    """The user is signed in but their role does not allow this action."""


class Unauthorized(Exception):
    """No valid identity on the request."""


def parse_groups(raw) -> set[str]:
    """Turn the cognito:groups claim into a set.

    HTTP API passes list claims as a string like "[admin viewer]", while other
    sources give a real list or a comma separated string. Handle all of them.
    """
    if raw is None:
        return set()
    if isinstance(raw, (list, tuple, set)):
        items = [str(i) for i in raw]
    else:
        items = re.split(r"[\s,\[\]\"']+", str(raw))
    return {i for i in items if i}


def get_claims(event: dict) -> dict:
    return (
        event.get("requestContext", {}).get("authorizer", {}).get("jwt", {}).get("claims", {})
    ) or {}


def get_groups(event: dict) -> set[str]:
    return parse_groups(get_claims(event).get("cognito:groups")) & VALID_ROLES


def get_username(event: dict) -> str:
    claims = get_claims(event)
    for key in ("email", "cognito:username", "username", "sub"):
        if claims.get(key):
            return claims[key]
    return "unknown"


def require_role(event: dict, role: str) -> str:
    """Raise unless the caller has `role` (or a stronger one). Returns the username."""
    if not get_claims(event):
        raise Unauthorized("Missing identity")
    groups = get_groups(event)
    if not groups & ROLE_ALLOWS[role]:
        raise Forbidden(f"The {role} role is required")
    return get_username(event)
