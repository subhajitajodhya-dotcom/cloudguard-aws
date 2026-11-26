"""WebSocket API: login check on connect, connection tracking, and broadcasting.

Flow: the dashboard opens  wss://.../prod?token=<JWT>.  API Gateway calls the
authorizer below before the connection is accepted. Valid connections are saved
in DynamoDB. The scan worker then pushes live events to every saved connection.
"""

from __future__ import annotations

import logging
import os

import boto3
import jwt
from botocore.exceptions import ClientError

from app.api.auth import VALID_ROLES, parse_groups
from app.api.common import dumps
from app.api.store import Store

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_jwks_client = None
_store: Store | None = None


class InvalidToken(Exception):
    pass


def get_store() -> Store:
    global _store
    if _store is None:
        _store = Store(os.environ["TABLE_NAME"])
    return _store


def get_jwks_client(issuer: str):
    global _jwks_client
    if _jwks_client is None:
        _jwks_client = jwt.PyJWKClient(f"{issuer}/.well-known/jwks.json", cache_keys=True)
    return _jwks_client


def verify_token(token: str, issuer: str, client_id: str, jwks_client) -> dict:
    """Check a Cognito JWT. Returns the claims, or raises InvalidToken."""
    try:
        key = jwks_client.get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            issuer=issuer,
            options={"verify_aud": False, "require": ["exp", "iss", "sub"]},
        )
    except jwt.PyJWTError as err:
        raise InvalidToken(str(err)) from err
    if claims.get("token_use") not in ("id", "access"):
        raise InvalidToken("Wrong token type")
    if client_id not in (claims.get("aud"), claims.get("client_id")):
        raise InvalidToken("Token was issued for another app")
    groups = parse_groups(claims.get("cognito:groups")) & VALID_ROLES
    if not groups:
        raise InvalidToken("User has no CloudGuard role")
    claims["_groups"] = sorted(groups)
    return claims


def _policy(effect: str, resource: str, principal: str = "anonymous", context: dict | None = None) -> dict:
    result = {
        "principalId": principal,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [{"Action": "execute-api:Invoke", "Effect": effect, "Resource": resource}],
        },
    }
    if context:
        result["context"] = context
    return result


def authorizer_handler(event, context=None):
    """REQUEST authorizer for the $connect route."""
    method_arn = event["methodArn"]
    token = (event.get("queryStringParameters") or {}).get("token", "")
    if not token:
        return _policy("Deny", method_arn)
    try:
        claims = verify_token(
            token,
            os.environ["COGNITO_ISSUER"],
            os.environ["COGNITO_CLIENT_ID"],
            get_jwks_client(os.environ["COGNITO_ISSUER"]),
        )
    except InvalidToken as err:
        logger.info("WebSocket login refused: %s", err)
        return _policy("Deny", method_arn)
    username = claims.get("email") or claims.get("cognito:username") or claims["sub"]
    return _policy(
        "Allow", method_arn, principal=claims["sub"],
        context={"username": str(username), "groups": ",".join(claims["_groups"])},
    )


def connect_handler(event, context=None):
    ctx = event["requestContext"]
    auth = ctx.get("authorizer", {}) or {}
    get_store().add_connection(ctx["connectionId"], auth.get("username", "unknown"), auth.get("groups", ""))
    return {"statusCode": 200}


def disconnect_handler(event, context=None):
    get_store().remove_connection(event["requestContext"]["connectionId"])
    return {"statusCode": 200}


def default_handler(event, context=None):
    """Any other message. The dashboard sends "ping" to keep the connection warm."""
    ctx = event["requestContext"]
    client = management_client(f"https://{ctx['domainName']}/{ctx['stage']}")
    try:
        client.post_to_connection(ConnectionId=ctx["connectionId"], Data=dumps({"type": "pong"}).encode())
    except ClientError:
        pass
    return {"statusCode": 200}


def management_client(endpoint_url: str):
    return boto3.client("apigatewaymanagementapi", endpoint_url=endpoint_url)


def broadcast(store: Store, client, message: dict) -> int:
    """Send a message to every open connection. Returns how many received it."""
    data = dumps(message).encode()
    delivered = 0
    for connection_id in store.list_connections():
        try:
            client.post_to_connection(ConnectionId=connection_id, Data=data)
            delivered += 1
        except ClientError as err:
            status = err.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if status == 410 or err.response["Error"]["Code"] == "GoneException":
                store.remove_connection(connection_id)  # the browser closed: clean up
            else:
                logger.warning("Could not send to %s: %s", connection_id, err)
    return delivered
