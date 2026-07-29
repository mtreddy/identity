"""
clientauth.py — how the AGENT proves which client it is at the token endpoint.

Two credible techniques (and the reason the demo features them over a static
key): the agent authenticates *per token request*, so there is no long-lived
bearer to leak.

  * client_secret_basic / _post — a shared secret, SHA-256-hashed at rest. The
    baseline; fine, but the secret still exists and can leak.

  * private_key_jwt (RFC 7523) — the agent signs a short-lived JWT assertion
    with its PRIVATE key; the AS verifies it with the client's registered PUBLIC
    key. Nothing secret ever crosses the wire, and a `jti` makes each assertion
    single-use (replay-proof). This is the recommended path.
"""

import jwt  # PyJWT

import db

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


class ClientAuthError(Exception):
    """Raised on any client-authentication failure -> 401 invalid_client. The
    message is intentionally coarse so we don't tell a caller *why* it failed."""


def authenticate_client_secret(client_id: str, secret: str):
    row = db.get_client(client_id)
    if row is None or row["auth_method"] != "client_secret_basic" \
            or not db.verify_client_secret(row, secret):
        raise ClientAuthError("invalid client credentials")
    return row


def authenticate_private_key_jwt(assertion: str, accepted_auds: list[str]):
    # Peek at the unverified issuer to find which client's key to verify with.
    try:
        claimed = jwt.decode(assertion, options={"verify_signature": False})
    except jwt.PyJWTError:
        raise ClientAuthError("malformed client_assertion")
    client_id = claimed.get("iss")
    row = db.get_client(client_id) if client_id else None
    if row is None or row["auth_method"] != "private_key_jwt" or not row["public_key_pem"]:
        raise ClientAuthError("unknown client")

    try:
        # aud must be this AS (its token endpoint or issuer); exp + jti required.
        payload = jwt.decode(
            assertion, row["public_key_pem"], algorithms=["RS256"],
            audience=accepted_auds, options={"require": ["exp", "aud", "jti"]},
        )
    except jwt.PyJWTError as e:
        raise ClientAuthError(f"bad client_assertion: {e}")

    # RFC 7523: for client auth the assertion is self-issued — iss == sub == client.
    if payload.get("iss") != client_id or payload.get("sub") != client_id:
        raise ClientAuthError("assertion iss/sub mismatch")

    # Single-use: reject a replayed assertion (same jti seen before).
    if not db.remember_jti(payload["jti"], payload["exp"]):
        raise ClientAuthError("replayed client_assertion")
    return row
