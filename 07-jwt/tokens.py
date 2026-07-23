"""
tokens.py — issue and verify short-lived JWT access tokens.

The flow (OAuth2 "client-credentials" in spirit):

    API key  --POST /v1/token-->  short-lived signed JWT  --> call the API

A JWT is a signed, self-describing token: the API can verify it with just the
signing secret — no database lookup per request. That statelessness is the
whole point, and the trade-off vs. API keys: a JWT can't be individually
revoked before it expires, so we keep its lifetime short (minutes).

Security choices worth noting:
  * ALGORITHM IS PINNED to HS256 on verify (`algorithms=["HS256"]`). This is
    critical: it blocks the classic "alg: none" forgery and HS/RS confusion
    attacks where an attacker changes the header's algorithm.
  * We verify `aud` (audience) and `iss` (issuer) so a token minted for another
    service/purpose can't be replayed here.
  * `exp` bounds the token's life; `scope` carries least-privilege claims.

HS256 (a shared secret) keeps this example self-contained. In production prefer
an ASYMMETRIC algorithm (RS256/EdDSA): the token endpoint signs with a private
key and resource servers verify with the public key, so verifiers never hold a
secret that can mint tokens.
"""

import os
import time

import jwt  # PyJWT

JWT_ALG = "HS256"
JWT_ISS = "identity-07-jwt"
JWT_AUD = "identity-api"
TOKEN_TTL = int(os.environ.get("TOKEN_TTL", "900"))  # seconds (15 min default)


def _secret() -> str:
    s = os.environ.get("JWT_SECRET")
    if not s:
        raise RuntimeError(
            "JWT_SECRET environment variable is not set.\n"
            'Generate one: export JWT_SECRET="$(python -c \'import secrets;'
            " print(secrets.token_hex(32))')\""
        )
    return s


def issue_token(client_id: int, name: str, scopes: list[str]) -> tuple[str, int]:
    """Mint a signed JWT for a client. Returns (token, ttl_seconds)."""
    now = int(time.time())
    payload = {
        "iss": JWT_ISS,
        "aud": JWT_AUD,
        "sub": str(client_id),          # the machine identity
        "name": name,
        "scope": " ".join(scopes),      # space-delimited, per OAuth2 convention
        "iat": now,
        "exp": now + TOKEN_TTL,
    }
    return jwt.encode(payload, _secret(), algorithm=JWT_ALG), TOKEN_TTL


def verify_token(token: str) -> dict:
    """Verify signature, audience, issuer and expiry. Raises jwt exceptions
    (ExpiredSignatureError / InvalidTokenError) on failure."""
    return jwt.decode(
        token,
        _secret(),
        algorithms=[JWT_ALG],   # pin the algorithm — do NOT trust the header
        audience=JWT_AUD,
        issuer=JWT_ISS,
    )
