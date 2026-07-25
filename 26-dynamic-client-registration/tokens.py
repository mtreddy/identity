"""
tokens.py — the access token issued at the end of the flow.

Consistent with mechanism 07: a short-lived HS256 JWT the resource server
verifies statelessly. Here `sub` is the USER (resource owner) who consented,
`client_id` records which app is acting on their behalf, and `scope` is what
they consented to.
"""

import os
import time

import jwt  # PyJWT

JWT_ALG = "HS256"
JWT_ISS = "identity-09-oauth"
JWT_AUD = "identity-09-api"
ACCESS_TTL = int(os.environ.get("ACCESS_TTL", "600"))  # 10 minutes


def _secret() -> str:
    s = os.environ.get("JWT_SECRET")
    if not s:
        raise RuntimeError(
            "JWT_SECRET environment variable is not set.\n"
            'Generate one: export JWT_SECRET="$(python -c \'import secrets;'
            " print(secrets.token_hex(32))')\""
        )
    return s


def issue_access_token(user_id: int, client_id: str, scope: str) -> tuple[str, int]:
    now = int(time.time())
    payload = {
        "iss": JWT_ISS,
        "aud": JWT_AUD,
        "sub": str(user_id),      # the human who authorized this
        "client_id": client_id,   # the app acting on their behalf
        "scope": scope,
        "iat": now,
        "exp": now + ACCESS_TTL,
    }
    return jwt.encode(payload, _secret(), algorithm=JWT_ALG), ACCESS_TTL


def verify_access_token(token: str) -> dict:
    return jwt.decode(
        token,
        _secret(),
        algorithms=[JWT_ALG],   # pin the algorithm (blocks alg:none / confusion)
        audience=JWT_AUD,
        issuer=JWT_ISS,
    )
