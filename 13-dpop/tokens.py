"""
tokens.py — DPoP-bound JWT access tokens.

Same idea as mechanism 12's certificate-bound tokens, but the token is bound to
the client's DPoP KEY instead of its certificate. The confirmation claim is:

    "cnf": { "jkt": "<RFC 7638 SHA-256 thumbprint of the client's public JWK>" }

On each request the resource server checks that the DPoP proof was signed by the
key whose thumbprint equals `cnf.jkt`. A stolen access token is useless without
that private key.

Signed HS256 (single issuer+verifier) to keep the focus on the binding.
"""

import os
import time

import jwt  # PyJWT

JWT_ALG = "HS256"
JWT_ISS = "identity-13"
JWT_AUD = "identity-13-api"
ACCESS_TTL = int(os.environ.get("ACCESS_TTL", "600"))


def _secret() -> str:
    s = os.environ.get("JWT_SECRET")
    if not s:
        raise RuntimeError(
            "JWT_SECRET is not set. Generate one:\n"
            '  export JWT_SECRET="$(python -c \'import secrets;'
            " print(secrets.token_hex(32))')\""
        )
    return s


def issue_access_token(client_id: int, name: str, scope: str, jkt: str) -> tuple[str, int]:
    """Issue an access token bound to a DPoP key thumbprint (jkt)."""
    now = int(time.time())
    payload = {
        "iss": JWT_ISS, "aud": JWT_AUD, "sub": str(client_id),
        "name": name, "scope": scope,
        "iat": now, "exp": now + ACCESS_TTL,
        "cnf": {"jkt": jkt},   # RFC 9449 §6: DPoP key-binding
    }
    return jwt.encode(payload, _secret(), algorithm=JWT_ALG), ACCESS_TTL


def verify_access_token(token: str) -> dict:
    return jwt.decode(token, _secret(), algorithms=[JWT_ALG],
                      audience=JWT_AUD, issuer=JWT_ISS)
