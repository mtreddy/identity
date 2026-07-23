"""
tokens.py — certificate-bound JWT access tokens (RFC 8705).

A normal bearer token (mechanisms 07/08) is a pure secret: whoever holds it is
granted access, so a stolen or leaked token can be replayed by anyone.

A *certificate-bound* token is **sender-constrained**. When the client obtains
it over mTLS, we record the client certificate's thumbprint inside the token:

    "cnf": { "x5t#S256": "<base64url SHA-256 of the client cert>" }

On every request the resource server checks that the client presenting the
token (over mTLS) holds the *same* certificate. A token stolen from a log or a
compromised proxy is useless without the matching private key — which never
leaves the legitimate client.

Signed with HS256 here (single issuer+verifier) to keep the focus on the
binding; see mechanism 10 for the RS256/JWKS upgrade.
"""

import os
import time

import jwt  # PyJWT

JWT_ALG = "HS256"
JWT_ISS = "identity-12"
JWT_AUD = "identity-12-api"
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


def issue_access_token(client_id: int, name: str, scope: str,
                       cert_thumbprint: str) -> tuple[str, int]:
    """Issue an access token bound to the client's certificate thumbprint."""
    now = int(time.time())
    payload = {
        "iss": JWT_ISS, "aud": JWT_AUD, "sub": str(client_id),
        "name": name, "scope": scope,
        "iat": now, "exp": now + ACCESS_TTL,
        # The confirmation claim (RFC 7800 / 8705) that binds this token to a cert.
        "cnf": {"x5t#S256": cert_thumbprint},
    }
    return jwt.encode(payload, _secret(), algorithm=JWT_ALG), ACCESS_TTL


def verify_access_token(token: str) -> dict:
    return jwt.decode(token, _secret(), algorithms=[JWT_ALG],
                      audience=JWT_AUD, issuer=JWT_ISS)
