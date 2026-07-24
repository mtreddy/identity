"""tokens.py — short-lived HS256 access token (as in mechanism 09)."""

import os
import time

import jwt  # PyJWT

ALG = "HS256"
ISS = "identity-24"
AUD = "identity-24-api"
ACCESS_TTL = int(os.environ.get("ACCESS_TTL", "600"))


def _secret() -> str:
    s = os.environ.get("JWT_SECRET")
    if not s:
        raise RuntimeError("JWT_SECRET is not set.")
    return s


def issue_access_token(user_id: int, client_id: str, scope: str) -> tuple[str, int]:
    now = int(time.time())
    payload = {"iss": ISS, "aud": AUD, "sub": str(user_id), "client_id": client_id,
               "scope": scope, "iat": now, "exp": now + ACCESS_TTL}
    return jwt.encode(payload, _secret(), algorithm=ALG), ACCESS_TTL


def verify_access_token(token: str) -> dict:
    return jwt.decode(token, _secret(), algorithms=[ALG], audience=AUD, issuer=ISS)
