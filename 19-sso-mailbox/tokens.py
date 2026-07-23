"""
tokens.py — OIDC tokens, signed with RS256 (asymmetric).

Two distinct tokens come out of an OIDC login:

  * ACCESS TOKEN — authorization: lets the client call the resource server.
    `aud` = the API. The client should treat it as opaque.

  * ID TOKEN — authentication: a signed statement *to the client* about who the
    user is. `aud` = the client_id. The client verifies it (signature via JWKS,
    `iss`, `aud`, `exp`, and the `nonce` it sent) and reads the identity claims.

Both are signed with the RSA private key (RS256) and name the key via `kid`, so
verifiers can fetch the matching public key from the JWKS endpoint.
"""

import os
import time

import jwt  # PyJWT

import crypto_keys

ALG = "RS256"
# The issuer identifies THIS provider; it must match the discovery document and
# is checked by clients. Defaults to the local dev URL.
ISS = os.environ.get("OIDC_ISSUER", "http://127.0.0.1:5000")
API_AUD = "identity-19-mailbox-api"
ACCESS_TTL = int(os.environ.get("ACCESS_TTL", "600"))   # 10 min
ID_TTL = int(os.environ.get("ID_TTL", "600"))


def _headers():
    return {"kid": crypto_keys.KID}


# --- access token (authorization) -------------------------------------------

def issue_access_token(user_id: int, client_id: str, scope: str) -> tuple[str, int]:
    now = int(time.time())
    payload = {
        "iss": ISS, "aud": API_AUD, "sub": str(user_id),
        "client_id": client_id, "scope": scope,
        "iat": now, "exp": now + ACCESS_TTL,
    }
    return jwt.encode(payload, crypto_keys.PRIVATE_KEY, algorithm=ALG,
                      headers=_headers()), ACCESS_TTL


def verify_access_token(token: str) -> dict:
    return jwt.decode(token, crypto_keys.PUBLIC_KEY, algorithms=[ALG],
                      audience=API_AUD, issuer=ISS)


# --- id token (authentication) ----------------------------------------------

def issue_id_token(user, client_id: str, nonce: str, scopes: list[str]) -> str:
    now = int(time.time())
    payload = {
        "iss": ISS,
        "sub": str(user["id"]),
        "aud": client_id,          # the id_token is FOR the client
        "iat": now,
        "exp": now + ID_TTL,
        "auth_time": now,
    }
    if nonce:
        payload["nonce"] = nonce   # binds the token to the client's request
    # Standard claims are released according to consented scopes.
    if "profile" in scopes and user["name"]:
        payload["name"] = user["name"]
    if "email" in scopes:
        payload["email"] = user["email"]
        payload["email_verified"] = True
    return jwt.encode(payload, crypto_keys.PRIVATE_KEY, algorithm=ALG, headers=_headers())


def verify_id_token(token: str, key, client_id: str, nonce: str | None = None) -> dict:
    """Client-side validation. `key` is a public key (e.g. built from a JWK).
    Verifies signature + `iss`/`aud`/`exp`, then the `nonce` the client sent."""
    claims = jwt.decode(token, key, algorithms=[ALG], audience=client_id, issuer=ISS)
    if nonce is not None and claims.get("nonce") != nonce:
        raise ValueError("nonce mismatch")
    return claims
