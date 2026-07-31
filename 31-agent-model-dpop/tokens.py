"""
tokens.py — the model-access token (RS256, asymmetric), DPoP-bound.

A short-lived JWT the agent presents to the gateway. Its power comes from the
bound claims the gateway checks on every call:

  * `aud`      = the gateway's canonical resource id — the token works ONLY here.
  * `scope`    = model:invoke / models:read — least privilege.
  * `exp`      = minutes out — a leaked token expires fast.
  * `cnf.jkt`  = the thumbprint of the agent's DPoP key (RFC 9449) — the token is
                 **sender-constrained**: usable only by whoever holds that private
                 key, so a *stolen* token is inert. This is what 31 adds over 30.

Signed with the AS private key and named by `kid`, so the gateway verifies with
the published JWKS and holds no minting secret. There is no `sub` user here:
this is the client_credentials grant, so the *agent* (client) is the subject.
On-behalf-of-a-user delegation is mechanism 32.
"""

import time

import jwt  # PyJWT

import config
import crypto_keys

ALG = "RS256"


def issue_access_token(client_id: str, scope: str, audience: str,
                       jkt: str | None = None,
                       ttl: int = config.ACCESS_TTL) -> tuple[str, int]:
    now = int(time.time())
    payload = {
        "iss": config.ISSUER,
        "aud": audience,           # bound to the requested resource (RFC 8707)
        "sub": client_id,          # the agent itself is the subject
        "client_id": client_id,
        "scope": scope,
        "iat": now,
        "exp": now + ttl,
    }
    if jkt is not None:
        payload["cnf"] = {"jkt": jkt}   # RFC 9449 §6: DPoP key-binding
    return jwt.encode(payload, crypto_keys.PRIVATE_KEY, algorithm=ALG,
                      headers={"kid": crypto_keys.KID}), ttl


def verify_access_token(token: str, audience: str) -> dict:
    """Verify signature (JWKS public key) + issuer + audience + expiry. A wrong
    audience raises jwt.InvalidAudienceError — that rejection is the whole point
    of audience binding: a token minted for another API can't be replayed here."""
    return jwt.decode(
        token, crypto_keys.PUBLIC_KEY, algorithms=[ALG],
        audience=audience, issuer=config.ISSUER,
        options={"require": ["exp", "aud", "iss"]},
    )
