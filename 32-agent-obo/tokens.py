"""
tokens.py — two JWTs, both RS256-signed by the AS: the model-access token the
agent presents to the gateway, and the **user (subject) token** it exchanges.

**Access token** (agent → gateway). Its power is the bound claims the gateway
checks on every call:

  * `aud`               = the gateway's canonical resource id — works ONLY here.
  * `scope`             = model:invoke / models:read — least privilege.
  * `exp`               = minutes out — a leaked token expires fast.
  * `cnf.jkt`           = the agent's DPoP-key thumbprint (RFC 9449) — the token
                          is sender-constrained; a *stolen* token is inert (30/31).
  * `sub` / `act`       = **who the token is for**. For plain `client_credentials`
                          `sub` is the agent itself. For an **on-behalf-of** token
                          (RFC 8693 token exchange, what 32 adds) `sub` is the
                          *user* and `act.sub` is the *agent* acting for them — so
                          the gateway logs and enforces the delegation chain.
  * `authorized_models` = the model set the delegated token may reach, computed at
                          issuance as *user ∩ agent* — the agent can never exceed
                          the user it serves. The gateway enforces this claim.

**User token** (the `subject_token`). Represents an authenticated user (an OIDC
login stands in — mechanism 10). It carries the user's own authority (`scope`,
`authorized_models`) and a **`may_act`** claim (RFC 8693 §4.4) naming the ONE
agent the user authorized to act for them. `aud` is the AS itself: a subject
token is presented back to the AS to be exchanged, never to the gateway.
"""

import time

import jwt  # PyJWT

import config
import crypto_keys

ALG = "RS256"


def issue_access_token(subject: str, client_id: str, scope: str, audience: str,
                       *, jkt: str | None = None,
                       act: dict | None = None,
                       authorized_models: str | None = None,
                       ttl: int = config.ACCESS_TTL) -> tuple[str, int]:
    now = int(time.time())
    payload = {
        "iss": config.ISSUER,
        "aud": audience,           # bound to the requested resource (RFC 8707)
        "sub": subject,            # the agent (client_credentials) OR the user (OBO)
        "client_id": client_id,    # always the calling agent (the OAuth client)
        "scope": scope,
        "iat": now,
        "exp": now + ttl,
    }
    if act is not None:
        payload["act"] = act                     # RFC 8693 §4.1: the actor (agent)
    if authorized_models is not None:
        payload["authorized_models"] = authorized_models   # user ∩ agent; RS enforces
    if jkt is not None:
        payload["cnf"] = {"jkt": jkt}            # RFC 9449 §6: DPoP key-binding
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


# --- the user (subject) token — the input to a token exchange ----------------

USER_TOKEN_USE = "user_identity"


def issue_user_token(user_id: str, scope: str, authorized_models: str,
                     may_act: str, ttl: int = config.USER_TTL) -> tuple[str, int]:
    """Mint a token representing an authenticated user. `may_act.sub` pins the one
    agent the user delegated to (RFC 8693 §4.4). `aud` is the AS — this token is
    only ever presented back here to be exchanged, never to the gateway."""
    now = int(time.time())
    payload = {
        "iss": config.ISSUER,
        "aud": config.ISSUER,          # a subject token targets the AS, not the RS
        "sub": user_id,
        "scope": scope,
        "authorized_models": authorized_models,
        "may_act": {"sub": may_act},   # who this user permits to act for them
        "token_use": USER_TOKEN_USE,
        "iat": now,
        "exp": now + ttl,
    }
    return jwt.encode(payload, crypto_keys.PRIVATE_KEY, algorithm=ALG,
                      headers={"kid": crypto_keys.KID}), ttl


def verify_user_token(token: str) -> dict:
    """Verify a subject token: signature + issuer + `aud == AS` + expiry, and that
    it really is a user token (`token_use`). Binding `aud` to the AS (not the
    gateway) is what stops an *access* token from being replayed as a subject
    token to launder authority — it has the wrong audience and wrong token_use."""
    claims = jwt.decode(
        token, crypto_keys.PUBLIC_KEY, algorithms=[ALG],
        audience=config.ISSUER, issuer=config.ISSUER,
        options={"require": ["exp", "aud", "iss"]},
    )
    if claims.get("token_use") != USER_TOKEN_USE:
        raise jwt.InvalidTokenError("not a user token")
    return claims
