"""
dpop.py — DPoP proofs (RFC 9449): create (client side) and verify (server side).

A DPoP proof is a short-lived JWT the client signs with ITS OWN key and sends in
the `DPoP` header on every request. It proves, per request, that the caller
holds the private key the access token is bound to.

  proof header:  { "typ": "dpop+jwt", "alg": "ES256", "jwk": <public key> }
  proof claims:  { "jti", "htm" (method), "htu" (URL), "iat",
                   "ath" (base64url SHA-256 of the access token, on API calls) }

The access token carries `cnf.jkt` = the RFC 7638 thumbprint of that public key,
so the resource server can tie the two together.

Security checks live in `verify_proof`; read them as the threat model.
"""

import base64
import hashlib
import json
import time
import uuid

import jwt  # PyJWT
from jwt.algorithms import ECAlgorithm

ALLOWED_ALGS = {"ES256"}
DEFAULT_MAX_AGE = 60  # seconds a proof's iat may be from now

# In-memory replay cache of seen jti values. Fine for a single-process demo;
# in production use a shared store (e.g. Redis) with a TTL == the proof max-age.
_seen_jti: set[str] = set()


class DPoPError(Exception):
    """Raised when a DPoP proof is missing or fails any check."""


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 JWK thumbprint (the `jkt`): SHA-256 over the canonical JSON of
    the REQUIRED members only, in lexicographic order, no whitespace."""
    if jwk.get("kty") != "EC":
        raise DPoPError("unsupported key type")
    members = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}
    canonical = json.dumps(members, separators=(",", ":"), sort_keys=True).encode()
    return _b64url(hashlib.sha256(canonical).digest())


def ath(access_token: str) -> str:
    """The `ath` claim: base64url(SHA-256(access token))."""
    return _b64url(hashlib.sha256(access_token.encode("ascii")).digest())


# --- client side ------------------------------------------------------------

def public_jwk(private_key) -> dict:
    """Public JWK (kty/crv/x/y) for an EC private key, via PyJWT."""
    return json.loads(ECAlgorithm.to_jwk(private_key.public_key()))


def create_proof(private_key, htm: str, htu: str, access_token: str | None = None) -> str:
    """Build a DPoP proof JWT signed with the client's private key."""
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": public_jwk(private_key)}
    payload = {
        "jti": uuid.uuid4().hex,
        "htm": htm,
        "htu": htu,
        "iat": int(time.time()),
    }
    if access_token is not None:
        payload["ath"] = ath(access_token)
    return jwt.encode(payload, private_key, algorithm="ES256", headers=header)


# --- server side ------------------------------------------------------------

def verify_proof(proof: str, htm: str, htu: str,
                 access_token: str | None = None, max_age: int = DEFAULT_MAX_AGE) -> str:
    """Verify a DPoP proof and return the key thumbprint (jkt) it was signed
    with. Raises DPoPError on any failure."""
    if not proof:
        raise DPoPError("missing DPoP proof")
    try:
        header = jwt.get_unverified_header(proof)
    except jwt.InvalidTokenError as e:
        raise DPoPError(f"malformed proof: {e}")

    if header.get("typ") != "dpop+jwt":
        raise DPoPError("wrong typ")
    if header.get("alg") not in ALLOWED_ALGS:
        raise DPoPError("disallowed alg")
    jwk = header.get("jwk")
    if not isinstance(jwk, dict) or "d" in jwk:
        raise DPoPError("missing or non-public jwk")  # never accept a private key

    # Signature: verify with the key embedded in the proof itself. (That's safe:
    # we then bind that key to the token via its thumbprint below.)
    try:
        key = ECAlgorithm.from_jwk(json.dumps(jwk))
        claims = jwt.decode(proof, key, algorithms=list(ALLOWED_ALGS))
    except jwt.InvalidTokenError as e:
        raise DPoPError(f"bad signature: {e}")

    if claims.get("htm") != htm:
        raise DPoPError("htm mismatch")
    if claims.get("htu") != htu:
        raise DPoPError("htu mismatch")

    iat = claims.get("iat")
    if not isinstance(iat, int) or abs(time.time() - iat) > max_age:
        raise DPoPError("missing or stale iat")

    jti = claims.get("jti")
    if not jti or jti in _seen_jti:
        raise DPoPError("missing or replayed jti")
    _seen_jti.add(jti)

    if access_token is not None and claims.get("ath") != ath(access_token):
        raise DPoPError("ath mismatch")

    return jwk_thumbprint(jwk)
