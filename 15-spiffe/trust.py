"""
trust.py — the trust domain's issuing authority (a tiny stand-in for SPIRE
Server) and its trust bundle.

Holds two long-lived secrets for the trust domain `example.org`:
  * an X.509 CA that signs X.509-SVIDs, and
  * an RSA key that signs JWT-SVIDs.

Publishes the **trust bundle** that relying parties use to verify SVIDs:
  * the CA certificate (for X.509-SVID chains), and
  * a JWKS of the JWT-SVID public key(s).

Keys are generated on first use and cached under svids/.
"""

import base64
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization

import spiffe

TRUST_DOMAIN = os.environ.get("TRUST_DOMAIN", "example.org")
_DIR = Path(os.environ.get("SVID_DIR", Path(__file__).parent / "svids"))
_CA_CERT = _DIR / "ca.pem"
_CA_KEY = _DIR / "ca_key.pem"
_JWT_KEY = _DIR / "jwt_key.pem"


def _load_or_create():
    _DIR.mkdir(exist_ok=True)
    if _CA_CERT.exists() and _CA_KEY.exists() and _JWT_KEY.exists():
        from cryptography import x509
        ca_cert = x509.load_pem_x509_certificate(_CA_CERT.read_bytes())
        ca_key = serialization.load_pem_private_key(_CA_KEY.read_bytes(), password=None)
        jwt_key = serialization.load_pem_private_key(_JWT_KEY.read_bytes(), password=None)
        return ca_cert, ca_key, jwt_key
    ca_cert, ca_key = spiffe.create_ca(TRUST_DOMAIN)
    jwt_key = spiffe.new_key()
    _CA_CERT.write_bytes(spiffe.cert_pem(ca_cert))
    _CA_KEY.write_bytes(spiffe.key_pem(ca_key))
    _JWT_KEY.write_bytes(spiffe.key_pem(jwt_key))
    return ca_cert, ca_key, jwt_key


CA_CERT, CA_KEY, JWT_KEY = _load_or_create()


def _kid() -> str:
    der = JWT_KEY.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b"=").decode()[:16]


KID = _kid()


def spiffe_id(path: str) -> str:
    return f"spiffe://{TRUST_DOMAIN}/{path.lstrip('/')}"


# --- issuance ---------------------------------------------------------------

def issue_x509_svid(sid: str, ttl_hours: int = 24):
    return spiffe.issue_x509_svid(CA_CERT, CA_KEY, sid, ttl_hours)


def issue_jwt_svid(sid: str, audience: str, ttl_seconds: int = 300) -> str:
    return spiffe.issue_jwt_svid(JWT_KEY, KID, sid, audience, ttl_seconds)


# --- trust bundle -----------------------------------------------------------

def bundle_ca_pem() -> bytes:
    return spiffe.cert_pem(CA_CERT)


def _b64url_uint(n: int) -> str:
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jwks() -> dict:
    nums = JWT_KEY.public_key().public_numbers()
    return {"keys": [{
        "kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID,
        "n": _b64url_uint(nums.n), "e": _b64url_uint(nums.e),
    }]}


def jwt_public_key():
    return JWT_KEY.public_key()
