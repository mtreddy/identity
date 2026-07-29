"""
crypto_keys.py — the authorization server's RSA signing key (RS256).

The AS holds the PRIVATE key and signs access tokens; the model gateway (and
any other verifier) checks them with the PUBLIC key, published at the JWKS
endpoint. Verifiers hold no minting secret — the same asymmetric split used for
OIDC id_tokens in mechanism 10. Each key has a `kid` so tokens name the key that
signed them, which is what makes rotation possible. Loaded from a PEM on disk
(generated on first run); in production this comes from a KMS/HSM.
"""

import base64
import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

_KEY_PATH = Path(
    os.environ.get("AS_KEY_FILE", Path(__file__).parent / "as_signing_key.pem")
)


def _load_or_create():
    if _KEY_PATH.exists():
        return serialization.load_pem_private_key(_KEY_PATH.read_bytes(), password=None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _KEY_PATH.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return key


PRIVATE_KEY = _load_or_create()
PUBLIC_KEY = PRIVATE_KEY.public_key()


def _b64url_uint(n: int) -> str:
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _compute_kid() -> str:
    der = PUBLIC_KEY.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b"=").decode()[:16]


KID = _compute_kid()


def jwks() -> dict:
    """The public key in JWK Set form, for /.well-known/jwks.json."""
    nums = PUBLIC_KEY.public_numbers()
    return {
        "keys": [
            {
                "kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID,
                "n": _b64url_uint(nums.n), "e": _b64url_uint(nums.e),
            }
        ]
    }
