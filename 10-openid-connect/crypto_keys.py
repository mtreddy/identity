"""
crypto_keys.py — the RSA signing key for OpenID Connect (RS256).

Mechanisms 07-09 signed tokens with a shared secret (HS256): anyone who can
*verify* a token can also *mint* one. OIDC id_tokens are consumed by many
independent clients, so we switch to **asymmetric** signing:

  * the authorization server holds the PRIVATE key and signs (RS256);
  * clients/resource servers verify with the PUBLIC key, which is published at
    the JWKS endpoint (/.well-known/jwks.json) — they hold no minting secret.

Each key has a `kid` (key id) so tokens can name which key signed them, which
is what makes key rotation possible. Here we load a PEM from disk (generating
it on first run); in production this comes from a KMS/HSM.
"""

import base64
import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

_KEY_PATH = Path(
    os.environ.get("OIDC_KEY_FILE", Path(__file__).parent / "oidc_private_key.pem")
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
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": KID,
                "n": _b64url_uint(nums.n),
                "e": _b64url_uint(nums.e),
            }
        ]
    }
