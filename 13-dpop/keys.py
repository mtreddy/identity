"""
keys.py — API key generation and hashing (reused from mechanism 06).

Here the API key authenticates the client to the TOKEN endpoint only. The
access token it hands back is then bound to the client's own DPoP key, so the
API key isn't what protects resource calls — the DPoP proof is.
"""

import hashlib
import secrets

KEY_PREFIX = "sk_live_"


def generate_api_key() -> str:
    return KEY_PREFIX + secrets.token_urlsafe(32)  # 256 bits of randomness


def hash_api_key(full_key: str) -> str:
    # Fast hash is correct for high-entropy secrets (see 06-api-keys/README).
    return hashlib.sha256(full_key.encode("utf-8")).hexdigest()


def display_prefix(full_key: str) -> str:
    return full_key[:12] + "…"
