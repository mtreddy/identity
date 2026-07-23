"""
keys.py — API key generation and hashing.

An API key is a long, random secret that a machine/agent client presents on
every request (no interactive login). Design choices here:

  * FORMAT: a public prefix + high-entropy random secret, e.g.
      sk_live_Xw9...   (43 url-safe chars = 256 bits of randomness)
    The `sk_live_` prefix makes keys greppable/identifiable in code and logs
    (and lets secret scanners spot leaks).

  * STORAGE: we store only a SHA-256 *hash* of the key, never the key itself,
    so a database leak doesn't hand out usable credentials — the same reason
    we hash passwords.

  * WHY SHA-256 AND NOT BCRYPT: bcrypt is deliberately slow to defend
    *low-entropy* human passwords against brute force. An API key is 256 bits
    of randomness — it cannot be brute-forced regardless of hash speed — so a
    fast hash is the right tool. It also keeps per-request auth cheap.
"""

import hashlib
import secrets

KEY_PREFIX = "sk_live_"
REFRESH_PREFIX = "rt_"  # refresh tokens are opaque secrets, like API keys


def generate_api_key() -> str:
    """Return a brand-new API key (the only time the full secret exists)."""
    return KEY_PREFIX + secrets.token_urlsafe(32)  # 32 bytes -> 256 bits


def generate_refresh_token() -> str:
    """A refresh token is also a high-entropy opaque secret (256 bits). Unlike
    a JWT it carries no claims — it's just a handle we look up (and can revoke)
    in the database."""
    return REFRESH_PREFIX + secrets.token_urlsafe(32)


def hash_token(full_token: str) -> str:
    """Hash any opaque token (API key or refresh token) for storage/lookup.
    Deterministic so we can find it by hash; SHA-256 is right for high-entropy
    secrets (see the note above about bcrypt vs. passwords)."""
    return hashlib.sha256(full_token.encode("utf-8")).hexdigest()


# Backwards-compatible alias used by the existing API-key code paths.
def hash_api_key(full_key: str) -> str:
    return hash_token(full_key)


def display_prefix(full_key: str) -> str:
    """A short, non-secret label to identify a key in listings and logs
    without revealing it (e.g. 'sk_live_Xw9a…')."""
    return full_key[:12] + "…"
