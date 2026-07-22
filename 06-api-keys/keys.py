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


def generate_api_key() -> str:
    """Return a brand-new API key (the only time the full secret exists)."""
    return KEY_PREFIX + secrets.token_urlsafe(32)  # 32 bytes -> 256 bits


def hash_api_key(full_key: str) -> str:
    """Hash a key for storage / lookup. Deterministic so we can look a key up
    by its hash (unlike a salted password hash)."""
    return hashlib.sha256(full_key.encode("utf-8")).hexdigest()


def display_prefix(full_key: str) -> str:
    """A short, non-secret label to identify a key in listings and logs
    without revealing it (e.g. 'sk_live_Xw9a…')."""
    return full_key[:12] + "…"
