"""
device.py — code generation for the Device Authorization Grant (RFC 8628).

Two codes are minted per device-login attempt:

  * device_code — a long, high-entropy secret the DEVICE polls with (stored
    hashed, like an API key).
  * user_code   — a short, HUMAN-typed code shown on the device screen, entered
    by the user in a browser on their phone/laptop. It uses a base-20 charset
    with no vowels or ambiguous characters (RFC 8628 §6.1) so it's easy to read
    and type, e.g. "WDJB-MDLN".
"""

import hashlib
import secrets

# No vowels (avoids real words), no 0/1/I/O-style ambiguity.
_USER_CODE_CHARSET = "BCDFGHJKLMNPQRSTVWXZ"


def generate_device_code() -> str:
    return secrets.token_urlsafe(32)          # 256 bits


def generate_user_code() -> str:
    chars = "".join(secrets.choice(_USER_CODE_CHARSET) for _ in range(8))
    return f"{chars[:4]}-{chars[4:]}"          # WDJB-MDLN


def normalize_user_code(s: str) -> str:
    """Accept user codes with any spacing/casing/dashes and normalize."""
    up = "".join(ch for ch in (s or "").upper() if ch in _USER_CODE_CHARSET)
    return f"{up[:4]}-{up[4:]}" if len(up) == 8 else (s or "").strip().upper()


def hash_code(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()
