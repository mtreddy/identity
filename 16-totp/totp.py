"""
totp.py — TOTP / HOTP from primitives (RFC 4226 + RFC 6238).

A second factor: "something you have" (a shared secret in an authenticator app)
on top of "something you know" (the password from mechanism 01).

  HOTP(K, C) = truncate(HMAC-SHA1(K, C)) mod 10^digits      (RFC 4226)
  TOTP(K)    = HOTP(K, floor(unixtime / period))            (RFC 6238)

Both sides hold the same secret K; the counter C is derived from the clock, so
no state is exchanged. Verification allows a small ± window for clock skew. We
use SHA-1 and 6 digits / 30s for compatibility with common authenticator apps.
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

PERIOD = 30
DIGITS = 6


def generate_secret(num_bytes: int = 20) -> str:
    """A fresh Base32 secret (no padding), as authenticator apps expect."""
    return base64.b32encode(secrets.token_bytes(num_bytes)).decode().rstrip("=")


def _hotp(secret_b32: str, counter: int, digits: int = DIGITS) -> str:
    # Base32 decode (restore padding), HMAC-SHA1 over the 8-byte counter,
    # then RFC 4226 dynamic truncation.
    key = base64.b32decode(secret_b32 + "=" * ((-len(secret_b32)) % 8))
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    truncated = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10 ** digits)).zfill(digits)


def now_code(secret: str, ts: float | None = None) -> str:
    """The current TOTP code — used to build test codes and to display."""
    if ts is None:
        ts = time.time()
    return _hotp(secret, int(ts // PERIOD))


def verify(secret: str, code: str, ts: float | None = None, window: int = 1) -> bool:
    """Check a submitted code against the current time step ± `window` steps,
    in constant time (per candidate) to avoid leaking via timing."""
    if ts is None:
        ts = time.time()
    if not code or not code.isdigit():
        return False
    current = int(ts // PERIOD)
    for step in range(current - window, current + window + 1):
        if hmac.compare_digest(_hotp(secret, step), code):
            return True
    return False


def provisioning_uri(secret: str, account: str, issuer: str) -> str:
    """The otpauth:// URI an authenticator app imports (usually via QR code)."""
    label = quote(f"{issuer}:{account}")
    return (f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}"
            f"&algorithm=SHA1&digits={DIGITS}&period={PERIOD}")
