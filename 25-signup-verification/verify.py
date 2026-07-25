"""
verify.py — the email-verification token primitives.

A verification token is a high-entropy random string that we email to the
address a user claims. Possession of the token (from clicking the link) is the
proof that they control the mailbox. Three properties make it safe:

  * high entropy    — token_urlsafe(32) is ~256 bits, so it can't be guessed.
  * stored hashed   — we keep only SHA-256(token), like an API key (06). Because
                      the token is high-entropy, a fast hash is correct here;
                      bcrypt/scrypt only buy anything for low-entropy passwords.
  * single-use + TTL — enforced in db.consume_verification: the one-shot UPDATE
                      and expires_at make a token redeemable at most once and
                      only for a short window.

Lookup is by the hash (a primary-key hit), and the compare is on the hash, so
there's no secret-dependent branch to time.
"""

import hashlib
import secrets

# Short for a demo so the test can exercise expiry; a real link is ~24h.
DEFAULT_TTL_SECONDS = 24 * 60 * 60


def generate_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
