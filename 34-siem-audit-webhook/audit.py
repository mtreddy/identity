"""
audit.py — signing & verification for SIEM audit-event webhooks.

An *audit event* is a security-relevant fact your app knows and a SIEM needs:
a login failure, a token revocation, a permission change. This module is the
core of a *webhook* — the app POSTs each event as JSON to a receiver (here, a
local endpoint that logs it; in production, a SIEM's HTTP event collector).

The problem a webhook must solve: the receiver accepts unsolicited POSTs from
the network. Anyone who learns the URL can forge or replay events, poisoning the
very audit trail the SIEM is supposed to trust. So every event we emit is:

  * SIGNED  — HMAC-SHA256 over  timestamp . nonce . raw-body  with a shared
              secret, so the receiver can prove the sender holds the secret and
              that not one byte of the body changed in flight (authenticity +
              integrity).
  * FRESH   — a timestamp the receiver checks against a tolerance window, so an
              old capture can't be re-sent indefinitely.
  * UNIQUE  — a nonce the receiver remembers within that window, so a captured
              event can't be replayed even once inside it (cf. 13-dpop's `jti`).

Why HMAC (symmetric) and not a public-key signature? A webhook is point-to-point
between two services that can share a secret; HMAC is fast, simple, and needs no
PKI. When many independent receivers must verify without holding a signing
secret, you switch to an asymmetric signature (JWS) — noted in the README.

Why SHA-256/HMAC and not bcrypt? The secret is high-entropy (256 bits); a fast
keyed hash is exactly right and can't be brute-forced — same reasoning as the
API-key module (06). Passwords are hashed slowly *because* they're low-entropy.

Everything here is standard library (hmac, hashlib) so the algorithm is visible.
"""

import hashlib
import hmac
import json
import secrets
import time
import uuid
from datetime import datetime, timezone

SIG_SCHEME = "v1"          # names the MAC algorithm so it can be rotated later
SIG_HEADER = "X-Siem-Signature"
DEFAULT_TOLERANCE = 300    # seconds a timestamp may differ from the receiver's "now"


def build_event(event: str, actor: str, outcome: str = "success", **detail) -> dict:
    """Construct a structured audit event.

    `event` is a dotted type (auth.login.failed, token.revoked, role.granted);
    `outcome` is success|failure|error; `detail` carries event-specific fields.
    The `id` makes events idempotent for a downstream store; `ts` is UTC ISO-8601.
    Never put a password or full secret in `detail` — an audit log is read widely.
    """
    return {
        "id": "evt_" + uuid.uuid4().hex,
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event": event,
        "actor": actor,
        "outcome": outcome,
        "detail": detail,
    }


def canonical_body(event: dict) -> bytes:
    """Serialize an event to the exact bytes that are BOTH signed and sent.

    Sender and receiver must agree on these bytes. Crucially, the receiver signs
    the *raw bytes it received* — never a re-serialization — because re-encoding
    can change bytes (key order, spacing, unicode escaping) and a canonicalization
    mismatch is the classic signature-verification bug. `sort_keys` + no spaces
    keeps the sender deterministic.
    """
    return json.dumps(event, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _mac(secret: str, ts: int, nonce: str, body: bytes) -> str:
    """HMAC-SHA256 over  "<ts>.<nonce>." + body. Binding ts and nonce INTO the
    MAC means an attacker can't rewrite them to dodge the freshness/replay checks
    without invalidating the signature."""
    signed_payload = f"{ts}.{nonce}.".encode("utf-8") + body
    return hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()


def sign(secret: str, body: bytes, ts: int | None = None,
         nonce: str | None = None) -> str:
    """Return the X-Siem-Signature header value for `body`:

        t=<unix>,n=<nonce>,v1=<hex-hmac>
    """
    ts = int(time.time()) if ts is None else ts
    nonce = nonce or secrets.token_urlsafe(16)
    return f"t={ts},n={nonce},{SIG_SCHEME}={_mac(secret, ts, nonce, body)}"


def parse_header(value: str) -> dict:
    """Parse 't=..,n=..,v1=..' into a dict; tolerant of ordering and spacing."""
    out = {}
    for part in value.split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


class VerifyError(Exception):
    """Raised when an event fails verification. `.reason` is a short, non-sensitive
    code safe to log and return to the sender (missing-signature, bad-signature,
    stale-timestamp, replayed-nonce, …)."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def verify(secret: str, header_value: str, body: bytes, *,
           tolerance: int = DEFAULT_TOLERANCE, now: int | None = None,
           seen_nonce=None) -> dict:
    """Verify a received event; return {"ts", "nonce"} on success or raise
    VerifyError(reason). Checks run in a deliberate order:

      1. header present and well-formed
      2. signature matches (constant-time)      — authenticity + integrity
      3. timestamp within +/- tolerance of now  — freshness
      4. nonce not seen before in the window    — anti-replay

    The signature is checked BEFORE we trust the timestamp or nonce, precisely
    because the MAC covers them — otherwise an attacker could pick a fresh ts to
    slip past step 3. `seen_nonce(nonce, ts) -> bool` records the nonce and
    returns True if it was already present.
    """
    if not header_value:
        raise VerifyError("missing-signature")
    fields = parse_header(header_value)
    ts_raw = fields.get("t")
    nonce = fields.get("n")
    provided = fields.get(SIG_SCHEME)
    if not (ts_raw and nonce and provided):
        raise VerifyError("malformed-signature")
    try:
        ts = int(ts_raw)
    except ValueError:
        raise VerifyError("malformed-signature")

    # 2. Constant-time compare so we don't leak the correct MAC byte-by-byte.
    expected = _mac(secret, ts, nonce, body)
    if not hmac.compare_digest(expected, provided):
        raise VerifyError("bad-signature")

    # 3. Freshness: reject anything too far from now (past OR future clock skew).
    now = int(time.time()) if now is None else now
    if abs(now - ts) > tolerance:
        raise VerifyError("stale-timestamp")

    # 4. Replay: a signed event captured on the wire is valid until `ts` ages out
    #    of the window — the nonce closes that gap by rejecting the second sight.
    if seen_nonce is not None and seen_nonce(nonce, ts):
        raise VerifyError("replayed-nonce")

    return {"ts": ts, "nonce": nonce}


class NonceCache:
    """Remembers nonces for `ttl` seconds so an event can't be replayed inside the
    freshness window. In-memory and per-process — fine for this single-process
    demo. A real deployment shares it across receiver instances (e.g. Redis with
    a TTL) so a replay to a *different* instance is still caught. See README."""

    def __init__(self, ttl: int = DEFAULT_TOLERANCE):
        self.ttl = ttl
        self._seen: dict[str, int] = {}   # nonce -> expiry (unix)

    def check_and_add(self, nonce: str, ts: int) -> bool:
        """Return True if `nonce` was already seen; otherwise record it. `ts` is
        unused for eviction (we evict by wall-clock expiry) but kept in the
        signature so callers can pass it through from the verified header."""
        now = int(time.time())
        for n, exp in list(self._seen.items()):     # evict expired entries
            if exp <= now:
                del self._seen[n]
        if nonce in self._seen:
            return True
        self._seen[nonce] = now + self.ttl
        return False
