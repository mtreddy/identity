"""
client_example.py — the sender side of the webhook: emit signed audit events.

Pure standard library (urllib) plus this repo's audit.py. It signs each event
with the shared secret and POSTs it to the receiver, then demonstrates the
receiver REJECTING a tampered event and a replayed one — the whole point of
signing a webhook — and finally shows the /vuln endpoint swallowing a forgery.

    SIEM_SECRET=... python client_example.py
    # (start the receiver first: python app.py)
"""

import json
import os
import sys
import urllib.error
import urllib.request

import audit

BASE = os.environ.get("SIEM_BASE", "http://127.0.0.1:5000")
SECRET = os.environ.get("SIEM_SECRET", "dev-only-insecure-secret-change-me")


def post(path: str, body: bytes, sig: str | None):
    """POST raw bytes with an optional signature header. We send the EXACT bytes
    we signed — re-serializing here would break verification on the far side."""
    headers = {"Content-Type": "application/json"}
    if sig is not None:
        headers[audit.SIG_HEADER] = sig
    req = urllib.request.Request(BASE + path, data=body, method="POST",
                                 headers=headers)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.load(resp)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def emit(event: str, actor: str, outcome="success", **detail):
    """Build → canonicalize → sign → send. Returns (status, response, body, sig)."""
    body = audit.canonical_body(audit.build_event(event, actor, outcome, **detail))
    sig = audit.sign(SECRET, body)
    st, resp = post("/siem/ingest", body, sig)
    return st, resp, body, sig


def main():
    print(f"Receiver: {BASE}\n")

    print("1) Two well-formed, signed events (expect 202 accepted):")
    st, resp, _, _ = emit("auth.login.failed", "alice@example.com", "failure",
                          source_ip="203.0.113.7", reason="bad_password", attempt=5)
    print(f"   auth.login.failed -> {st} {resp}")
    st, resp, body, sig = emit("token.revoked", "svc-billing", "success",
                               key_id="sk_live_Xw9a", by="admin@example.com")
    print(f"   token.revoked     -> {st} {resp}")

    print("\n2) Tampered body (signed original, changed a byte) — expect 401 bad-signature:")
    tampered = body.replace(b"svc-billing", b"svc-b1lling")  # same length, one byte changed
    st, resp = post("/siem/ingest", tampered, sig)
    print(f"   tampered          -> {st} {resp}")

    print("\n3) Replay the exact valid event again — expect 401 replayed-nonce:")
    st, resp = post("/siem/ingest", body, sig)
    print(f"   replay            -> {st} {resp}")

    print("\n4) Forge an event with NO signature to /siem/ingest — expect 401 missing-signature:")
    forged = audit.canonical_body(
        audit.build_event("role.granted", "attacker@example.com", "success", role="admin"))
    st, resp = post("/siem/ingest", forged, None)
    print(f"   unsigned          -> {st} {resp}")

    print("\n5) The SAME forgery to /vuln/ingest (verification removed) — it is ACCEPTED:")
    st, resp = post("/vuln/ingest", forged, None)
    print(f"   vuln accepts      -> {st} {resp}")
    print("\n   ^ that is the attack the signed endpoint blocks: an unauthenticated")
    print("     webhook lets anyone write 'admin granted' into the audit trail.")


if __name__ == "__main__":
    if SECRET == "dev-only-insecure-secret-change-me":
        print("warning: SIEM_SECRET not set; using the insecure dev default "
              "(fine for a quick local run only).\n", file=sys.stderr)
    main()
