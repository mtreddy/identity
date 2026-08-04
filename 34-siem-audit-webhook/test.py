"""test.py — checks for 34-siem-audit-webhook. Exits nonzero on failure.

Happy path plus the security negatives that justify signing the webhook:
missing/tampered/wrong-key signatures, a stale timestamp, a replayed nonce, and
the /vuln endpoint accepting a forgery the /siem endpoint blocks.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import testlib as T  # noqa: E402

sys.path.insert(0, HERE)
import audit  # noqa: E402

SECRET = "test-shared-siem-secret"


def post(base, path, body: bytes, sig):
    headers = {"Content-Type": "application/json"}
    if sig is not None:
        headers[audit.SIG_HEADER] = sig
    req = urllib.request.Request(base + path, data=body, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def main():
    T.clean(HERE)
    proc, base = T.start_server(HERE, env_extra={"SIEM_SECRET": SECRET})

    def signed(event="auth.login.failed", actor="alice@example.com", **kw):
        body = audit.canonical_body(audit.build_event(event, actor, **kw))
        return body, audit.sign(SECRET, body)

    # 1. Happy path: a well-formed signed event is accepted and stored.
    body, sig = signed(source_ip="203.0.113.7", reason="bad_password")
    st, resp = post(base, "/siem/ingest", body, sig)
    T.check("valid signed event -> 202 accepted",
            st == 202 and resp.get("status") == "accepted", f"{st} {resp}")

    # 2. Missing signature -> rejected.
    body2, _ = signed(event="role.granted", actor="attacker@example.com", role="admin")
    st, resp = post(base, "/siem/ingest", body2, None)
    T.check("no signature -> 401 missing-signature",
            st == 401 and resp.get("reason") == "missing-signature", f"{st} {resp}")

    # 3. Tampered body (valid sig over the ORIGINAL) -> bad-signature.
    body3, sig3 = signed(actor="svc-billing")
    tampered = body3.replace(b"svc-billing", b"svc-evilllll")
    st, resp = post(base, "/siem/ingest", tampered, sig3)
    T.check("tampered body -> 401 bad-signature",
            st == 401 and resp.get("reason") == "bad-signature", f"{st} {resp}")

    # 4. Signed with the WRONG secret -> bad-signature.
    body4 = audit.canonical_body(audit.build_event("token.revoked", "svc-x"))
    st, resp = post(base, "/siem/ingest", body4, audit.sign("wrong-secret", body4))
    T.check("wrong secret -> 401 bad-signature",
            st == 401 and resp.get("reason") == "bad-signature", f"{st} {resp}")

    # 5. Stale timestamp (correctly signed, but far in the past) -> stale-timestamp.
    body5 = audit.canonical_body(audit.build_event("auth.login.failed", "bob@example.com"))
    old = int(time.time()) - 6000
    st, resp = post(base, "/siem/ingest", body5, audit.sign(SECRET, body5, ts=old))
    T.check("stale timestamp -> 401 stale-timestamp",
            st == 401 and resp.get("reason") == "stale-timestamp", f"{st} {resp}")

    # 6. Replay: the exact same valid (body, sig) sent twice -> 2nd is replayed-nonce.
    body6, sig6 = signed(event="token.revoked", actor="svc-billing", key_id="sk_live_1")
    st_a, _ = post(base, "/siem/ingest", body6, sig6)
    st_b, resp_b = post(base, "/siem/ingest", body6, sig6)
    T.check("replayed nonce -> first 202, second 401 replayed-nonce",
            st_a == 202 and st_b == 401 and resp_b.get("reason") == "replayed-nonce",
            f"{st_a} then {st_b} {resp_b}")

    # 7. The secured sink holds ONLY the accepted events (1 and 6), nothing rejected.
    st, resp = T.get_json(base + "/siem/events")
    events = resp.get("events", [])
    types = sorted(e.get("event") for e in events)
    T.check("secure sink stored only accepted events",
            st == 200 and resp.get("count") == 2
            and types == ["auth.login.failed", "token.revoked"], f"{resp}")

    # 8. The vulnerable endpoint accepts the unsigned forgery the secured one blocked.
    st, resp = post(base, "/vuln/ingest", body2, None)
    T.check("/vuln/ingest accepts unsigned forgery (the anti-pattern)",
            st == 202 and resp.get("status") == "accepted", f"{st} {resp}")
    st, resp = T.get_json(base + "/siem/events?sink=vuln")
    T.check("forged 'role.granted admin' landed in the vuln sink",
            resp.get("count") == 1 and resp["events"][0]["event"] == "role.granted",
            f"{resp}")

    T.finish(proc)


if __name__ == "__main__":
    main()
