"""
app.py — a local SIEM webhook receiver: the URL you POST audit events to.

It stands in for a SIEM's HTTP event collector. Endpoints:

    GET  /healthz        liveness check, no auth
    POST /siem/ingest    the SECURED endpoint: verifies the HMAC signature,
                         freshness, and nonce before accepting an event
    POST /vuln/ingest    the SAME sink with verification REMOVED — to show what
                         an unauthenticated webhook lets through (forgery/replay)
    GET  /siem/events    read back what's been stored, so you can see the sink

Accepted events are appended as JSON Lines to a sink file (siem.log for the
secured path, siem.vuln.log for the vulnerable one). Every accept/reject is also
written to receiver.log with its reason. See README.md for the threat model.

The shared HMAC secret comes from SIEM_SECRET (run seed.py to mint one). Because
the secret authenticates every event, the webhook must run over TLS in
production — provide TLS_CERT/TLS_KEY or USE_ADHOC_TLS=1 locally.
"""

import json
import logging
import os

from flask import Flask, jsonify, request

import audit

HERE = os.path.dirname(os.path.abspath(__file__))
SECRET = os.environ.get("SIEM_SECRET", "dev-only-insecure-secret-change-me")
TOLERANCE = int(os.environ.get("SIEM_TOLERANCE", str(audit.DEFAULT_TOLERANCE)))

SINKS = {"secure": os.path.join(HERE, "siem.log"),
         "vuln": os.path.join(HERE, "siem.vuln.log")}

app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    handlers=[logging.FileHandler(os.path.join(HERE, "receiver.log")),
              logging.StreamHandler()],
)
log = logging.getLogger("siem")

# The receiver's replay memory. Its TTL matches the freshness window: a nonce
# only needs remembering for as long as its timestamp could still pass step 3.
_nonces = audit.NonceCache(ttl=TOLERANCE)


def _store(sink: str, event: dict) -> None:
    """Append one event as a JSON line to the named sink (the 'ship to SIEM' step)."""
    with open(SINKS[sink], "a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, separators=(",", ":")) + "\n")


@app.route("/healthz")
def healthz():
    return jsonify(status="ok")


@app.route("/siem/ingest", methods=["POST"])
def ingest():
    """Verify, then store. Verification happens over the RAW request bytes —
    never a re-parse — so the signature covers exactly what arrived."""
    body = request.get_data()                        # raw bytes, as received
    header = request.headers.get(audit.SIG_HEADER, "")
    try:
        audit.verify(SECRET, header, body, tolerance=TOLERANCE,
                     seen_nonce=_nonces.check_and_add)
    except audit.VerifyError as e:
        # One 401 with a short reason; the body is NOT stored — a rejected event
        # must never pollute the trusted audit trail.
        log.warning("reject reason=%s ip=%s bytes=%d",
                    e.reason, request.remote_addr, len(body))
        return jsonify(status="rejected", reason=e.reason), 401

    try:
        event = json.loads(body)
    except ValueError:
        # Signature was valid but the payload isn't JSON — a sender bug, not an
        # attack (only the secret-holder could have signed it). Reject cleanly.
        log.warning("reject reason=bad-json ip=%s", request.remote_addr)
        return jsonify(status="rejected", reason="bad-json"), 400

    _store("secure", event)
    log.info("accept id=%s event=%s actor=%s",
             event.get("id"), event.get("event"), event.get("actor"))
    return jsonify(status="accepted", id=event.get("id")), 202


@app.route("/vuln/ingest", methods=["POST"])
def vuln_ingest():
    """The anti-pattern: an audit webhook with NO verification. It trusts the
    network, so any POST — a forged event, a replayed capture, a tampered body —
    lands in the sink as 'true'. This is what /siem/ingest defends against; it
    exists only to make the attack visible. Bound to localhost, like 20's /vuln."""
    body = request.get_data()
    try:
        event = json.loads(body or b"{}")
    except ValueError:
        event = {"raw": body.decode("utf-8", "replace")}
    _store("vuln", event)
    log.info("vuln-accept (unverified) event=%s", event.get("event"))
    return jsonify(status="accepted", id=event.get("id"), warning="unverified"), 202


@app.route("/siem/events")
def events():
    """Read back a sink so you can see what was stored. `?sink=secure` (default)
    or `?sink=vuln`. Convenience for the demo/tests — a real SIEM has its own UI."""
    sink = request.args.get("sink", "secure")
    if sink not in SINKS:
        return jsonify(error="unknown sink"), 400
    out = []
    try:
        with open(SINKS[sink], encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
    except FileNotFoundError:
        pass
    return jsonify(sink=sink, count=len(out), events=out)


if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG") == "1"

    ssl_context = None
    cert, key = os.environ.get("TLS_CERT"), os.environ.get("TLS_KEY")
    if cert and key:
        ssl_context = (cert, key)
    elif os.environ.get("USE_ADHOC_TLS") == "1":
        ssl_context = "adhoc"

    if SECRET == "dev-only-insecure-secret-change-me":
        log.warning("SIEM_SECRET not set — using an insecure dev default. "
                    "Run seed.py and export SIEM_SECRET before real use.")

    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=debug, ssl_context=ssl_context)
