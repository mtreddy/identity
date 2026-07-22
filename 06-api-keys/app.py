"""
app.py — a JSON API protected by API-key authentication.

This is machine-to-machine: there is no login form, no cookie, no session.
A client (script, service, or agent) sends its key on every request in the
standard Authorization header:

    Authorization: Bearer sk_live_XXXXXXXX

The server hashes the presented key, looks up the owning client, and serves
that client's data. See README.md for the threat model.

Endpoints:
    GET /healthz        — liveness check, no auth
    GET /v1/whoami      — the authenticated client's identity
    GET /v1/resources   — the authenticated client's resources
"""

import functools
import logging
import os

from flask import Flask, g, jsonify, request

import db

app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(os.path.dirname(__file__), "auth.log")),
        logging.StreamHandler(),
    ],
)
auth_log = logging.getLogger("auth")


def _extract_key():
    """Pull the API key out of the request.

    Preferred: `Authorization: Bearer <key>`. We also accept `X-API-Key: <key>`
    as a convenience for simple clients.
    """
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        return header[len("Bearer "):].strip()
    return request.headers.get("X-API-Key", "").strip() or None


def require_api_key(view):
    """Gate a route behind a valid API key. On success, the authenticated
    client is available as g.client."""

    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        key = _extract_key()
        client = db.authenticate(key) if key else None
        if client is None:
            # One generic error whether the key is missing, malformed, revoked,
            # or unknown — don't help an attacker distinguish those cases.
            auth_log.warning(
                "api auth failure path=%s ip=%s", request.path, request.remote_addr
            )
            resp = jsonify(error="unauthorized")
            resp.headers["WWW-Authenticate"] = "Bearer"
            return resp, 401
        g.client = client
        auth_log.info(
            "api auth ok client=%s path=%s ip=%s",
            client["name"], request.path, request.remote_addr,
        )
        return view(*args, **kwargs)

    return wrapped


@app.route("/healthz")
def healthz():
    return jsonify(status="ok")


@app.route("/v1/whoami")
@require_api_key
def whoami():
    return jsonify(client_id=g.client["client_id"], name=g.client["name"])


@app.route("/v1/resources")
@require_api_key
def resources():
    rows = db.get_resources_for_client(g.client["client_id"])
    return jsonify(resources=[dict(r) for r in rows])


if __name__ == "__main__":
    db.init_schema()
    debug = os.environ.get("FLASK_DEBUG") == "1"

    # TLS is essential for a bearer-token API (the key is sent on every
    # request). Provide TLS_CERT/TLS_KEY, or USE_ADHOC_TLS=1 for local HTTPS.
    ssl_context = None
    cert, key = os.environ.get("TLS_CERT"), os.environ.get("TLS_KEY")
    if cert and key:
        ssl_context = (cert, key)
    elif os.environ.get("USE_ADHOC_TLS") == "1":
        ssl_context = "adhoc"

    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=debug, ssl_context=ssl_context)
