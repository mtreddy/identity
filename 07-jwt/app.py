"""
app.py — a JSON API that authenticates with short-lived JWT access tokens.

Two-step, machine-to-machine flow:

  1. POST /v1/token        with the API key (Authorization: Bearer <api_key>)
                           -> returns a signed, short-lived JWT + its scopes
  2. GET  /v1/resources    with the JWT   (Authorization: Bearer <jwt>)
                           -> verified statelessly (signature/exp/aud/iss/scope)

So the long-lived API key (mechanism 06) is used ONCE to obtain a token, and
the token — not the key — is what travels on subsequent requests. See
README.md for the threat model and trade-offs.

Endpoints:
    GET  /healthz          — liveness, no auth
    POST /v1/token         — API key -> JWT (requires a valid API key)
    GET  /v1/whoami        — identity from the JWT             (needs a JWT)
    GET  /v1/resources     — the client's resources            (scope resources:read)
    GET  /v1/admin/stats   — privileged endpoint                (scope admin)
"""

import functools
import logging
import os

import jwt as pyjwt
from flask import Flask, g, jsonify, request

import db
import tokens

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


def _bearer():
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        return header[len("Bearer "):].strip() or None
    return None


def _unauthorized(msg="unauthorized"):
    resp = jsonify(error=msg)
    resp.headers["WWW-Authenticate"] = "Bearer"
    return resp, 401


# --- API-key gate (only for the token endpoint) -----------------------------
def require_api_key(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        key = _bearer() or request.headers.get("X-API-Key", "").strip() or None
        client = db.authenticate(key) if key else None
        if client is None:
            auth_log.warning("token-issue auth failure ip=%s", request.remote_addr)
            return _unauthorized()
        g.client = client
        return view(*args, **kwargs)

    return wrapped


# --- JWT gate (for the resource endpoints), with optional scope -------------
def require_jwt(scope=None):
    def decorator(view):
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            token = _bearer()
            if not token:
                return _unauthorized()
            try:
                claims = tokens.verify_token(token)
            except pyjwt.ExpiredSignatureError:
                auth_log.warning("jwt expired path=%s ip=%s",
                                 request.path, request.remote_addr)
                return _unauthorized("token_expired")
            except pyjwt.InvalidTokenError:
                auth_log.warning("jwt invalid path=%s ip=%s",
                                 request.path, request.remote_addr)
                return _unauthorized("invalid_token")

            if scope is not None and scope not in claims.get("scope", "").split():
                auth_log.warning("scope denied need=%s sub=%s path=%s",
                                 scope, claims.get("sub"), request.path)
                return jsonify(error="insufficient_scope", required=scope), 403

            g.claims = claims
            return view(*args, **kwargs)

        return wrapped

    return decorator


@app.route("/healthz")
def healthz():
    return jsonify(status="ok")


@app.route("/v1/token", methods=["POST"])
@require_api_key
def token():
    scopes = db.get_client_scopes(g.client["client_id"])
    access_token, ttl = tokens.issue_token(
        g.client["client_id"], g.client["name"], scopes
    )
    auth_log.info("token issued client=%s scopes=%s ip=%s",
                  g.client["name"], scopes, request.remote_addr)
    return jsonify(
        access_token=access_token,
        token_type="Bearer",
        expires_in=ttl,
        scope=" ".join(scopes),
    )


@app.route("/v1/whoami")
@require_jwt()
def whoami():
    return jsonify(
        client_id=int(g.claims["sub"]),
        name=g.claims.get("name"),
        scope=g.claims.get("scope", ""),
        expires_at=g.claims["exp"],
    )


@app.route("/v1/resources")
@require_jwt(scope="resources:read")
def resources():
    rows = db.get_resources_for_client(int(g.claims["sub"]))
    return jsonify(resources=[dict(r) for r in rows])


@app.route("/v1/admin/stats")
@require_jwt(scope="admin")
def admin_stats():
    # Privileged endpoint to demonstrate scope enforcement.
    return jsonify(clients=1, note="privileged data visible only with 'admin' scope")


if __name__ == "__main__":
    db.init_schema()
    # Fail fast if the signing secret is missing (verifies config at boot).
    tokens._secret()

    debug = os.environ.get("FLASK_DEBUG") == "1"
    ssl_context = None
    cert, key = os.environ.get("TLS_CERT"), os.environ.get("TLS_KEY")
    if cert and key:
        ssl_context = (cert, key)
    elif os.environ.get("USE_ADHOC_TLS") == "1":
        ssl_context = "adhoc"

    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=debug, ssl_context=ssl_context)
