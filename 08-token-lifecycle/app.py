"""
app.py — token lifecycle: refresh tokens + revocation + introspection.

Extends mechanism 07 (short-lived JWTs) with the pieces a real token service
needs, all of which revolve around REVOCATION — the thing a bare stateless JWT
can't do:

  * POST /v1/token          API key -> { short access JWT, long refresh token }
  * POST /v1/token/refresh  refresh token -> new access JWT (+ rotated refresh)
                            with stolen-token REUSE DETECTION
  * POST /v1/token/revoke   revoke a refresh token and/or an access token (jti)
  * POST /v1/introspect     RFC 7662 — is this token active? (API-key gated)

Access tokens carry a `jti`; revoking one adds its jti to a deny-list that is
checked on every request. Refresh tokens are opaque, hashed at rest, and
rotated on each use.

    GET  /healthz          liveness, no auth
    GET  /v1/whoami        identity from the JWT              (needs a JWT)
    GET  /v1/resources     the client's resources             (scope resources:read)
    GET  /v1/admin/stats   privileged                          (scope admin)
"""

import functools
import logging
import os

import jwt as pyjwt
from flask import Flask, g, jsonify, request

import db
import tokens

app = Flask(__name__)

# Refresh tokens are long-lived (default 30 days). Configurable for testing.
REFRESH_TTL = int(os.environ.get("REFRESH_TTL", str(30 * 24 * 3600)))

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


def _param(name):
    """Read a value from form body or JSON body (RFC 6749 uses form params)."""
    if request.form and name in request.form:
        return request.form.get(name)
    if request.is_json:
        return (request.get_json(silent=True) or {}).get(name)
    return None


def _unauthorized(msg="unauthorized"):
    resp = jsonify(error=msg)
    resp.headers["WWW-Authenticate"] = "Bearer"
    return resp, 401


# --- API-key gate (token issuance + introspection) --------------------------
def require_api_key(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        key = _bearer() or request.headers.get("X-API-Key", "").strip() or None
        client = db.authenticate(key) if key else None
        if client is None:
            auth_log.warning("api-key auth failure path=%s ip=%s",
                             request.path, request.remote_addr)
            return _unauthorized()
        g.client = client
        return view(*args, **kwargs)

    return wrapped


# --- JWT gate (resource routes), with optional scope + deny-list check ------
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
                return _unauthorized("token_expired")
            except pyjwt.InvalidTokenError:
                return _unauthorized("invalid_token")

            # Revocation: an otherwise-valid token whose jti is on the
            # deny-list is rejected before it would naturally expire.
            if db.is_jti_revoked(claims.get("jti", "")):
                auth_log.warning("jwt revoked jti=%s path=%s",
                                 claims.get("jti"), request.path)
                return _unauthorized("token_revoked")

            if scope is not None and scope not in claims.get("scope", "").split():
                return jsonify(error="insufficient_scope", required=scope), 403

            g.claims = claims
            return view(*args, **kwargs)

        return wrapped

    return decorator


def _issue_pair(client_id, name, scopes, rotated_from=None):
    """Mint a fresh access JWT + a refresh token and shape the response."""
    access_token, ttl, _jti = tokens.issue_token(client_id, name, scopes)
    refresh_token, _rid = db.create_refresh_token(
        client_id, scopes, REFRESH_TTL, rotated_from=rotated_from
    )
    return jsonify(
        access_token=access_token,
        token_type="Bearer",
        expires_in=ttl,
        refresh_token=refresh_token,
        refresh_expires_in=REFRESH_TTL,
        scope=" ".join(scopes),
    )


@app.route("/healthz")
def healthz():
    return jsonify(status="ok")


@app.route("/v1/token", methods=["POST"])
@require_api_key
def token():
    cid, name = g.client["client_id"], g.client["name"]
    scopes = db.get_client_scopes(cid)
    auth_log.info("token issued client=%s scopes=%s ip=%s",
                  name, scopes, request.remote_addr)
    return _issue_pair(cid, name, scopes)


@app.route("/v1/token/refresh", methods=["POST"])
def token_refresh():
    presented = _param("refresh_token") or _bearer()
    if not presented:
        return jsonify(error="invalid_request", detail="refresh_token required"), 400

    row = db.get_refresh_record(presented)
    if row is None:
        return _unauthorized("invalid_grant")

    # REUSE DETECTION: a client rotates its refresh token on every use, so a
    # previously-rotated (revoked) token showing up again means someone else
    # has a copy — treat it as theft and revoke the whole family.
    if row["revoked"]:
        n = db.revoke_all_refresh_for_client(row["client_id"])
        auth_log.warning(
            "refresh REUSE detected client_id=%s — revoked %d refresh token(s) ip=%s",
            row["client_id"], n, request.remote_addr,
        )
        return _unauthorized("invalid_grant")

    if db.refresh_is_expired(row):
        return _unauthorized("invalid_grant")

    # Valid: rotate. Revoke the presented token, issue a new access+refresh pair.
    db.revoke_refresh_token_id(row["id"])
    client = db.get_client(row["client_id"])
    if client is None:
        return _unauthorized("invalid_grant")
    scopes = row["scopes"].split()
    auth_log.info("token refreshed client=%s ip=%s", client["name"], request.remote_addr)
    return _issue_pair(client["id"], client["name"], scopes, rotated_from=row["id"])


@app.route("/v1/token/revoke", methods=["POST"])
def token_revoke():
    """Revoke a refresh token (present it as `refresh_token`) and/or an access
    token (present it as `access_token`; its jti goes on the deny-list).
    Per RFC 7009 we return 200 even if the token was already invalid."""
    did = []

    refresh = _param("refresh_token")
    if refresh:
        row = db.get_refresh_record(refresh)
        if row is not None and not row["revoked"]:
            db.revoke_refresh_token_id(row["id"])
            did.append("refresh_token")

    access = _param("access_token")
    if access:
        try:
            claims = tokens.verify_token(access)
            db.revoke_jti(claims["jti"], claims["exp"])
            did.append("access_token")
        except pyjwt.InvalidTokenError:
            pass  # already invalid/expired — nothing to deny-list

    auth_log.info("revoke request revoked=%s ip=%s", did, request.remote_addr)
    return jsonify(revoked=did), 200


@app.route("/v1/introspect", methods=["POST"])
@require_api_key
def introspect():
    """RFC 7662-style token introspection. Callers must authenticate (API key).
    Returns {"active": false} for anything invalid/expired/revoked."""
    presented = _param("token")
    if not presented:
        return jsonify(active=False)

    # Try as an access JWT first.
    try:
        claims = tokens.verify_token(presented)
        if db.is_jti_revoked(claims.get("jti", "")):
            return jsonify(active=False)
        return jsonify(
            active=True,
            token_type="access_token",
            sub=claims["sub"],
            client_name=claims.get("name"),
            scope=claims.get("scope", ""),
            jti=claims.get("jti"),
            exp=claims["exp"],
        )
    except pyjwt.InvalidTokenError:
        pass

    # Otherwise treat it as a refresh token.
    row = db.get_refresh_record(presented)
    if row is not None and not row["revoked"] and not db.refresh_is_expired(row):
        return jsonify(
            active=True,
            token_type="refresh_token",
            sub=str(row["client_id"]),
            scope=row["scopes"],
            exp=row["expires_at"],
        )

    return jsonify(active=False)


@app.route("/v1/whoami")
@require_jwt()
def whoami():
    return jsonify(
        client_id=int(g.claims["sub"]),
        name=g.claims.get("name"),
        scope=g.claims.get("scope", ""),
        jti=g.claims.get("jti"),
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
    return jsonify(clients=1, note="privileged data visible only with 'admin' scope")


if __name__ == "__main__":
    db.init_schema()
    tokens._secret()  # fail fast if JWT_SECRET is missing

    debug = os.environ.get("FLASK_DEBUG") == "1"
    ssl_context = None
    cert, key = os.environ.get("TLS_CERT"), os.environ.get("TLS_KEY")
    if cert and key:
        ssl_context = (cert, key)
    elif os.environ.get("USE_ADHOC_TLS") == "1":
        ssl_context = "adhoc"

    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=debug, ssl_context=ssl_context)
