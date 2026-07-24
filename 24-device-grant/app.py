"""
app.py — OAuth2 Device Authorization Grant (RFC 8628).

For devices with no browser / hard keyboards (TVs, CLIs, IoT). The device can't
run a redirect flow, so instead:

  1. Device -> POST /device_authorization  (client_id, scope)
        <- device_code, user_code, verification_uri, interval, expires_in
  2. Device shows: "On your phone go to <verification_uri> and enter <user_code>"
  3. Device polls  POST /token  (grant_type=device_code, device_code)
        <- authorization_pending  (keep polling)  / slow_down / access_denied
        <- access_token           (once the user approves)
  4. Meanwhile the USER, on a browser, opens /device, enters the user_code, logs
     in, and approves the requested scopes.

One process plays all roles (auth server + a demo resource server). The device
side is `client_example.py`.
"""

import functools
import os
import time

from flask import (
    Flask, jsonify, redirect, render_template, request, session, url_for,
)
from flask_wtf import CSRFProtect

import db
import device
import tokens

app = Flask(__name__)
_secret = os.environ.get("SECRET_KEY")
if not _secret:
    raise RuntimeError("SECRET_KEY is not set.")
app.secret_key = _secret
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") == "1")
csrf = CSRFProtect(app)

DEVICE_CODE_TTL = int(os.environ.get("DEVICE_CODE_TTL", "600"))     # 10 min
POLL_INTERVAL = int(os.environ.get("DEVICE_INTERVAL", "5"))         # seconds
DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"

SCOPE_DESCRIPTIONS = {
    "profile": "See your basic profile (name + email)",
    "resources:read": "Read your resources",
}


def current_user():
    uid = session.get("user_id")
    return db.get_user_by_id(uid) if uid else None


def _oauth_error(err, status=400, **extra):
    return jsonify(error=err, **extra), status


# ===========================================================================
# (A) DEVICE ENDPOINTS (device-to-server; no browser, no CSRF)
# ===========================================================================

@app.route("/device_authorization", methods=["POST"])
@csrf.exempt
def device_authorization():
    client_id = request.form.get("client_id", "")
    scope = request.form.get("scope", "")
    client = db.get_client(client_id)
    if client is None:
        return _oauth_error("invalid_client", 401)
    allowed = client["allowed_scopes"].split()
    requested = scope.split()
    if not requested or any(s not in allowed for s in requested):
        return _oauth_error("invalid_scope")

    device_code = device.generate_device_code()
    user_code = device.generate_user_code()
    db.create_device_code(device_code, user_code, client_id, scope,
                          POLL_INTERVAL, DEVICE_CODE_TTL)
    base = request.host_url.rstrip("/")
    app.logger.info("device_authorization client=%s user_code=%s", client_id, user_code)
    return jsonify(
        device_code=device_code,
        user_code=user_code,
        verification_uri=base + "/device",
        verification_uri_complete=base + "/device?user_code=" + user_code,
        expires_in=DEVICE_CODE_TTL,
        interval=POLL_INTERVAL,
    )


@app.route("/token", methods=["POST"])
@csrf.exempt
def token():
    if request.form.get("grant_type") != DEVICE_GRANT:
        return _oauth_error("unsupported_grant_type")
    device_code = request.form.get("device_code", "")
    row = db.get_by_device_code(device_code)
    if row is None:
        return _oauth_error("invalid_grant")

    now = time.time()
    if now >= row["expires_at"]:
        return _oauth_error("expired_token")

    # Rate-limit polling: faster than `interval` -> slow_down (RFC 8628 §3.5).
    if row["last_polled"] is not None and (now - row["last_polled"]) < row["interval"]:
        db.touch_poll(row["device_code_hash"], now)
        return _oauth_error("slow_down")
    db.touch_poll(row["device_code_hash"], now)

    status = row["status"]
    if status == "pending":
        return _oauth_error("authorization_pending")
    if status == "denied":
        return _oauth_error("access_denied")
    if status == "consumed":
        return _oauth_error("invalid_grant")     # one-time
    if status == "approved":
        db.consume(row["device_code_hash"])       # a device_code redeems once
        access_token, ttl = tokens.issue_access_token(
            row["user_id"], row["client_id"], row["scope"])
        app.logger.info("device token issued client=%s user_id=%s", row["client_id"], row["user_id"])
        return jsonify(access_token=access_token, token_type="Bearer",
                       expires_in=ttl, scope=row["scope"])
    return _oauth_error("invalid_grant")


# ===========================================================================
# (B) USER-FACING BROWSER FLOW (enter code -> login -> consent -> approve)
# ===========================================================================

@app.route("/device", methods=["GET", "POST"])
def device_verify():
    if request.method == "POST":
        user_code = device.normalize_user_code(request.form.get("user_code", ""))
        row = db.get_by_user_code(user_code)
        if row is None or time.time() >= row["expires_at"]:
            return render_template("device_entry.html",
                                   error="That code is not valid or has expired.",
                                   user_code=request.form.get("user_code", ""))
        if row["status"] != "pending":
            return render_template("device_entry.html",
                                   error="That code has already been used.",
                                   user_code="")
        session["device_user_code"] = user_code
        return redirect(url_for("device_consent"))
    return render_template("device_entry.html", error=None,
                           user_code=request.args.get("user_code", ""))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    nxt = request.values.get("next", url_for("device_consent"))
    if request.method == "POST":
        user = db.get_user_by_email(request.form.get("email", "").strip().lower())
        if user and db.verify_password(request.form.get("password", ""), user["password_hash"]):
            session["user_id"] = user["id"]
            return redirect(nxt if nxt.startswith("/") else url_for("device_consent"))
        error = "Invalid email or password."
    return render_template("login.html", error=error, next=nxt)


@app.route("/device/consent")
def device_consent():
    user_code = session.get("device_user_code")
    if not user_code:
        return redirect(url_for("device_verify"))
    if current_user() is None:
        return redirect(url_for("login", next=url_for("device_consent")))
    row = db.get_by_user_code(user_code)
    if row is None or row["status"] != "pending":
        session.pop("device_user_code", None)
        return render_template("error.html", message="This request is no longer pending.")
    client = db.get_client(row["client_id"])
    scopes = [(s, SCOPE_DESCRIPTIONS.get(s, s)) for s in row["scope"].split()]
    return render_template("consent.html", client=client, scopes=scopes,
                           user_code=user_code, user=current_user())


@app.route("/device/decision", methods=["POST"])
def device_decision():
    user_code = session.get("device_user_code")
    if not user_code or current_user() is None:
        return redirect(url_for("device_verify"))
    row = db.get_by_user_code(user_code)
    if row is None or row["status"] != "pending":
        session.pop("device_user_code", None)
        return render_template("error.html", message="This request is no longer pending.")
    approved = request.form.get("decision") == "approve"
    db.set_status(user_code, "approved" if approved else "denied",
                  current_user()["id"] if approved else None)
    session.pop("device_user_code", None)
    app.logger.info("device %s by user=%s code=%s",
                    "approved" if approved else "denied", current_user()["email"], user_code)
    return render_template("result.html", approved=approved)


# ===========================================================================
# (C) RESOURCE SERVER
# ===========================================================================

def require_token(scope=None):
    def deco(view):
        @functools.wraps(view)
        def wrapped(*a, **k):
            h = request.headers.get("Authorization", "")
            if not h.startswith("Bearer "):
                return jsonify(error="unauthorized"), 401
            try:
                claims = tokens.verify_access_token(h[7:].strip())
            except Exception:
                return jsonify(error="invalid_token"), 401
            if scope is not None and scope not in claims.get("scope", "").split():
                return jsonify(error="insufficient_scope", required=scope), 403
            request.claims = claims
            return view(*a, **k)
        return wrapped
    return deco


@app.route("/api/resources")
@require_token(scope="resources:read")
def api_resources():
    rows = db.get_resources_for_user(int(request.claims["sub"]))
    return jsonify(resources=[dict(r) for r in rows])


@app.route("/")
def index():
    return app.response_class(
        "Device Authorization Grant demo. The device starts at "
        "/device_authorization; the user approves at /device.\n",
        mimetype="text/plain")


if __name__ == "__main__":
    db.init_schema()
    tokens._secret()
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=os.environ.get("FLASK_DEBUG") == "1")
