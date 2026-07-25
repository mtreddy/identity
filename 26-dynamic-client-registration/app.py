"""
app.py — OAuth2 Authorization Code + PKCE, with Dynamic Client Registration.

Same three-roles-in-one-process shape as 09, plus a fourth surface: clients now
provision THEMSELVES instead of being hand-seeded.

  (A) AUTHORIZATION SERVER   /login /authorize /authorize/decision /token
  (B) RESOURCE SERVER        /api/userinfo /api/resources
  (C) DEMO CLIENT APP        / /client/start /client/callback
  (D) REGISTRATION ENDPOINT  POST /register            (RFC 7591)
                             GET|PUT|DELETE /register/<client_id>  (RFC 7592)

The registration endpoint is gated by an *initial access token* (unless
OPEN_REGISTRATION=1) so it can't be used to bulk-create clients. Each created
client gets its own *registration access token* that authorizes managing only
itself. redirect_uris are validated hard — that allow-list is where codes and
tokens ultimately get sent.

See README.md for the threat model.
"""

import base64
import functools
import json
import os
import secrets
import ssl
import urllib.parse
import urllib.request

from flask import (
    Flask, g, jsonify, redirect, render_template, request, session, url_for,
)
from flask_wtf import CSRFProtect

import db
import oauth
import registration
import tokens

app = Flask(__name__)

_secret = os.environ.get("SECRET_KEY")
if not _secret:
    raise RuntimeError("SECRET_KEY is not set (needed to sign the session cookie).")
app.secret_key = _secret
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") == "1",
    SESSION_COOKIE_SAMESITE="Lax",
)

csrf = CSRFProtect(app)

# Registration gate. With an initial access token set, /register requires it;
# with OPEN_REGISTRATION=1 anyone may register (the RFC allows it — see README
# for why that's usually a bad idea). Fail closed if neither is configured.
INITIAL_ACCESS_TOKEN = os.environ.get("REGISTRATION_TOKEN")
OPEN_REGISTRATION = os.environ.get("OPEN_REGISTRATION") == "1"
DEMO_CLIENT_FILE = os.path.join(os.path.dirname(__file__), "demo_client.json")

SCOPE_DESCRIPTIONS = {
    "profile": "See your email address",
    "resources:read": "Read your resources",
    "resources:write": "Modify your resources",
}


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def current_user():
    uid = session.get("user_id")
    return db.get_user_by_id(uid) if uid else None


def _is_safe_next(target: str) -> bool:
    if not target:
        return False
    parts = urllib.parse.urlparse(target)
    return not parts.scheme and not parts.netloc and target.startswith("/")


def _registration_client_uri(client_id: str) -> str:
    return request.host_url.rstrip("/") + "/register/" + client_id


# ===========================================================================
# (D) DYNAMIC CLIENT REGISTRATION  (RFC 7591 / RFC 7592)
# ===========================================================================

def _initial_access_token_ok() -> bool:
    if OPEN_REGISTRATION:
        return True
    if not INITIAL_ACCESS_TOKEN:
        return False                     # misconfigured -> refuse (fail closed)
    hdr = request.headers.get("Authorization", "")
    if not hdr.startswith("Bearer "):
        return False
    return secrets.compare_digest(hdr[7:].strip(), INITIAL_ACCESS_TOKEN)


def _client_info(row, *, secret=None, rat=None) -> dict:
    """The RFC 7591 client information response. Secrets are only ever included
    on the create/rotate response (when passed in), never on a later read."""
    info = {
        "client_id": row["client_id"],
        "client_name": row["name"],
        "redirect_uris": db.client_redirect_uris(row),
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": row["token_endpoint_auth_method"],
        "scope": row["allowed_scopes"],
        "client_id_issued_at": row["client_id_issued_at"],
        "registration_client_uri": _registration_client_uri(row["client_id"]),
    }
    if secret is not None:
        info["client_secret"] = secret
    if rat is not None:
        info["registration_access_token"] = rat
    return info


@app.route("/register", methods=["POST"])
@csrf.exempt   # machine-to-machine JSON endpoint, authenticated by bearer token
def register():
    if not _initial_access_token_ok():
        return jsonify(error="invalid_token",
                       error_description="initial access token required"), 401

    body = request.get_json(silent=True)
    meta, err = registration.validate_metadata(body or {})
    if err:
        return jsonify(error=err), 400

    created = db.register_client(meta)
    row = db.get_oauth_client(created["client_id"])
    app.logger.info("client registered client_id=%s auth=%s scope=%s",
                    created["client_id"], meta["token_endpoint_auth_method"], meta["scope"])
    # The secret + RAT are shown exactly once, here.
    return jsonify(_client_info(
        row, secret=created["client_secret"],
        rat=created["registration_access_token"],
    )), 201


def _authorize_management(client_id: str):
    """RFC 7592: the caller must present the client's registration access token.
    Returns the client row on success, or a (json, status) error tuple. Unknown
    client and bad token look identical (401) — no existence oracle."""
    row = db.get_oauth_client(client_id)
    hdr = request.headers.get("Authorization", "")
    token = hdr[7:].strip() if hdr.startswith("Bearer ") else ""
    if row is None or not db.verify_registration_access_token(row, token):
        return None, (jsonify(error="invalid_token"), 401)
    return row, None


@app.route("/register/<client_id>", methods=["GET", "PUT", "DELETE"])
@csrf.exempt
def manage_client(client_id):
    row, error = _authorize_management(client_id)
    if error:
        return error

    if request.method == "GET":
        return jsonify(_client_info(row)), 200

    if request.method == "DELETE":
        db.delete_client(client_id)
        app.logger.info("client deleted client_id=%s", client_id)
        return "", 204

    # PUT — full replacement of the metadata (re-validated from scratch).
    body = request.get_json(silent=True)
    meta, err = registration.validate_metadata(body or {})
    if err:
        return jsonify(error=err), 400
    db.update_client(client_id, meta)
    app.logger.info("client updated client_id=%s", client_id)
    return jsonify(_client_info(db.get_oauth_client(client_id))), 200


# ===========================================================================
# (A) AUTHORIZATION SERVER
# ===========================================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    next_url = request.values.get("next", "/")
    if not _is_safe_next(next_url):
        next_url = "/"
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = db.get_user_by_email(email)
        if user and db.verify_password(password, user["password_hash"]):
            session["user_id"] = user["id"]
            return redirect(next_url)
        error = "Invalid email or password."
    return render_template("login.html", error=error, next=next_url)


@app.route("/logout")
def logout():
    session.pop("user_id", None)
    return redirect(url_for("client_home"))


def _validate_authorize_params():
    p = {k: request.values.get(k, "") for k in (
        "response_type", "client_id", "redirect_uri", "scope", "state",
        "code_challenge", "code_challenge_method",
    )}
    client = db.get_oauth_client(p["client_id"])
    if client is None:
        return None, p, "Unknown client_id."
    if p["redirect_uri"] not in db.client_redirect_uris(client):
        return None, p, "redirect_uri is not registered for this client."
    return client, p, None


def _redirect_error(redirect_uri, error, state):
    q = urllib.parse.urlencode({"error": error, "state": state})
    return redirect(f"{redirect_uri}?{q}")


@app.route("/authorize")
def authorize():
    client, p, hard_error = _validate_authorize_params()
    if hard_error:
        return render_template("error.html", message=hard_error), 400

    if p["response_type"] != "code":
        return _redirect_error(p["redirect_uri"], "unsupported_response_type", p["state"])
    if not p["code_challenge"] or p["code_challenge_method"] != "S256":
        return _redirect_error(p["redirect_uri"], "invalid_request", p["state"])

    requested = p["scope"].split()
    allowed = db.client_allowed_scopes(client)
    if not requested or any(s not in allowed for s in requested):
        return _redirect_error(p["redirect_uri"], "invalid_scope", p["state"])

    if current_user() is None:
        return redirect(url_for("login", next=request.full_path))

    return render_template(
        "consent.html",
        client=client, params=p,
        scopes=[(s, SCOPE_DESCRIPTIONS.get(s, s)) for s in requested],
        user=current_user(),
    )


@app.route("/authorize/decision", methods=["POST"])
def authorize_decision():
    if current_user() is None:
        return redirect(url_for("login"))

    p = {k: request.form.get(k, "") for k in (
        "client_id", "redirect_uri", "scope", "state",
        "code_challenge", "code_challenge_method",
    )}
    client = db.get_oauth_client(p["client_id"])
    if client is None or p["redirect_uri"] not in db.client_redirect_uris(client):
        return render_template("error.html", message="Invalid client/redirect."), 400
    allowed = db.client_allowed_scopes(client)
    if any(s not in allowed for s in p["scope"].split()):
        return _redirect_error(p["redirect_uri"], "invalid_scope", p["state"])

    if request.form.get("decision") != "approve":
        return _redirect_error(p["redirect_uri"], "access_denied", p["state"])

    code = oauth.generate_auth_code()
    db.create_auth_code(
        code, p["client_id"], current_user()["id"], p["redirect_uri"], p["scope"],
        p["code_challenge"], p["code_challenge_method"],
    )
    app.logger.info("authorization code issued client=%s user=%s scope=%s",
                    p["client_id"], current_user()["email"], p["scope"])
    q = urllib.parse.urlencode({"code": code, "state": p["state"]})
    return redirect(f"{p['redirect_uri']}?{q}")


def _presented_client_secret():
    """A confidential client authenticates with client_secret_basic (HTTP Basic)
    or client_secret_post (a form field). Support both."""
    hdr = request.headers.get("Authorization", "")
    if hdr.startswith("Basic "):
        try:
            raw = base64.b64decode(hdr[6:]).decode()
            _, _, pw = raw.partition(":")
            return pw
        except Exception:
            return ""
    return request.form.get("client_secret", "")


@app.route("/token", methods=["POST"])
@csrf.exempt
def token():
    if request.form.get("grant_type") != "authorization_code":
        return jsonify(error="unsupported_grant_type"), 400

    code = request.form.get("code", "")
    redirect_uri = request.form.get("redirect_uri", "")
    client_id = request.form.get("client_id", "")
    code_verifier = request.form.get("code_verifier", "")

    client = db.get_oauth_client(client_id)
    if client is None:
        return jsonify(error="invalid_client"), 401

    # Confidential clients must authenticate with their secret; public clients
    # rely on PKCE alone (they hold no secret).
    if client["token_endpoint_auth_method"] != "none":
        if not db.verify_client_secret(client, _presented_client_secret()):
            app.logger.warning("client secret auth failed client=%s", client_id)
            return jsonify(error="invalid_client"), 401

    row = db.consume_auth_code(code)
    if row is None:
        return jsonify(error="invalid_grant"), 400
    if row["client_id"] != client_id or row["redirect_uri"] != redirect_uri:
        return jsonify(error="invalid_grant"), 400
    if not oauth.verify_pkce(code_verifier, row["code_challenge"],
                             row["code_challenge_method"]):
        app.logger.warning("PKCE verification failed client=%s", client_id)
        return jsonify(error="invalid_grant"), 400

    access_token, ttl = tokens.issue_access_token(
        row["user_id"], client_id, row["scope"]
    )
    app.logger.info("access token issued client=%s user_id=%s scope=%s",
                    client_id, row["user_id"], row["scope"])
    return jsonify(
        access_token=access_token,
        token_type="Bearer",
        expires_in=ttl,
        scope=row["scope"],
    )


# ===========================================================================
# (B) RESOURCE SERVER
# ===========================================================================

def require_token(scope=None):
    def decorator(view):
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            header = request.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                return jsonify(error="unauthorized"), 401
            try:
                claims = tokens.verify_access_token(header[7:].strip())
            except Exception:
                return jsonify(error="invalid_token"), 401
            if scope is not None and scope not in claims.get("scope", "").split():
                return jsonify(error="insufficient_scope", required=scope), 403
            g.claims = claims
            return view(*args, **kwargs)
        return wrapped
    return decorator


@app.route("/api/userinfo")
@require_token(scope="profile")
def userinfo():
    user = db.get_user_by_id(int(g.claims["sub"]))
    return jsonify(sub=user["id"], email=user["email"])


@app.route("/api/resources")
@require_token(scope="resources:read")
def api_resources():
    rows = db.get_resources_for_user(int(g.claims["sub"]))
    return jsonify(resources=[dict(r) for r in rows])


# ===========================================================================
# (C) DEMO CLIENT APP  (uses a client that seed.py registered dynamically)
# ===========================================================================

def _demo_client():
    """The browser demo drives a real registered client — the one seed.py
    created via /register and recorded here. No hardcoded client row exists."""
    try:
        with open(DEMO_CLIENT_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _client_redirect_uri():
    return request.host_url.rstrip("/") + "/client/callback"


@app.route("/")
def client_home():
    return render_template("client_home.html", user=current_user(),
                           demo=_demo_client())


@app.route("/client/start")
def client_start():
    demo = _demo_client()
    if not demo:
        return render_template("error.html",
                               message="No demo client registered. Run seed.py first."), 400
    verifier = oauth.generate_code_verifier()
    state = oauth.generate_state()
    session["cli_verifier"] = verifier
    session["cli_state"] = state
    q = urllib.parse.urlencode({
        "response_type": "code",
        "client_id": demo["client_id"],
        "redirect_uri": _client_redirect_uri(),
        "scope": demo.get("scope", "profile resources:read"),
        "state": state,
        "code_challenge": oauth.code_challenge_s256(verifier),
        "code_challenge_method": "S256",
    })
    return redirect(url_for("authorize") + "?" + q)


@app.route("/client/callback")
def client_callback():
    demo = _demo_client()
    if request.args.get("error"):
        return render_template("error.html", message="Authorization failed: "
                               + request.args.get("error")), 400
    if not request.args.get("state") or request.args.get("state") != session.get("cli_state"):
        return render_template("error.html", message="State mismatch."), 400
    code = request.args.get("code", "")

    base = request.host_url.rstrip("/")
    ctx = ssl.create_default_context()
    if base.startswith("https"):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    data = urllib.parse.urlencode({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": _client_redirect_uri(),
        "client_id": demo["client_id"],
        "code_verifier": session.get("cli_verifier", ""),
    }).encode()
    with urllib.request.urlopen(urllib.request.Request(base + "/token", data=data),
                                context=ctx) as r:
        tok = json.load(r)

    def api(path):
        req = urllib.request.Request(base + path)
        req.add_header("Authorization", "Bearer " + tok["access_token"])
        with urllib.request.urlopen(req, context=ctx) as r:
            return json.load(r)

    session.pop("cli_verifier", None)
    session.pop("cli_state", None)
    return render_template(
        "client_result.html",
        scope=tok.get("scope"), expires_in=tok.get("expires_in"),
        userinfo=api("/api/userinfo"), resources=api("/api/resources")["resources"],
    )


if __name__ == "__main__":
    db.init_schema()
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
