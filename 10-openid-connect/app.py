"""
app.py — OAuth2 Authorization Code flow with PKCE.

For a self-contained demo this one process plays THREE roles that in the real
world are separate parties. They're kept in clearly-labelled sections:

  (A) AUTHORIZATION SERVER  /login  /authorize  /authorize/decision  /token
  (B) RESOURCE SERVER       /api/userinfo  /api/resources
  (C) DEMO CLIENT APP       /  /client  /client/start  /client/callback

The flow:

  1. The CLIENT sends the user's browser to /authorize with client_id,
     redirect_uri, scope, state, and a PKCE code_challenge.
  2. The AUTH SERVER authenticates the user (password login) and asks for
     CONSENT to the requested scopes.
  3. On approval it redirects back to the client's redirect_uri with a one-time
     authorization CODE (+ the state).
  4. The CLIENT exchanges the code at /token, proving possession of the PKCE
     code_verifier, and receives an access token.
  5. The CLIENT calls the RESOURCE SERVER with that token.

See README.md for the threat model.
"""

import functools
import json
import os
import ssl
import urllib.parse
import urllib.request

import jwt  # PyJWT — used client-side to read the id_token header / build JWKS keys
from flask import (
    Flask, g, jsonify, redirect, render_template, request, session, url_for,
)
from flask_wtf import CSRFProtect

import crypto_keys
import db
import oauth
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

# Human-readable descriptions shown on the consent screen.
SCOPE_DESCRIPTIONS = {
    "openid": "Confirm your identity",
    "profile": "See your basic profile (name)",
    "email": "See your email address",
    "resources:read": "Read your resources",
}


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def current_user():
    uid = session.get("user_id")
    return db.get_user_by_id(uid) if uid else None


def _is_safe_next(target: str) -> bool:
    """Only allow relative, same-site redirects for the post-login 'next' —
    never an absolute URL (open-redirect protection)."""
    if not target:
        return False
    parts = urllib.parse.urlparse(target)
    return not parts.scheme and not parts.netloc and target.startswith("/")


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
    """Returns (client_row, params_dict, error). If error is a string, the
    caller must show it WITHOUT redirecting (client/redirect_uri untrusted)."""
    p = {k: request.values.get(k, "") for k in (
        "response_type", "client_id", "redirect_uri", "scope", "state",
        "nonce", "code_challenge", "code_challenge_method",
    )}
    client = db.get_oauth_client(p["client_id"])
    if client is None:
        return None, p, "Unknown client_id."
    if p["redirect_uri"] not in db.client_redirect_uris(client):
        # Never redirect to an unregistered URI — it could be the attacker's.
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

    # From here redirect_uri is trusted, so recoverable errors go back to it.
    if p["response_type"] != "code":
        return _redirect_error(p["redirect_uri"], "unsupported_response_type", p["state"])
    if not p["code_challenge"] or p["code_challenge_method"] != "S256":
        return _redirect_error(p["redirect_uri"], "invalid_request", p["state"])

    requested = p["scope"].split()
    allowed = db.client_allowed_scopes(client)
    if not requested or any(s not in allowed for s in requested):
        return _redirect_error(p["redirect_uri"], "invalid_scope", p["state"])

    # Authenticate the resource owner.
    if current_user() is None:
        return redirect(url_for("login", next=request.full_path))

    # Ask for consent.
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
        "client_id", "redirect_uri", "scope", "state", "nonce",
        "code_challenge", "code_challenge_method",
    )}
    client = db.get_oauth_client(p["client_id"])
    # Re-validate — never trust the hidden form fields blindly.
    if client is None or p["redirect_uri"] not in db.client_redirect_uris(client):
        return render_template("error.html", message="Invalid client/redirect."), 400
    allowed = db.client_allowed_scopes(client)
    if any(s not in allowed for s in p["scope"].split()):
        return _redirect_error(p["redirect_uri"], "invalid_scope", p["state"])

    if request.form.get("decision") != "approve":
        return _redirect_error(p["redirect_uri"], "access_denied", p["state"])

    # Mint a one-time code bound to everything that matters.
    code = oauth.generate_auth_code()
    db.create_auth_code(
        code, p["client_id"], current_user()["id"], p["redirect_uri"], p["scope"],
        p["code_challenge"], p["code_challenge_method"], nonce=p["nonce"],
    )
    app.logger.info("authorization code issued client=%s user=%s scope=%s",
                    p["client_id"], current_user()["email"], p["scope"])
    q = urllib.parse.urlencode({"code": code, "state": p["state"]})
    return redirect(f"{p['redirect_uri']}?{q}")


@app.route("/token", methods=["POST"])
@csrf.exempt  # OAuth token endpoint: authenticated by the code + PKCE, not a form
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

    row = db.consume_auth_code(code)   # one-time; None if unknown/used/expired
    if row is None:
        return jsonify(error="invalid_grant"), 400
    # The code is bound to a client + redirect_uri; both must match.
    if row["client_id"] != client_id or row["redirect_uri"] != redirect_uri:
        return jsonify(error="invalid_grant"), 400
    # PKCE: prove possession of the verifier behind the earlier challenge.
    if not oauth.verify_pkce(code_verifier, row["code_challenge"],
                             row["code_challenge_method"]):
        app.logger.warning("PKCE verification failed client=%s", client_id)
        return jsonify(error="invalid_grant"), 400

    scopes = row["scope"].split()
    access_token, ttl = tokens.issue_access_token(
        row["user_id"], client_id, row["scope"]
    )
    resp = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": ttl,
        "scope": row["scope"],
    }
    # OIDC: the `openid` scope turns this into an authentication response — we
    # additionally return a signed id_token describing the user, bound to the
    # client's nonce.
    if "openid" in scopes:
        user = db.get_user_by_id(row["user_id"])
        resp["id_token"] = tokens.issue_id_token(user, client_id, row["nonce"], scopes)
        app.logger.info("id_token + access token issued client=%s user_id=%s scope=%s",
                        client_id, row["user_id"], row["scope"])
    else:
        app.logger.info("access token issued client=%s user_id=%s scope=%s",
                        client_id, row["user_id"], row["scope"])
    return jsonify(resp)


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


@app.route("/userinfo")
@require_token(scope="openid")
def userinfo():
    """OIDC UserInfo: identity claims for the bearer of an openid access token,
    filtered by the scopes that were granted."""
    user = db.get_user_by_id(int(g.claims["sub"]))
    scopes = g.claims.get("scope", "").split()
    out = {"sub": str(user["id"])}
    if "profile" in scopes and user["name"]:
        out["name"] = user["name"]
    if "email" in scopes:
        out["email"] = user["email"]
        out["email_verified"] = True
    return jsonify(out)


@app.route("/api/resources")
@require_token(scope="resources:read")
def api_resources():
    rows = db.get_resources_for_user(int(g.claims["sub"]))
    return jsonify(resources=[dict(r) for r in rows])


# --- OIDC provider metadata (public, unauthenticated) -----------------------

@app.route("/.well-known/openid-configuration")
def openid_configuration():
    base = request.host_url.rstrip("/")
    return jsonify({
        "issuer": tokens.ISS,
        "authorization_endpoint": base + "/authorize",
        "token_endpoint": base + "/token",
        "userinfo_endpoint": base + "/userinfo",
        "jwks_uri": base + "/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "scopes_supported": ["openid", "profile", "email", "resources:read"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "code_challenge_methods_supported": ["S256"],
        "subject_types_supported": ["public"],
        "claims_supported": [
            "sub", "iss", "aud", "exp", "iat", "nonce",
            "name", "email", "email_verified",
        ],
    })


@app.route("/.well-known/jwks.json")
def jwks_json():
    # Public verification keys. Clients fetch these to verify id_tokens; the
    # private key never leaves the server.
    return jsonify(crypto_keys.jwks())


# ===========================================================================
# (C) DEMO CLIENT APP  (a separate party; here for a runnable browser demo)
# ===========================================================================

CLIENT_ID = "demo-web-app"
# `openid` makes this an authentication request (we'll get an id_token).
CLIENT_SCOPE = "openid profile email resources:read"


def _client_redirect_uri():
    return request.host_url.rstrip("/") + "/client/callback"


def _verify_id_token_via_jwks(id_token, base, ctx, nonce):
    """Real OIDC client verification: discover the provider, fetch its JWKS,
    pick the key named by the token's `kid`, and validate signature + claims."""
    disc = json.load(urllib.request.urlopen(
        base + "/.well-known/openid-configuration", context=ctx))
    jwks = json.load(urllib.request.urlopen(disc["jwks_uri"], context=ctx))
    kid = jwt.get_unverified_header(id_token)["kid"]
    jwk = next(k for k in jwks["keys"] if k["kid"] == kid)
    key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
    return tokens.verify_id_token(id_token, key, CLIENT_ID, nonce=nonce)


@app.route("/")
def client_home():
    return render_template("client_home.html", user=current_user())


@app.route("/client/start")
def client_start():
    # The client creates PKCE + state + nonce and stashes them in ITS session.
    verifier = oauth.generate_code_verifier()
    state = oauth.generate_state()
    nonce = oauth.generate_nonce()
    session["cli_verifier"] = verifier
    session["cli_state"] = state
    session["cli_nonce"] = nonce
    q = urllib.parse.urlencode({
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": _client_redirect_uri(),
        "scope": CLIENT_SCOPE,
        "state": state,
        "nonce": nonce,
        "code_challenge": oauth.code_challenge_s256(verifier),
        "code_challenge_method": "S256",
    })
    return redirect(url_for("authorize") + "?" + q)


@app.route("/client/callback")
def client_callback():
    if request.args.get("error"):
        return render_template("error.html", message="Authorization failed: "
                               + request.args.get("error")), 400
    # Verify state (defeats CSRF on the redirect).
    if not request.args.get("state") or request.args.get("state") != session.get("cli_state"):
        return render_template("error.html", message="State mismatch."), 400
    code = request.args.get("code", "")

    # Exchange the code for a token (server-to-server), proving PKCE.
    base = request.host_url.rstrip("/")
    ctx = ssl.create_default_context()
    if base.startswith("https"):
        ctx.check_hostname = False       # DEMO ONLY: trust the local self-signed AS
        ctx.verify_mode = ssl.CERT_NONE
    data = urllib.parse.urlencode({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": _client_redirect_uri(),
        "client_id": CLIENT_ID,
        "code_verifier": session.get("cli_verifier", ""),
    }).encode()
    with urllib.request.urlopen(urllib.request.Request(base + "/token", data=data),
                                context=ctx) as r:
        tok = json.load(r)

    # AUTHENTICATION: validate the id_token (signature via JWKS + iss/aud/exp +
    # the nonce we sent). Its claims tell us WHO logged in.
    id_claims = _verify_id_token_via_jwks(
        tok["id_token"], base, ctx, session.get("cli_nonce"))

    # AUTHORIZATION: use the access token against the resource server.
    def api(path):
        req = urllib.request.Request(base + path)
        req.add_header("Authorization", "Bearer " + tok["access_token"])
        with urllib.request.urlopen(req, context=ctx) as r:
            return json.load(r)

    userinfo = api("/userinfo")
    resources = api("/api/resources")["resources"]

    # One-time values are spent; clear them.
    for k in ("cli_verifier", "cli_state", "cli_nonce"):
        session.pop(k, None)
    return render_template(
        "client_result.html",
        scope=tok.get("scope"), expires_in=tok.get("expires_in"),
        id_claims=id_claims, userinfo=userinfo, resources=resources,
    )


if __name__ == "__main__":
    db.init_schema()
    _ = crypto_keys.KID  # ensure the signing key is loaded/generated at boot

    debug = os.environ.get("FLASK_DEBUG") == "1"
    ssl_context = None
    cert, key = os.environ.get("TLS_CERT"), os.environ.get("TLS_KEY")
    if cert and key:
        ssl_context = (cert, key)
    elif os.environ.get("USE_ADHOC_TLS") == "1":
        ssl_context = "adhoc"

    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=debug, ssl_context=ssl_context)
