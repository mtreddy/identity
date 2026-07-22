"""
app.py — web server, hardened step 2.

Carries forward 02-secrets-transport (env secret key, debug off, TLS) and adds three
hardening features that make the *authentication itself* more robust:

  Feature 4 — Hardened session cookie (Secure / HttpOnly / SameSite / lifetime).
  Feature 5 — Brute-force protection via per-IP + per-account rate limiting.
  Feature 6 — Close the timing side-channel that leaks which emails exist.

See README.md for the threat each one addresses.
"""

import functools
import os

import bcrypt
from flask import (
    Flask,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import db

app = Flask(__name__)

# Feature 1 (from 02-secrets-transport): secret key from the environment.
_secret = os.environ.get("SECRET_KEY")
if not _secret:
    raise RuntimeError(
        "SECRET_KEY environment variable is not set.\n"
        "Generate one and export it before starting the server:\n"
        '  export SECRET_KEY="$(python -c \'import secrets;'
        " print(secrets.token_hex(32))')\""
    )
app.secret_key = _secret

# --- Feature 4: harden the session cookie -----------------------------------
# HttpOnly  -> JavaScript can't read the cookie (limits XSS cookie theft).
# Secure    -> the browser only sends it over HTTPS (needs TLS from 02-secrets-transport).
# SameSite  -> the cookie isn't sent on cross-site requests (CSRF mitigation).
# Lifetime  -> sessions expire, bounding the window a stolen cookie is useful.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") == "1",
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=1800,  # 30 minutes
)

# --- Feature 5: rate limiting (brute-force / credential-stuffing defense) ----
# Limits are keyed by client IP. The login route additionally applies a
# per-account limit so one email can't be hammered from rotating IPs.
# NOTE: the default in-memory store resets on restart and isn't shared across
# processes — fine for this single-process example; use Redis in production.
limiter = Limiter(key_func=get_remote_address, app=app)

# Feature 6: a fixed dummy hash to compare against when the email is unknown,
# so an attacker can't tell "no such user" (fast) from "wrong password" (slow).
_DUMMY_HASH = bcrypt.hashpw(b"timing-equalizer", bcrypt.gensalt()).decode()


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def _login_account_key():
    """Rate-limit key for the per-account limit: the submitted email."""
    return request.form.get("email", "").strip().lower() or get_remote_address()


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
# Feature 5: cap attempts. Per-IP AND per-account, on POST only.
@limiter.limit(
    "10 per minute", methods=["POST"], key_func=get_remote_address
)
@limiter.limit("5 per minute", methods=["POST"], key_func=_login_account_key)
def login():
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = db.get_user_by_email(email)

        # --- Feature 6: constant-ish work regardless of whether the user
        # exists. Always run one bcrypt verification; use the dummy hash when
        # there's no such user so both paths take the same time.
        stored_hash = user["password_hash"] if user else _DUMMY_HASH
        password_ok = db.verify_password(password, stored_hash)

        if user and password_ok:
            session.clear()
            session["user_id"] = user["id"]
            session["email"] = user["email"]
            return redirect(url_for("dashboard"))

        error = "Invalid email or password."

    return render_template("login.html", error=error)


@app.errorhandler(429)
def too_many_requests(_e):
    # Friendly message when the rate limiter kicks in.
    return (
        render_template(
            "login.html",
            error="Too many attempts. Please wait a minute and try again.",
        ),
        429,
    )


@app.route("/dashboard")
@login_required
def dashboard():
    resources = db.get_resources_for_user(session["user_id"])
    return render_template(
        "dashboard.html", email=session["email"], resources=resources
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    db.init_schema()
    debug = os.environ.get("FLASK_DEBUG") == "1"

    ssl_context = None
    cert, key = os.environ.get("TLS_CERT"), os.environ.get("TLS_KEY")
    if cert and key:
        ssl_context = (cert, key)
    elif os.environ.get("USE_ADHOC_TLS") == "1":
        ssl_context = "adhoc"

    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=debug, ssl_context=ssl_context)
