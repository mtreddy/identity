"""
app.py — web server, hardened step 3.

Carries forward 03-auth-robustness and adds three more defenses:

  Feature 7 — CSRF protection on POST forms (Flask-WTF).
  Feature 8 — Defeat bcrypt's 72-byte truncation (implemented in db.py).
  Feature 9 — Security response headers.

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
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError

import db

app = Flask(__name__)

_secret = os.environ.get("SECRET_KEY")
if not _secret:
    raise RuntimeError(
        "SECRET_KEY environment variable is not set.\n"
        "Generate one and export it before starting the server:\n"
        '  export SECRET_KEY="$(python -c \'import secrets;'
        " print(secrets.token_hex(32))')\""
    )
app.secret_key = _secret

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") == "1",
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=1800,
)

# --- Feature 7: CSRF protection ---------------------------------------------
# CSRFProtect requires every POST to carry a valid, session-bound token
# (rendered into forms via {{ csrf_token() }}). A malicious site that
# auto-submits a form to us can't know the token, so forged requests fail.
csrf = CSRFProtect(app)

limiter = Limiter(key_func=get_remote_address, app=app)

# Timing equalizer (Feature 6). db.verify_password re-hashes the input the
# same way for real and dummy users, so both branches cost the same.
_DUMMY_HASH = bcrypt.hashpw(b"timing-equalizer", bcrypt.gensalt()).decode()


# --- Feature 9: security headers on every response --------------------------
@app.after_request
def set_security_headers(resp):
    # Stop the browser from MIME-sniffing responses into a different type.
    resp.headers["X-Content-Type-Options"] = "nosniff"
    # Disallow framing -> clickjacking protection for the login page.
    resp.headers["X-Frame-Options"] = "DENY"
    # Minimal CSP: only load resources from our own origin. (Inline <style> in
    # the templates is allowed via 'unsafe-inline' to keep the demo simple;
    # move CSS to a file and drop that in a stricter build.)
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "frame-ancestors 'none'"
    )
    resp.headers["Referrer-Policy"] = "no-referrer"
    # HSTS only matters over HTTPS; harmless (ignored) on plain HTTP.
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def _login_account_key():
    return request.form.get("email", "").strip().lower() or get_remote_address()


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"], key_func=get_remote_address)
@limiter.limit("5 per minute", methods=["POST"], key_func=_login_account_key)
def login():
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = db.get_user_by_email(email)
        stored_hash = user["password_hash"] if user else _DUMMY_HASH
        password_ok = db.verify_password(password, stored_hash)

        if user and password_ok:
            session.clear()
            session["user_id"] = user["id"]
            session["email"] = user["email"]
            return redirect(url_for("dashboard"))

        error = "Invalid email or password."

    return render_template("login.html", error=error)


@app.errorhandler(CSRFError)
def handle_csrf_error(_e):
    return (
        render_template(
            "login.html",
            error="Your session expired or the form was invalid. Try again.",
        ),
        400,
    )


@app.errorhandler(429)
def too_many_requests(_e):
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
