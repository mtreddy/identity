"""
app.py — web server, hardened step 4 (final: everything else).

Carries forward 04-web-hardening and adds the remaining defense-in-depth items:

  Feature 10 — Server-side, revocable sessions ("log out everywhere").
  Feature 11 — Password policy (length + breached/common rejection).
  Feature 12 — Authentication logging (never logs the password).
  Feature 13 — Custom error pages (no stack traces leak to users).

A protected /change-password route is added so Features 10 and 11 are
actually exercised end to end.
"""

import functools
import logging
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
from flask_session import Session
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError

import db
import policy

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

# --- Feature 10: server-side sessions ---------------------------------------
# With the default Flask setup the entire session lives in the (signed) cookie,
# so the server cannot revoke it. Here session DATA is stored server-side (the
# cookie holds only an opaque id), which makes sessions individually revocable
# and is the foundation for "log out everywhere" via the session_epoch check
# below.
app.config.update(
    SESSION_TYPE="filesystem",
    SESSION_FILE_DIR=os.path.join(os.path.dirname(__file__), ".flask_session"),
    SESSION_PERMANENT=False,
)
Session(app)

csrf = CSRFProtect(app)
limiter = Limiter(key_func=get_remote_address, app=app)
_DUMMY_HASH = bcrypt.hashpw(b"timing-equalizer", bcrypt.gensalt()).decode()

# --- Feature 12: authentication logging -------------------------------------
# A dedicated logger for security-relevant auth events. It records WHO/WHERE/
# WHAT (email, source IP, outcome) and NEVER the password. In production this
# would feed a SIEM / alerting so brute-force and takeover attempts are seen.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(os.path.dirname(__file__), "auth.log")),
        logging.StreamHandler(),
    ],
)
auth_log = logging.getLogger("auth")


@app.after_request
def set_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "frame-ancestors 'none'"
    )
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        # Feature 10: reject sessions whose epoch is stale (e.g. after the
        # user changed their password on another device).
        user = db.get_user_by_id(session["user_id"])
        if user is None or user["session_epoch"] != session.get("epoch"):
            session.clear()
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
            session["epoch"] = user["session_epoch"]  # Feature 10
            auth_log.info("login success email=%s ip=%s", email, request.remote_addr)
            return redirect(url_for("dashboard"))

        # Feature 12: record the failure (no password in the log).
        auth_log.warning("login failure email=%s ip=%s", email, request.remote_addr)
        error = "Invalid email or password."

    return render_template("login.html", error=error)


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    error = ok = None
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        user = db.get_user_by_id(session["user_id"])

        if not db.verify_password(current, user["password_hash"]):
            error = "Current password is incorrect."
            auth_log.warning(
                "password-change denied (bad current) email=%s ip=%s",
                user["email"], request.remote_addr,
            )
        else:
            # Feature 11: enforce the password policy.
            problems = policy.validate_password(new)
            if problems:
                error = "New password " + "; ".join(problems) + "."
            else:
                # Feature 10: bump epoch -> all OTHER sessions are invalidated.
                new_epoch = db.update_password(user["id"], new)
                session["epoch"] = new_epoch  # keep THIS session valid
                auth_log.info(
                    "password changed email=%s ip=%s (other sessions revoked)",
                    user["email"], request.remote_addr,
                )
                ok = "Password changed. All other sessions have been logged out."

    return render_template("change_password.html", error=error, ok=ok)


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


# --- Feature 13: custom error pages (no stack traces to users) --------------
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


@app.errorhandler(404)
def not_found(_e):
    return render_template("404.html"), 404


@app.errorhandler(500)
def server_error(_e):
    # debug=False guarantees the raw traceback is never shown to the client.
    return render_template("500.html"), 500


# Opt-in route (TEST_ERRORS=1) to verify the 500 page renders cleanly.
if os.environ.get("TEST_ERRORS") == "1":
    @app.route("/__boom")
    def _boom():
        raise RuntimeError("intentional error for testing the 500 page")


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
