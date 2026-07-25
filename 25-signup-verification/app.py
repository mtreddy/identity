"""
app.py — self-service signup + email verification (user provisioning).

Builds on 05-defense-in-depth (CSRF, rate limiting, password policy, server-side
revocable sessions, auth logging) and adds the *provisioning* front door: how a
brand-new user comes into existence, instead of being hand-seeded.

  /signup   — create an account. The response is IDENTICAL whether or not the
              email was already registered (no account-enumeration oracle); a
              verification link is emailed to a new address, an "you already
              have an account" note to an existing one.
  /verify   — consume the single-use, short-TTL token from the emailed link and
              flip email_verified. Only then can the account sign in.
  /resend   — re-send the verification link, rate-limited so it can't be turned
              into a mail bomb.

The login route carries forward from 05 but adds the verification GATE: correct
credentials for an unverified account do NOT grant a session.

See README.md for the threat model.
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
import mailer
import policy
import verify

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

# How long a verification link stays valid, and where links point. PUBLIC_BASE_URL
# must match where the user's browser reaches the app (the link is absolute).
VERIFY_TTL = int(os.environ.get("VERIFY_TTL", str(verify.DEFAULT_TTL_SECONDS)))
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") == "1",
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=1800,
    SESSION_TYPE="filesystem",
    SESSION_FILE_DIR=os.path.join(os.path.dirname(__file__), ".flask_session"),
    SESSION_PERMANENT=False,
)
Session(app)

csrf = CSRFProtect(app)
limiter = Limiter(key_func=get_remote_address, app=app)
_DUMMY_HASH = bcrypt.hashpw(b"timing-equalizer", bcrypt.gensalt()).decode()

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
        user = db.get_user_by_id(session["user_id"])
        if user is None or user["session_epoch"] != session.get("epoch"):
            session.clear()
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def _login_account_key():
    return request.form.get("email", "").strip().lower() or get_remote_address()


def _verify_url(token: str) -> str:
    """Absolute URL for the emailed link. Prefer PUBLIC_BASE_URL so the link is
    correct even behind a proxy; fall back to the request host."""
    base = PUBLIC_BASE_URL or request.host_url.rstrip("/")
    return f"{base}{url_for('verify_email')}?token={token}"


def _issue_verification(user_id: int, email: str):
    token = verify.generate_token()
    db.create_verification(token, user_id, VERIFY_TTL)
    mailer.send_verification_email(email, _verify_url(token))


# ---------------------------------------------------------------------------
# Signup (provisioning)
# ---------------------------------------------------------------------------

@app.route("/signup", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"], key_func=get_remote_address)
def signup():
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        # Basic shape check; a real system would do fuller RFC 5322 validation.
        if "@" not in email or "." not in email.split("@")[-1]:
            error = "Enter a valid email address."
        else:
            problems = policy.validate_password(password)
            if problems:
                error = "Password " + "; ".join(problems) + "."

        if error is None:
            existing = db.get_user_by_email(email)
            if existing is None:
                user_id = db.create_user(email, password, email_verified=0)
                _issue_verification(user_id, email)
                auth_log.info("signup created (unverified) email=%s ip=%s",
                              email, request.remote_addr)
            else:
                # Do NOT reveal that the address is taken. Notify the real owner
                # out-of-band; the requester sees the same page either way.
                mailer.send_already_registered_email(email)
                auth_log.info("signup for existing email=%s ip=%s (notice sent)",
                              email, request.remote_addr)
            # Identical response in both branches — no enumeration oracle.
            return render_template("check_email.html", email=email)

    return render_template("signup.html", error=error)


@app.route("/verify")
def verify_email():
    token = request.args.get("token", "")
    user_id = db.consume_verification(token) if token else None
    if user_id is None:
        # Covers unknown, already-used, and expired tokens alike (no oracle on
        # which one it was). Offer a fresh link via /signup or /resend.
        auth_log.warning("verification failed ip=%s", request.remote_addr)
        return render_template("verify_result.html", ok=False), 400
    db.mark_email_verified(user_id)
    user = db.get_user_by_id(user_id)
    auth_log.info("email verified email=%s ip=%s", user["email"], request.remote_addr)
    return render_template("verify_result.html", ok=True)


@app.route("/resend", methods=["POST"])
@limiter.limit("3 per hour", methods=["POST"], key_func=get_remote_address)
def resend():
    email = request.form.get("email", "").strip().lower()
    user = db.get_user_by_email(email)
    # Only send if the account exists AND is still unverified. Cap per-account
    # sends in the DB too, so the link can't be spammed to the victim's inbox.
    if (user and not user["email_verified"]
            and db.count_recent_verifications(user["id"], 3600) < 3):
        _issue_verification(user["id"], email)
        auth_log.info("verification resent email=%s ip=%s", email, request.remote_addr)
    # Same response regardless — still no enumeration oracle.
    return render_template("check_email.html", email=email, resent=True)


# ---------------------------------------------------------------------------
# Login (with the verification gate) + protected area, carried from 05
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"], key_func=get_remote_address)
@limiter.limit("5 per minute", methods=["POST"], key_func=_login_account_key)
def login():
    error = unverified_email = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = db.get_user_by_email(email)
        stored_hash = user["password_hash"] if user else _DUMMY_HASH
        password_ok = db.verify_password(password, stored_hash)

        if user and password_ok and user["email_verified"]:
            session.clear()
            session["user_id"] = user["id"]
            session["email"] = user["email"]
            session["epoch"] = user["session_epoch"]
            auth_log.info("login success email=%s ip=%s", email, request.remote_addr)
            return redirect(url_for("dashboard"))

        if user and password_ok and not user["email_verified"]:
            # The gate: correct password, but the email is unproven. Deny the
            # session and let them request a fresh link.
            auth_log.warning("login blocked (unverified) email=%s ip=%s",
                             email, request.remote_addr)
            error = "Please verify your email address before signing in."
            unverified_email = email
        else:
            auth_log.warning("login failure email=%s ip=%s", email, request.remote_addr)
            error = "Invalid email or password."

    return render_template("login.html", error=error, unverified_email=unverified_email)


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


# --- custom error pages (carried from 05) -----------------------------------
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
            error="Too many attempts. Please wait and try again.",
        ),
        429,
    )


@app.errorhandler(404)
def not_found(_e):
    return render_template("404.html"), 404


@app.errorhandler(500)
def server_error(_e):
    return render_template("500.html"), 500


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
