"""
app.py — password login (mechanism 01) + a TOTP second factor.

Login is two steps when TOTP is enabled:

  1. POST /login   email + password  -> a PENDING session (factor 1 done)
  2. POST /verify  6-digit TOTP code  -> a FULL session (factor 2 done)

Only a full session may see /dashboard. /setup enrolls (or re-enrolls) TOTP by
showing the otpauth URI and requiring one valid code to confirm the secret.
"""

import functools
import os
import time

from flask import (
    Flask, redirect, render_template, request, session, url_for,
)
from flask_wtf import CSRFProtect

import db
import totp

ISSUER = "identity-16"

app = Flask(__name__)
_secret = os.environ.get("SECRET_KEY")
if not _secret:
    raise RuntimeError("SECRET_KEY is not set (needed for the session cookie).")
app.secret_key = _secret
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") == "1")
csrf = CSRFProtect(app)

# Brute-force defense: a 6-digit code has only 10^6 values, so throttle attempts
# per pending user. In-memory for the demo.
_ATTEMPTS: dict[int, list[float]] = {}
MAX_ATTEMPTS = 5
WINDOW_SECONDS = 60


def _rate_limited(uid: int) -> bool:
    now = time.time()
    hits = [t for t in _ATTEMPTS.get(uid, []) if now - t < WINDOW_SECONDS]
    _ATTEMPTS[uid] = hits
    return len(hits) >= MAX_ATTEMPTS


def _record_attempt(uid: int):
    _ATTEMPTS.setdefault(uid, []).append(time.time())


def login_required(view):
    @functools.wraps(view)
    def wrapped(*a, **k):
        if "uid" not in session:
            return redirect(url_for("login"))
        return view(*a, **k)
    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = db.get_user_by_email(email)
        if user and db.verify_password(request.form.get("password", ""), user["password_hash"]):
            session.clear()
            if user["totp_enabled"]:
                session["pending_uid"] = user["id"]   # factor 1 only
                return redirect(url_for("verify"))
            session["uid"] = user["id"]                # no 2FA configured
            return redirect(url_for("dashboard"))
        error = "Invalid email or password."
    return render_template("login.html", error=error)


@app.route("/verify", methods=["GET", "POST"])
def verify():
    uid = session.get("pending_uid")
    if not uid:
        return redirect(url_for("login"))
    error = None
    if request.method == "POST":
        if _rate_limited(uid):
            error = "Too many attempts. Wait a minute and try again."
        else:
            _record_attempt(uid)
            user = db.get_user_by_id(uid)
            if totp.verify(user["totp_secret"], request.form.get("code", "").strip()):
                session.pop("pending_uid", None)
                session["uid"] = uid                  # factor 2 done -> full session
                _ATTEMPTS.pop(uid, None)
                return redirect(url_for("dashboard"))
            error = "Invalid code."
    return render_template("verify.html", error=error)


@app.route("/")
@login_required
def dashboard():
    user = db.get_user_by_id(session["uid"])
    return render_template("dashboard.html", user=user)


@app.route("/setup", methods=["GET", "POST"])
@login_required
def setup():
    user = db.get_user_by_id(session["uid"])
    if "setup_secret" not in session:
        session["setup_secret"] = totp.generate_secret()
    secret = session["setup_secret"]
    message = error = None
    if request.method == "POST":
        if totp.verify(secret, request.form.get("code", "").strip()):
            db.set_totp(user["id"], secret, True)
            session.pop("setup_secret", None)
            message = "Two-factor authentication is now enabled."
            secret = None
        else:
            error = "That code didn't match — try the current one."
    uri = totp.provisioning_uri(secret, user["email"], ISSUER) if secret else None
    return render_template("setup.html", secret=secret, uri=uri,
                           enabled=user["totp_enabled"], message=message, error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    db.init_schema()
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=os.environ.get("FLASK_DEBUG") == "1")
