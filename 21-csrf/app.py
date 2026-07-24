"""
app.py — CSRF attack vs. defense, side by side.

A teaching demo. A logged-in user has a state-changing action ("change my
account email"). The same action is exposed two ways:

  POST /vuln/change-email   — NO CSRF protection
  POST /safe/change-email   — requires a synchronizer CSRF token

An attacker page on another origin (served at /attacker to stand in for
evil.example) auto-submits a cross-site form. Because the victim's browser
attaches their session cookie automatically, the forged request is
*authenticated* — but the attacker can't supply the secret CSRF token. So the
/vuln action succeeds (account takeover) and the /safe action is rejected.

Three defenses appear here (all used elsewhere in this repo):
  1. Synchronizer token (Flask-WTF) — /safe requires {{ csrf_token() }}.
  2. SameSite cookie — a modern browser won't even send the cookie on a
     cross-site POST (set COOKIE_SAMESITE=None to simulate a legacy/relaxed
     cookie and watch the token become the deciding defense).
  3. (elsewhere) OAuth `state` — the redirect-flow analog, see mechanism 09.

The /vuln endpoint is intentionally exploitable; this is a sandbox.
"""

import os

from flask import (
    Flask, jsonify, redirect, render_template, request, session, url_for,
)
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-csrf-demo-key")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") == "1",
    # Defense 2: SameSite. Default Lax already blocks cross-site POST cookies;
    # set COOKIE_SAMESITE=None to opt out and demonstrate the token defense.
    SESSION_COOKIE_SAMESITE=os.environ.get("COOKIE_SAMESITE", "Lax"),
)
csrf = CSRFProtect(app)


@app.errorhandler(CSRFError)
def _csrf_error(e):
    return jsonify(error="csrf_validation_failed", detail=e.description), 403


def _logged_in():
    return "user" in session


@app.route("/login")
def login():
    # Trivial login to establish a session (the focus is CSRF, not auth).
    session["user"] = "alice"
    session.setdefault("email", "alice@example.com")
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("dashboard"))


@app.route("/")
def dashboard():
    if not _logged_in():
        return render_template("login.html")
    return render_template("dashboard.html", email=session.get("email"))


@app.route("/vuln/change-email", methods=["POST"])
@csrf.exempt   # DANGER: no CSRF protection — forgeable across sites.
def vuln_change_email():
    if not _logged_in():
        return jsonify(error="unauthorized"), 401
    session["email"] = request.form.get("email", "")
    return jsonify(status="ok", protected=False, email=session["email"])


@app.route("/safe/change-email", methods=["POST"])
def safe_change_email():
    # CSRFProtect requires a valid, session-bound token on this POST.
    if not _logged_in():
        return jsonify(error="unauthorized"), 401
    session["email"] = request.form.get("email", "")
    return jsonify(status="ok", protected=True, email=session["email"])


@app.route("/attacker")
def attacker():
    """Stands in for a malicious page on a DIFFERENT origin (evil.example)."""
    return render_template("attacker.html", target=request.host_url.rstrip("/"))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=os.environ.get("FLASK_DEBUG") == "1")
