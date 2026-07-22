"""
app.py — web server, hardened step 1.

Adds three deployment/operational hardening features on top of the base
01-login-password example. The application logic (login, session, protected
dashboard) is unchanged; what changes is how the server handles SECRETS,
DEBUGGING, and TRANSPORT.

  Feature 1 — Secret key loaded from the environment (never hard-coded).
  Feature 2 — Debug server OFF by default.
  Feature 3 — TLS/HTTPS support.

See README.md for the threat each one addresses.
"""

import functools
import os

from flask import (
    Flask,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

import db

app = Flask(__name__)

# --- Feature 1: secret key from the environment -----------------------------
# The session cookie is signed with this key. If it is known to an attacker
# (e.g. hard-coded in source that leaks), they can forge a cookie for ANY
# user. We therefore load it from the environment and refuse to start without
# it, so a real secret is a deployment requirement, not an afterthought.
_secret = os.environ.get("SECRET_KEY")
if not _secret:
    raise RuntimeError(
        "SECRET_KEY environment variable is not set.\n"
        "Generate one and export it before starting the server:\n"
        '  export SECRET_KEY="$(python -c \'import secrets;'
        " print(secrets.token_hex(32))')\""
    )
app.secret_key = _secret


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = db.get_user_by_email(email)
        if user and db.verify_password(password, user["password_hash"]):
            session.clear()
            session["user_id"] = user["id"]
            session["email"] = user["email"]
            return redirect(url_for("dashboard"))

        error = "Invalid email or password."

    return render_template("login.html", error=error)


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

    # --- Feature 2: debug OFF by default ------------------------------------
    # Flask's debug mode enables the Werkzeug interactive debugger, which
    # allows arbitrary code execution if it is ever reachable. It must never
    # be on in a shared/production setting. It is opt-in here, local-only.
    debug = os.environ.get("FLASK_DEBUG") == "1"

    # --- Feature 3: TLS / HTTPS ---------------------------------------------
    # Passwords must not travel in cleartext. Provide a real cert+key via
    # TLS_CERT / TLS_KEY (e.g. from mkcert), or set USE_ADHOC_TLS=1 for a
    # throwaway self-signed cert to test HTTPS locally. Without either, it
    # serves plain HTTP (fine for a quick local smoke test only).
    ssl_context = None
    cert, key = os.environ.get("TLS_CERT"), os.environ.get("TLS_KEY")
    if cert and key:
        ssl_context = (cert, key)
    elif os.environ.get("USE_ADHOC_TLS") == "1":
        ssl_context = "adhoc"

    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=debug, ssl_context=ssl_context)
