"""
app.py — the web server (the "front door").

This ties the mechanism together:

  1. GET  /login      -> show the login form
  2. POST /login      -> verify email + password against the DB (db.verify_password)
                         if valid, mark the browser session as authenticated
  3. GET  /dashboard  -> a PROTECTED page; only reachable when logged in.
                         Shows the user's resources from the DB.
  4. GET  /logout     -> clear the session

Authentication state is kept in a Flask *session cookie*. Flask signs this
cookie with SECRET_KEY so the browser can't forge "I am alice". The cookie
only stores the user id/email — never the password.
"""

import functools

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
# In a real app this comes from an environment variable / secret manager and
# must be long and random. Hard-coded here only so the example runs stand-alone.
app.secret_key = "dev-only-insecure-secret-change-me"


def login_required(view):
    """Decorator: bounce anonymous visitors to /login.

    This is how a route becomes a "protected resource".
    """

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

        # Note: we give the SAME generic error whether the email is unknown or
        # the password is wrong. Telling an attacker "that email exists but the
        # password is wrong" would leak which accounts are real.
        if user and db.verify_password(password, user["password_hash"]):
            # Success: record who is logged in, in the signed session cookie.
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
    # Ensure the schema exists so the server can start even before seeding.
    db.init_schema()
    # 127.0.0.1 keeps this bound to your machine only.
    app.run(host="127.0.0.1", port=5000, debug=True)
