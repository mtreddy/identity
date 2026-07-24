"""
app.py — XSS attack vs. defense, side by side.

A teaching demo. User input is rendered back into a page two ways:

  /vuln/search, /vuln/comments   — input concatenated into HTML (NOT escaped)
  /safe/search, /safe/comments   — input rendered through Jinja (auto-escaped),
                                   and served with a Content-Security-Policy

If a page reflects/stores `<script>…</script>` (or an `onerror=` handler)
without encoding it, the browser runs it as code in the victim's session — that
is Cross-Site Scripting. The fix is **contextual output encoding**: treat user
input as text, so `<script>` becomes the harmless characters `&lt;script&gt;`.

Layers shown here:
  1. Output encoding (Jinja autoescaping) — the primary fix, on /safe.
  2. Content-Security-Policy — on /safe responses; blocks inline script as a
     second line of defense even if an encoding bug slips through.
  3. HttpOnly session cookie — so a successful XSS still can't read the session
     cookie via document.cookie.

The /vuln endpoints are intentionally exploitable; this is a sandbox.
"""

import os

from flask import Flask, render_template, render_template_string, request, session

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-xss-demo-key")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,   # defense 3: JS can't read the session cookie
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") == "1",
    SESSION_COOKIE_SAMESITE="Lax",
)

# In-memory "stored" content (reset on restart).
COMMENTS_VULN, COMMENTS_SAFE = [], []

CSP = ("default-src 'self'; script-src 'self'; object-src 'none'; "
       "base-uri 'none'; frame-ancestors 'none'")


@app.after_request
def _headers(resp):
    # Defense 2: apply a Content-Security-Policy to the SAFE responses. (The
    # /vuln responses deliberately omit it so you can see what a page without
    # CSP allows.)
    if request.path.startswith("/safe"):
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


@app.route("/")
def index():
    session["seen"] = True   # set an HttpOnly session cookie
    return render_template("index.html")


# --- reflected XSS ----------------------------------------------------------

@app.route("/vuln/search")
def vuln_search():
    q = request.args.get("q", "")
    # DANGER: user input concatenated straight into the HTML response.
    return (f"<!doctype html><h1>Results</h1>"
            f"<p>You searched for: {q}</p>"
            f'<p><a href="/">back</a></p>')


@app.route("/safe/search")
def safe_search():
    q = request.args.get("q", "")
    # SAFE: Jinja auto-escapes {{ q }} -> '<' becomes '&lt;', so it's inert text.
    return render_template_string(
        "<!doctype html><h1>Results</h1><p>You searched for: {{ q }}</p>"
        '<p><a href="/">back</a></p>', q=q)


# --- stored XSS -------------------------------------------------------------

@app.route("/vuln/comments", methods=["GET", "POST"])
def vuln_comments():
    if request.method == "POST":
        COMMENTS_VULN.append(request.form.get("comment", ""))
    # DANGER: stored comments rendered without escaping.
    items = "".join(f"<li>{c}</li>" for c in COMMENTS_VULN)
    return (f"<!doctype html><h1>Comments (vuln)</h1><ul>{items}</ul>"
            '<form method="post"><input name="comment"><button>Post</button></form>')


@app.route("/safe/comments", methods=["GET", "POST"])
def safe_comments():
    if request.method == "POST":
        COMMENTS_SAFE.append(request.form.get("comment", ""))
    return render_template("comments.html", comments=COMMENTS_SAFE)


# --- DOM-based XSS (browser-only; documented) -------------------------------

@app.route("/dom")
def dom():
    return render_template("dom.html")


# convenience: what does document.cookie expose? (HttpOnly hides the session)
@app.route("/whoami")
def whoami():
    return {"note": "the session cookie is HttpOnly, so document.cookie can't read it"}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=os.environ.get("FLASK_DEBUG") == "1")
