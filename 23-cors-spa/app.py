"""
app.py — the API server (origin B) with CORS.

CORS (Cross-Origin Resource Sharing) is what lets a browser page on ONE origin
(the SPA, origin A) read a response from an API on a DIFFERENT origin (origin B).
By default the same-origin policy blocks that; the API must opt in by returning
`Access-Control-Allow-Origin` (and friends). CORS is enforced by the BROWSER,
not the server: the server always runs the request, but the browser only exposes
the response to the page if the CORS headers permit it.

Key idea this demo makes concrete: **CORS is a relaxation of the same-origin
policy, not a security feature.** Getting it wrong — reflecting any `Origin` with
credentials — lets *any* website read your users' authenticated data.

Endpoints:
  GET/OPTIONS /api/data    — CORS done right: an explicit origin ALLOW-LIST
  GET/OPTIONS /vuln/data   — the classic MISCONFIG: reflect any Origin + creds
  GET /                    — hint page

Run the SPA (origin A) with `python spa.py` and open it in a browser.
"""

import os

from flask import Flask, jsonify, request

app = Flask(__name__)

# The allow-list: only these origins may read authenticated responses. Never
# use "*" with credentials (browsers reject that combination anyway).
ALLOWED_ORIGINS = set(filter(None, os.environ.get(
    "ALLOWED_ORIGINS", "http://127.0.0.1:5001,http://localhost:5001").split(",")))
API_TOKEN = os.environ.get("API_TOKEN", "demo-spa-token")


def _allowed(origin):
    return origin if origin in ALLOWED_ORIGINS else None


@app.route("/api/data", methods=["GET", "OPTIONS"])
def api_data():
    """CORS done right: allow-list check; credentials only for allow-listed
    origins; `Vary: Origin` so caches don't mix responses across origins."""
    origin = request.headers.get("Origin")
    allow = _allowed(origin)

    if request.method == "OPTIONS":               # preflight
        resp = app.response_class(status=204)
        resp.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        resp.headers["Access-Control-Max-Age"] = "600"
        if allow:
            resp.headers["Access-Control-Allow-Origin"] = allow
            resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers["Vary"] = "Origin"
        return resp

    if request.headers.get("Authorization") != f"Bearer {API_TOKEN}":
        resp = jsonify(error="unauthorized")
        resp.status_code = 401
    else:
        resp = jsonify(data=["Q3 revenue: $4.2M", "roadmap: launch in Nov"])

    # Expose the response ONLY to allow-listed origins.
    if allow:
        resp.headers["Access-Control-Allow-Origin"] = allow
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    resp.headers["Vary"] = "Origin"
    return resp


@app.route("/vuln/data", methods=["GET", "OPTIONS"])
def vuln_data():
    """MISCONFIGURATION (do NOT do this): reflect whatever Origin asked, with
    credentials. Any website a logged-in user visits can now read this API's
    authenticated responses."""
    origin = request.headers.get("Origin", "")

    if request.method == "OPTIONS":
        resp = app.response_class(status=204)
        resp.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
    else:
        resp = jsonify(data=["Q3 revenue: $4.2M", "roadmap: launch in Nov"])

    if origin:
        resp.headers["Access-Control-Allow-Origin"] = origin        # DANGER: reflected
        resp.headers["Access-Control-Allow-Credentials"] = "true"    # DANGER: with creds
    return resp


@app.route("/")
def index():
    return app.response_class(
        "CORS API (origin B). Allowed SPA origins: "
        + ", ".join(sorted(ALLOWED_ORIGINS))
        + "\nTry: /api/data (allow-listed) and /vuln/data (reflects any origin)\n",
        mimetype="text/plain")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=os.environ.get("FLASK_DEBUG") == "1")
