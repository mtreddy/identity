"""
spa.py — serves the browser SPA (origin A) that calls the API (origin B).

This is a SEPARATE origin from the API (different port = different origin), which
is what makes the calls cross-origin and subjects them to CORS. Run it alongside
app.py:

    python app.py                        # API on :5000
    PORT=5001 python spa.py              # SPA on :5001  (an allow-listed origin)

Then open http://127.0.0.1:5001/ and click the buttons to watch CORS in the
browser's network tab / console.
"""

import os

from flask import Flask, render_template_string

app = Flask(__name__)
API_BASE = os.environ.get("API_BASE", "http://127.0.0.1:5000")

PAGE = """<!doctype html>
<title>CORS SPA (origin A)</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 34rem; margin: 3rem auto; }
  button { padding:.5rem 1rem; margin:.3rem .3rem 0 0; }
  pre { background:#f4f4f4; padding:.75rem; border-radius:6px; white-space:pre-wrap; }
  code { background:#f4f4f4; padding:.05rem .3rem; border-radius:3px; }
</style>
<h1>Browser SPA (origin A)</h1>
<p>This page's origin differs from the API at <code>{{ api_base }}</code>, so
every call below is <strong>cross-origin</strong> and governed by CORS. Watch the
browser console: a call the API doesn't allow will be blocked <em>by the
browser</em> even though the server responded.</p>

<button onclick="call('/api/data')">GET /api/data (allow-listed)</button>
<button onclick="call('/vuln/data')">GET /vuln/data (reflects any origin)</button>
<pre id="out">(results appear here)</pre>

<script>
const API = "{{ api_base }}";
async function call(path) {
  const out = document.getElementById('out');
  out.textContent = "requesting " + API + path + " …";
  try {
    // Authorization header makes this a "non-simple" request -> the browser
    // sends a preflight OPTIONS first. credentials:'include' sends cookies.
    const r = await fetch(API + path, {
      headers: { 'Authorization': 'Bearer demo-spa-token' },
      credentials: 'include',
    });
    out.textContent = path + " -> " + r.status + "\\n" + JSON.stringify(await r.json(), null, 2);
  } catch (e) {
    out.textContent = path + " -> BLOCKED by the browser (CORS): " + e;
  }
}
</script>
"""


@app.route("/")
def index():
    return render_template_string(PAGE, api_base=API_BASE)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5001"))
    app.run(host="127.0.0.1", port=port, debug=os.environ.get("FLASK_DEBUG") == "1")
