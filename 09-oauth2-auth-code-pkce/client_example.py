"""
client_example.py — drive the raw Authorization Code + PKCE protocol.

This one script plays BOTH the user's browser (login + consent) and the OAuth
client (PKCE + token exchange), so you can watch every message without a
browser. The demo client pages in app.py (/client/*) do the same thing for a
human; this is the scriptable/testable version.

    API_BASE=http://127.0.0.1:5000 python client_example.py

It expects seed.py to have registered the client with a redirect_uri that
matches API_BASE (set PUBLIC_BASE_URL when seeding to line them up).
"""

import html
import http.cookiejar
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

import oauth

BASE = os.environ.get("API_BASE", "http://127.0.0.1:5000").rstrip("/")
CLIENT_ID = "demo-web-app"
SCOPE = "profile resources:read"
REDIRECT_URI = BASE + "/client/callback"

USER_EMAIL = "user@example.com"
USER_PASSWORD = "correct-horse-battery-staple"

# A cookie jar carries the login session; disable auto-redirects so we can see
# each 302 (and read the authorization code out of the final Location).
_jar = http.cookiejar.CookieJar()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPCookieProcessor(_jar))


def _open(method, url, data=None):
    body = urllib.parse.urlencode(data).encode() if data else None
    req = urllib.request.Request(url, data=body, method=method)
    try:
        r = _opener.open(req)
        return r.status, r.headers, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode()


def _abs(loc):
    return loc if loc.startswith("http") else BASE + loc


def _field(page, name):
    # HTML-unescape the attribute value, exactly as a browser would before it
    # re-submits the form (e.g. '&amp;' in the 'next' URL becomes '&').
    m = re.search(r'name="%s"\s+value="([^"]*)"' % re.escape(name), page)
    return html.unescape(m.group(1)) if m else ""


def main():
    # The CLIENT creates PKCE + state.
    verifier = oauth.generate_code_verifier()
    state = oauth.generate_state()
    authorize_url = BASE + "/authorize?" + urllib.parse.urlencode({
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
        "state": state,
        "code_challenge": oauth.code_challenge_s256(verifier),
        "code_challenge_method": "S256",
    })

    # 1. /authorize -> not logged in -> redirect to /login
    st, hdr, _ = _open("GET", authorize_url)
    print(f"1. GET /authorize            -> {st} -> {hdr.get('Location')}")
    login_url = _abs(hdr["Location"])

    # 2. load the login form (grab CSRF + next)
    st, _, html = _open("GET", login_url)
    csrf, nxt = _field(html, "csrf_token"), _field(html, "next")
    print(f"2. GET /login                -> {st} (csrf acquired)")

    # 3. submit credentials -> redirect back to /authorize
    st, hdr, _ = _open("POST", BASE + "/login", {
        "csrf_token": csrf, "next": nxt,
        "email": USER_EMAIL, "password": USER_PASSWORD,
    })
    print(f"3. POST /login               -> {st} -> {hdr.get('Location')}")

    # 4. /authorize again (authenticated) -> consent page
    st, _, html = _open("GET", _abs(hdr["Location"]))
    print(f"4. GET /authorize (auth'd)   -> {st} (consent screen)")
    form = {k: _field(html, k) for k in (
        "csrf_token", "client_id", "redirect_uri", "scope", "state",
        "code_challenge", "code_challenge_method",
    )}

    # 5. approve consent -> redirect to redirect_uri?code=...&state=...
    st, hdr, _ = _open("POST", BASE + "/authorize/decision", {**form, "decision": "approve"})
    loc = hdr["Location"]
    print(f"5. POST /authorize/decision  -> {st} -> {loc}")
    q = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
    code, ret_state = q["code"][0], q["state"][0]
    assert ret_state == state, "state mismatch!"
    print(f"   state verified, code = {code[:10]}…")

    # 6. exchange the code for a token (PKCE verifier revealed here)
    st, _, body = _open("POST", BASE + "/token", {
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": REDIRECT_URI, "client_id": CLIENT_ID,
        "code_verifier": verifier,
    })
    tok = json.loads(body)
    print(f"6. POST /token               -> {st} scope={tok.get('scope')!r}")

    # 7. call the resource server with the access token
    def api(path):
        req = urllib.request.Request(BASE + path)
        req.add_header("Authorization", "Bearer " + tok["access_token"])
        with urllib.request.urlopen(req) as r:
            return r.status, json.load(r)
    print(f"7. GET /api/userinfo         -> {api('/api/userinfo')}")
    print(f"   GET /api/resources        -> {api('/api/resources')}")

    # 8. codes are one-time: replay must fail
    st, _, body = _open("POST", BASE + "/token", {
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": REDIRECT_URI, "client_id": CLIENT_ID,
        "code_verifier": verifier,
    })
    print(f"8. POST /token (replay code) -> {st} {body.strip()}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # noqa
        print(f"FAILED: {type(e).__name__}: {e}")
        sys.exit(1)
