"""
client_example.py — drive Dynamic Client Registration end to end, without a
browser:

    register (RFC 7591)  ->  read/update (RFC 7592)  ->  run the OAuth flow with
    the freshly-registered client  ->  delete it

It plays both the registrant (machine-to-machine JSON at /register) and, for the
authorization step, the user's browser (login + consent) and the client (PKCE +
token exchange) — the same raw flow as 09, but against a client that provisioned
itself moments earlier.

    API_BASE=http://127.0.0.1:5000 REGISTRATION_TOKEN=... python client_example.py
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
INITIAL_TOKEN = os.environ.get("REGISTRATION_TOKEN", "")
USER_EMAIL = "user@example.com"
USER_PASSWORD = "correct-horse-battery-staple"

_jar = http.cookiejar.CookieJar()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPCookieProcessor(_jar))


def _open(method, url, data=None, headers=None):
    body = urllib.parse.urlencode(data).encode() if data else None
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        r = _opener.open(req)
        return r.status, r.headers, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode()


def _json(method, url, body=None, bearer=None):
    """A JSON request to the registration endpoints."""
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if bearer:
        headers["Authorization"] = "Bearer " + bearer
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        r = _opener.open(req)
        text = r.read().decode()
        return r.status, (json.loads(text) if text else {})
    except urllib.error.HTTPError as e:
        text = e.read().decode()
        return e.code, (json.loads(text) if text else {})


def _field(page, name):
    m = re.search(r'name="%s"\s+value="([^"]*)"' % re.escape(name), page)
    return html.unescape(m.group(1)) if m else ""


def register(metadata, bearer=None):
    return _json("POST", BASE + "/register", metadata, bearer or INITIAL_TOKEN)


def run_oauth_flow(client_id, redirect_uri, scope, client_secret=None):
    """Login + consent + PKCE token exchange with the given client. Returns
    (status, token_json). Starts from a fresh (logged-out) cookie jar."""
    _jar.clear()
    verifier, state = oauth.generate_code_verifier(), oauth.generate_state()
    authorize_url = BASE + "/authorize?" + urllib.parse.urlencode({
        "response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri,
        "scope": scope, "state": state,
        "code_challenge": oauth.code_challenge_s256(verifier),
        "code_challenge_method": "S256"})

    _, hdr, _ = _open("GET", authorize_url)                  # -> /login (or error)
    loc = hdr.get("Location") or ""
    if "error=" in loc:
        # /authorize bounced back to redirect_uri with an OAuth error (e.g. the
        # requested scope wasn't granted) — no code, so no token.
        err = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query).get("error", [""])[0]
        return 400, {"error": err}
    _, _, page = _open("GET", loc if loc.startswith("http") else BASE + loc)
    csrf, nxt = _field(page, "csrf_token"), _field(page, "next")
    _, hdr, _ = _open("POST", BASE + "/login",
                      {"csrf_token": csrf, "next": nxt,
                       "email": USER_EMAIL, "password": USER_PASSWORD})
    _, _, page = _open("GET", hdr["Location"] if hdr["Location"].startswith("http")
                       else BASE + hdr["Location"])          # consent screen
    form = {k: _field(page, k) for k in ("csrf_token", "client_id", "redirect_uri",
            "scope", "state", "code_challenge", "code_challenge_method")}
    _, hdr, _ = _open("POST", BASE + "/authorize/decision", {**form, "decision": "approve"})
    code = urllib.parse.parse_qs(urllib.parse.urlparse(hdr["Location"]).query)["code"][0]

    token_req = {"grant_type": "authorization_code", "code": code,
                 "redirect_uri": redirect_uri, "client_id": client_id,
                 "code_verifier": verifier}
    if client_secret:
        token_req["client_secret"] = client_secret       # client_secret_post
    st, _, body = _open("POST", BASE + "/token", token_req)
    return st, json.loads(body)


def main():
    redirect_uri = BASE + "/cb"

    # 1. Register a public client (RFC 7591).
    st, info = register({
        "client_name": "cli-registered-app",
        "redirect_uris": [redirect_uri],
        "token_endpoint_auth_method": "none",
        "scope": "profile resources:read",
    })
    assert st == 201, f"registration failed: {st} {info}"
    client_id = info["client_id"]
    rat = info["registration_access_token"]
    assert info.get("client_secret") is None, "public client must not get a secret"
    print(f"1. POST /register            -> 201 client_id={client_id}")
    print(f"   registration_access_token = {rat[:12]}…  (kept for management)")

    # 2. Read it back with the registration access token (RFC 7592).
    st, got = _json("GET", info["registration_client_uri"], bearer=rat)
    assert st == 200 and got["client_id"] == client_id, f"read failed: {st} {got}"
    print(f"2. GET  /register/{{id}}       -> 200 name={got['client_name']!r}")

    # 3. Use the freshly-registered client in the real OAuth flow.
    st, tok = run_oauth_flow(client_id, redirect_uri, "profile resources:read")
    assert st == 200 and tok.get("access_token"), f"token exchange failed: {st} {tok}"

    def api(path):
        _, _, body = _open("GET", BASE + path,
                           headers={"Authorization": "Bearer " + tok["access_token"]})
        return json.loads(body)
    ui = api("/api/userinfo")
    print(f"3. OAuth flow w/ new client  -> 200 token for {ui.get('email')}, "
          f"{len(api('/api/resources')['resources'])} resources")

    # 4. Update the client (RFC 7592 PUT) — change its name and narrow scope.
    st, updated = _json("PUT", info["registration_client_uri"], {
        "client_name": "cli-registered-app (renamed)",
        "redirect_uris": [redirect_uri],
        "token_endpoint_auth_method": "none",
        "scope": "profile",
    }, bearer=rat)
    assert st == 200 and updated["client_name"].endswith("(renamed)"), f"update failed: {st}"
    print(f"4. PUT  /register/{{id}}       -> 200 name={updated['client_name']!r}")

    # 5. Delete the client (RFC 7592 DELETE); afterwards management 401s.
    st, _, _ = _open("DELETE", info["registration_client_uri"],
                     headers={"Authorization": "Bearer " + rat})
    assert st == 204, f"delete failed: {st}"
    st_after, _ = _json("GET", info["registration_client_uri"], bearer=rat)
    assert st_after == 401, f"deleted client should 401, got {st_after}"
    print(f"5. DELETE /register/{{id}}     -> 204, subsequent GET -> {st_after}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # noqa
        print(f"FAILED: {type(e).__name__}: {e}")
        sys.exit(1)
