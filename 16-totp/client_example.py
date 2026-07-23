"""
client_example.py — drive the two-step (password + TOTP) login.

Computes the current TOTP code from the shared secret (as an authenticator app
would) and shows: full login works, a wrong code is refused, and the protected
page is unreachable without the second factor.

    TOTP_SECRET=<from seed.py> python client_example.py
"""

import html
import http.cookiejar
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

import totp

BASE = os.environ.get("API_BASE", "http://127.0.0.1:5000").rstrip("/")
EMAIL = "user@example.com"
PASSWORD = "correct-horse-battery-staple"
SECRET = os.environ.get("TOTP_SECRET")


def opener():
    jar = http.cookiejar.CookieJar()

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    return urllib.request.build_opener(NoRedirect, urllib.request.HTTPCookieProcessor(jar))


def _open(op, method, path, data=None):
    body = urllib.parse.urlencode(data).encode() if data else None
    req = urllib.request.Request(BASE + path, data=body, method=method)
    try:
        r = op.open(req)
        return r.status, r.headers, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode()


def csrf(page):
    m = re.search(r'name="csrf_token"\s+value="([^"]*)"', page)
    return html.unescape(m.group(1)) if m else ""


def password_step(op):
    _, _, page = _open(op, "GET", "/login")
    st, hdr, _ = _open(op, "POST", "/login",
                       {"csrf_token": csrf(page), "email": EMAIL, "password": PASSWORD})
    return st, hdr.get("Location")


def main():
    if not SECRET:
        print("Set TOTP_SECRET (printed by seed.py)."); sys.exit(2)

    # 1. password -> redirected to /verify (pending session, not yet in)
    op = opener()
    st, loc = password_step(op)
    print(f"1. POST /login (password)      -> {st} -> {loc}")
    print(f"   GET / before 2FA            -> {_open(op, 'GET', '/')[0]} (302 = blocked, needs code)")

    # 2. wrong code is refused
    _, _, vpage = _open(op, "GET", "/verify")
    st, _, page = _open(op, "POST", "/verify", {"csrf_token": csrf(vpage), "code": "000000"})
    bad = re.search(r'class="error">(.*?)<', page)
    print(f"2. POST /verify wrong code     -> {st} ({bad.group(1) if bad else ''})")

    # 3. correct current code -> full session
    _, _, vpage = _open(op, "GET", "/verify")
    st, hdr, _ = _open(op, "POST", "/verify",
                       {"csrf_token": csrf(vpage), "code": totp.now_code(SECRET)})
    print(f"3. POST /verify correct code   -> {st} -> {hdr.get('Location')}")
    st, _, page = _open(op, "GET", "/")
    who = re.search(r"<strong>(.*?)</strong>", page)
    print(f"   GET / after 2FA             -> {st} signed in as: {who.group(1) if who else '?'}")


if __name__ == "__main__":
    main()
