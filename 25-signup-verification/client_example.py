"""
client_example.py — drive the whole provisioning flow without a browser:

    signup  ->  read the emailed link  ->  verify  ->  login

Email delivery is stubbed (see mailer.py), so instead of a mailbox we read the
verification link out of outbox.log — standing in for "the user opened the
email and clicked the link". Everything else is the real HTTP flow, CSRF tokens
and all.

    API_BASE=http://127.0.0.1:5000 python client_example.py
"""

import html
import http.cookiejar
import os
import re
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get("API_BASE", "http://127.0.0.1:5000").rstrip("/")
OUTBOX = os.path.join(os.path.dirname(__file__), "outbox.log")

# A unique address per run so re-runs don't collide on the UNIQUE(email) index.
NEW_EMAIL = f"newuser-{secrets.token_hex(4)}@example.com"
NEW_PASSWORD = "a-Very-Strong-Passphrase-2026"

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


def _field(page, name):
    m = re.search(r'name="%s"\s+value="([^"]*)"' % re.escape(name), page)
    return html.unescape(m.group(1)) if m else ""


def link_for(email):
    """Pull the newest verification link addressed to `email` out of outbox.log
    — i.e. read the email the user would have received."""
    text = open(OUTBOX).read() if os.path.exists(OUTBOX) else ""
    # Split into individual messages and take the last one to this recipient.
    found = None
    for chunk in text.split("-" * 60):
        if f"To: {email}" in chunk and "/verify?token=" in chunk:
            m = re.search(r"(https?://\S+/verify\?token=\S+)", chunk)
            if m:
                found = m.group(1)
    return found


def signup(email, password):
    _, _, page = _open("GET", BASE + "/signup")
    st, _, page = _open("POST", BASE + "/signup",
                        {"csrf_token": _field(page, "csrf_token"),
                         "email": email, "password": password})
    return st, page


def verify(url):
    return _open("GET", url)


def login(email, password):
    _, _, page = _open("GET", BASE + "/login")
    return _open("POST", BASE + "/login",
                 {"csrf_token": _field(page, "csrf_token"),
                  "email": email, "password": password})


def main():
    print(f"new account: {NEW_EMAIL}")

    st, _ = signup(NEW_EMAIL, NEW_PASSWORD)
    print(f"1. POST /signup              -> {st} (check-your-email)")

    # Before verifying, login must be refused by the gate.
    st, hdr, page = login(NEW_EMAIL, NEW_PASSWORD)
    assert st == 200 and "verify your email" in page.lower(), "gate should block unverified login"
    print(f"2. POST /login (unverified)  -> {st} blocked by verification gate")

    url = link_for(NEW_EMAIL)
    assert url, "no verification link found in outbox.log"
    print(f"3. read emailed link         -> {url[:48]}…")

    st, _, page = verify(url)
    assert st == 200 and "verified" in page.lower(), f"verify failed ({st})"
    print(f"4. GET  {url.split(BASE)[-1][:20]}…   -> {st} email verified")

    # The link is single-use: a second GET must fail.
    st2, _, _ = verify(url)
    assert st2 == 400, f"verification link should be single-use (got {st2})"
    print(f"5. GET  verify (replay)      -> {st2} single-use enforced")

    st, hdr, _ = login(NEW_EMAIL, NEW_PASSWORD)
    assert st == 302 and "/dashboard" in hdr.get("Location", ""), f"login failed ({st})"
    print(f"6. POST /login (verified)    -> {st} -> {hdr.get('Location')}")

    st, _, page = _open("GET", BASE + "/dashboard")
    assert st == 200 and NEW_EMAIL in page, "dashboard not reachable after login"
    print(f"7. GET  /dashboard           -> {st} signed in as {NEW_EMAIL}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # noqa
        print(f"FAILED: {type(e).__name__}: {e}")
        sys.exit(1)
