"""
client_example.py — simulate a CSRF attack against the unprotected vs. protected
endpoints.

A real CSRF works because the *browser* auto-attaches the victim's session
cookie to a cross-site request. Headless, we model that by sending the victim's
cookie with a forged request that lacks the CSRF token — exactly what an
attacker page can produce.

    python client_example.py     (server must be running)
"""

import http.cookiejar
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get("API_BASE", "http://127.0.0.1:5000").rstrip("/")


class Browser:
    """A cookie-jar client standing in for the victim's browser: it carries the
    session cookie automatically, exactly as a browser attaches it to any
    request to the target origin (which is what makes CSRF possible)."""

    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))

    def req(self, method, path, data=None):
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        r = urllib.request.Request(BASE + path, data=body, method=method)
        try:
            resp = self.opener.open(r)
            return resp.status, resp.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def email(self):
        _, page = self.req("GET", "/")
        m = re.search(r"Current email: <strong>(.*?)</strong>", page)
        return m.group(1) if m else "?"

    def csrf(self):
        _, page = self.req("GET", "/")
        m = re.search(r'name="csrf_token"\s+value="([^"]*)"', page)
        return m.group(1) if m else ""


def main():
    victim = Browser()
    victim.req("GET", "/login")
    print(f"1. logged in; account email = {victim.email()}")

    # CSRF against the UNPROTECTED endpoint: forged POST, session cookie, NO token
    st, body = victim.req("POST", "/vuln/change-email", {"email": "attacker@evil.example"})
    print(f"2. forged POST /vuln (no token) -> {st}; account email now = {victim.email()}  <-- CSRF SUCCEEDED")

    # CSRF against the PROTECTED endpoint: same forged request -> rejected
    st, body = victim.req("POST", "/safe/change-email", {"email": "attacker2@evil.example"})
    print(f"3. forged POST /safe (no token) -> {st} {json.loads(body).get('error')}; email still = {victim.email()}  <-- CSRF BLOCKED")

    # Legitimate same-site request WITH the token works
    st, body = victim.req("POST", "/safe/change-email",
                          {"csrf_token": victim.csrf(), "email": "alice.new@example.com"})
    print(f"4. legit POST /safe (with token) -> {st}; account email now = {victim.email()}")


if __name__ == "__main__":
    if not BASE.startswith("http"):
        print("Set API_BASE."); sys.exit(2)
    main()
