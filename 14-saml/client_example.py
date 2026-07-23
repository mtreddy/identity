"""
client_example.py — drive the SAML SP-initiated SSO flow, then show that a
tampered assertion is rejected.

Acts as the user's browser (cookie jar, follows the redirect + auto-POST by
hand). Steps: start at the SP, log in at the IdP, and post the signed assertion
back to the SP's ACS. Then it re-runs the flow, tampers the SAMLResponse, and
confirms the ACS refuses it.
"""

import base64
import html
import http.cookiejar
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get("API_BASE", "http://127.0.0.1:5000").rstrip("/")
USER_EMAIL = "user@example.com"
USER_PASSWORD = "correct-horse-battery-staple"


def _opener():
    jar = http.cookiejar.CookieJar()

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    return urllib.request.build_opener(NoRedirect, urllib.request.HTTPCookieProcessor(jar))


def _open(opener, method, url, data=None):
    body = urllib.parse.urlencode(data).encode() if data else None
    req = urllib.request.Request(url, data=body, method=method)
    try:
        r = opener.open(req)
        return r.status, r.headers, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode()


def _field(page, name):
    m = re.search(r'name="%s"\s+value="([^"]*)"' % re.escape(name), page)
    return html.unescape(m.group(1)) if m else ""


def _action(page):
    m = re.search(r'action="([^"]*)"', page)
    return html.unescape(m.group(1)) if m else ""


def run_flow(opener):
    """Returns (acs_url, saml_response_b64) after logging in at the IdP."""
    st, hdr, _ = _open(opener, "GET", BASE + "/sp/login")           # -> 302 to IdP
    st, _, html_ = _open(opener, "GET", hdr["Location"])            # IdP login form
    sr, rs = _field(html_, "SAMLRequest"), _field(html_, "RelayState")
    st, _, html_ = _open(opener, "POST", BASE + "/idp/login", {     # authenticate
        "email": USER_EMAIL, "password": USER_PASSWORD,
        "SAMLRequest": sr, "RelayState": rs,
    })
    return _action(html_), _field(html_, "SAMLResponse")


def main():
    # 1-4: full happy path
    op = _opener()
    acs, saml_response = run_flow(op)
    st, _, page = _open(op, "POST", acs, {"SAMLResponse": saml_response, "RelayState": "/sp/"})
    who = re.search(r"<strong>(.*?)</strong>", page)
    print(f"1. SP-initiated SSO -> ACS      -> {st}  signed in as: {who.group(1) if who else '?'}")

    # 5: tamper — flip a byte in the signed assertion, expect rejection
    op2 = _opener()
    acs, saml_response = run_flow(op2)
    xml = base64.b64decode(saml_response).decode()
    tampered = xml.replace("user@example.com", "attacker@evil.com", 1)
    bad = base64.b64encode(tampered.encode()).decode()
    st, _, page = _open(op2, "POST", acs, {"SAMLResponse": bad, "RelayState": "/sp/"})
    msg = re.search(r'class="msg">(.*?)<', page)
    print(f"2. tampered assertion -> ACS    -> {st}  {msg.group(1) if msg else ''}")


if __name__ == "__main__":
    main()
