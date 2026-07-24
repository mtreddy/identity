"""
client_example.py — the DEVICE side of the Device Authorization Grant, plus a
simulated user approving in a browser (so the whole flow runs end-to-end).

    python client_example.py     (server must be running)

Real life: the device shows the user_code + URL on screen and polls; a human
approves on their phone. Here one script does both so you can watch every step.
"""

import http.cookiejar
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get("API_BASE", "http://127.0.0.1:5000").rstrip("/")
CLIENT_ID = "smart-tv-app"
SCOPE = "profile resources:read"
USER_EMAIL = "user@example.com"
USER_PASSWORD = "correct-horse-battery-staple"


# --- device side (plain POSTs; token endpoint is CSRF-exempt) ---------------

def _post(path, data, bearer=None):
    headers = {"Authorization": f"Bearer {bearer}"} if bearer else {}
    req = urllib.request.Request(BASE + path, data=urllib.parse.urlencode(data).encode(),
                                 method="POST", headers=headers)
    try:
        r = urllib.request.urlopen(req)
        return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def authorize():
    st, body = _post("/device_authorization", {"client_id": CLIENT_ID, "scope": SCOPE})
    return body


def poll(device_code):
    return _post("/token", {"grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                            "device_code": device_code})


def api(path, token):
    req = urllib.request.Request(BASE + path, headers={"Authorization": f"Bearer {token}"})
    try:
        r = urllib.request.urlopen(req)
        return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


# --- user browser side (cookie jar + CSRF) ----------------------------------

def _browser():
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def _open(opener, method, path, data=None):
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(BASE + path, data=body, method=method)
    with opener.open(req) as r:
        return r.read().decode()


def _field(page, name):
    m = re.search(r'name="%s"\s+value="([^"]*)"' % re.escape(name), page)
    return m.group(1) if m else ""


def user_decides(user_code, approve=True):
    """Simulate the user opening /device, entering the code, logging in, and
    approving/denying — the browser half of the flow."""
    b = _browser()
    page = _open(b, "GET", "/device")
    page = _open(b, "POST", "/device",
                 {"csrf_token": _field(page, "csrf_token"), "user_code": user_code})
    # followed redirects landed on the login page
    page = _open(b, "POST", "/login",
                 {"csrf_token": _field(page, "csrf_token"), "next": _field(page, "next"),
                  "email": USER_EMAIL, "password": USER_PASSWORD})
    # now on the consent page
    result = _open(b, "POST", "/device/decision",
                   {"csrf_token": _field(page, "csrf_token"),
                    "decision": "approve" if approve else "deny"})
    return "approved" in result


def main():
    dev = authorize()
    print(f"1. device_authorization ->")
    print(f"     user_code:        {dev['user_code']}")
    print(f"     verification_uri: {dev['verification_uri']}")
    print(f"     interval: {dev['interval']}s, expires_in: {dev['expires_in']}s")
    print(f"   >> On your phone, go to {dev['verification_uri']} and enter {dev['user_code']}")

    st, body = poll(dev["device_code"])
    print(f"2. poll -> {st} {body.get('error')}  (waiting for the user)")
    st, body = poll(dev["device_code"])
    print(f"3. poll again immediately -> {st} {body.get('error')}  (polled too fast)")

    print("4. [user approves in a browser...]")
    user_decides(dev["user_code"], approve=True)

    time.sleep(dev["interval"] + 0.2)
    st, body = poll(dev["device_code"])
    print(f"5. poll -> {st}  access_token received (scope={body.get('scope')!r})")
    token = body["access_token"]

    st, body = api("/api/resources", token)
    print(f"6. GET /api/resources -> {st} {[r['title'] for r in body['resources']]}")


if __name__ == "__main__":
    if not BASE.startswith("http"):
        print("Set API_BASE."); sys.exit(2)
    main()
