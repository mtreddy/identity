"""test.py — checks for 16-totp. Exits nonzero on failure."""
import base64
import os
import re
import secrets
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import testlib as T  # noqa: E402

EMAIL, PW = "user@example.com", "correct-horse-battery-staple"
ENV = {"SECRET_KEY": secrets.token_hex(32)}


def _csrf(page):
    m = re.search(r'name="csrf_token"\s+value="([^"]*)"', page)
    return m.group(1) if m else ""


def main():
    T.clean(HERE)
    seed = T.run(HERE, ["seed.py"], env_extra=ENV)
    secret = re.search(r"TOTP secret \(Base32\):\s*(\S+)", seed.stdout).group(1)
    proc, base = T.start_server(HERE, env_extra=ENV)

    sys.path.insert(0, HERE)
    import totp  # noqa: E402

    # RFC 6238 test vectors (SHA-1 secret "12345678901234567890")
    sec = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
    T.check("RFC 6238 vector t=59 -> 287082", totp._hotp(sec, 59 // 30) == "287082")
    T.check("RFC 6238 vector t=1111111109 -> 081804", totp._hotp(sec, 1111111109 // 30) == "081804")

    # Track the session cookie across requests: the CSRF token lives in Flask's
    # signed-cookie session, so each render of csrf_token() re-issues the cookie.
    state = {"cookie": ""}

    def req(method, path, data=None, redirects=False):
        hdrs = {"Cookie": state["cookie"]} if state["cookie"] else {}
        st, hdr, body = T.http(method, base + path, data=data, headers=hdrs,
                               allow_redirects=redirects)
        sc = hdr.get("Set-Cookie", "")
        if sc:
            state["cookie"] = sc.split(";")[0]
        return st, hdr, body

    # step 1: password -> pending session (2FA required)
    _, _, page = req("GET", "/login")
    st, hdr, _ = req("POST", "/login", {"csrf_token": _csrf(page), "email": EMAIL, "password": PW})
    T.check("password step -> redirect to /verify",
            st == 302 and "/verify" in hdr.get("Location", ""))
    T.check("dashboard blocked before 2FA", req("GET", "/")[0] == 302)

    # step 2: wrong code rejected
    _, _, page = req("GET", "/verify")
    _, _, body = req("POST", "/verify", {"csrf_token": _csrf(page), "code": "000000"})
    T.check("wrong TOTP code rejected", "Invalid code" in body)

    # step 2: correct code -> full session
    _, _, page = req("GET", "/verify")
    st, hdr, _ = req("POST", "/verify", {"csrf_token": _csrf(page), "code": totp.now_code(secret)})
    T.check("correct TOTP code -> full session (redirect to /)",
            st == 302 and hdr.get("Location", "").endswith("/"))
    st, _, body = req("GET", "/")
    T.check("dashboard reachable after 2FA", st == 200 and EMAIL in body)

    T.finish(proc)


if __name__ == "__main__":
    main()
