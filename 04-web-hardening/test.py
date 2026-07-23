"""test.py — checks for 04-web-hardening. Exits nonzero on failure."""
import os
import re
import secrets
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import testlib as T  # noqa: E402

EMAIL, PW = "alice@example.com", "correct-horse-battery-staple"
KEY = secrets.token_hex(32)


def main():
    T.clean(HERE)
    T.run(HERE, ["seed.py"], env_extra={"SECRET_KEY": KEY})
    proc, base = T.start_server(HERE, env_extra={"SECRET_KEY": KEY})

    # Feature 7: POST without CSRF token -> 400
    st, _, _ = T.http("POST", base + "/login", data={"email": EMAIL, "password": PW},
                      allow_redirects=False)
    T.check("login without CSRF token rejected (400)", st == 400, f"status={st}")

    # proper flow: GET token, then POST with token + cookie -> 302
    st, hdr, page = T.http("GET", base + "/login", allow_redirects=False)
    cookie = hdr.get("Set-Cookie", "").split(";")[0]
    m = re.search(r'name="csrf_token"\s+value="([^"]*)"', page)
    tok = m.group(1) if m else ""
    st, hdr, _ = T.http("POST", base + "/login",
                        data={"csrf_token": tok, "email": EMAIL, "password": PW},
                        headers={"Cookie": cookie}, allow_redirects=False)
    T.check("login with CSRF token + cookie succeeds (302)", st == 302, f"status={st}")

    # Feature 9: security headers
    _, hdr, _ = T.http("GET", base + "/login")
    T.check("X-Frame-Options: DENY", hdr.get("X-Frame-Options") == "DENY")
    T.check("X-Content-Type-Options: nosniff", hdr.get("X-Content-Type-Options") == "nosniff")
    T.check("Content-Security-Policy present", "default-src" in (hdr.get("Content-Security-Policy") or ""))

    # Feature 8: bcrypt 72-byte truncation defeated (direct import)
    sys.path.insert(0, HERE)
    import db  # noqa: E402
    h = db.hash_password("A" * 80)
    T.check("bcrypt prehash: correct long password verifies", db.verify_password("A" * 80, h))
    T.check("bcrypt prehash: 72-byte-prefix twin rejected",
            not db.verify_password("A" * 72 + "DIFFERENT", h))

    T.finish(proc)


if __name__ == "__main__":
    main()
