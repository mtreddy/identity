"""test.py — checks for 05-defense-in-depth. Exits nonzero on failure."""
import os
import re
import secrets
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import testlib as T  # noqa: E402

EMAIL, PW = "alice@example.com", "correct-horse-battery-staple"
KEY = secrets.token_hex(32)


def _csrf(page):
    m = re.search(r'name="csrf_token"\s+value="([^"]*)"', page)
    return m.group(1) if m else ""


def _login(base):
    """Return the session cookie for a fresh authenticated 'device'."""
    _, hdr, page = T.http("GET", base + "/login", allow_redirects=False)
    cookie = hdr.get("Set-Cookie", "").split(";")[0]
    _, hdr, _ = T.http("POST", base + "/login",
                       data={"csrf_token": _csrf(page), "email": EMAIL, "password": PW},
                       headers={"Cookie": cookie}, allow_redirects=False)
    sc = hdr.get("Set-Cookie", "")
    return sc.split(";")[0] if sc else cookie


def main():
    T.clean(HERE)
    T.run(HERE, ["seed.py"], env_extra={"SECRET_KEY": KEY})
    proc, base = T.start_server(HERE, env_extra={"SECRET_KEY": KEY})

    device_a = _login(base)
    device_b = _login(base)
    ok_a = "alice" in T.http("GET", base + "/dashboard", headers={"Cookie": device_a})[2]
    ok_b = "alice" in T.http("GET", base + "/dashboard", headers={"Cookie": device_b})[2]
    T.check("two independent sessions established", ok_a and ok_b)

    # Feature 11: weak new password rejected
    _, hdr, page = T.http("GET", base + "/change-password", headers={"Cookie": device_a},
                          allow_redirects=False)
    csrf = _csrf(page)
    _, _, body = T.http("POST", base + "/change-password", headers={"Cookie": device_a},
                        data={"csrf_token": csrf, "current_password": PW, "new_password": "short"})
    T.check("weak new password rejected", "at least 12" in body)

    # Feature 10: change password on A -> revokes B, keeps A
    _, hdr, page = T.http("GET", base + "/change-password", headers={"Cookie": device_a},
                          allow_redirects=False)
    csrf = _csrf(page)
    _, _, body = T.http("POST", base + "/change-password", headers={"Cookie": device_a},
                        data={"csrf_token": csrf, "current_password": PW,
                              "new_password": "a-Very-Strong-Passphrase-2026"})
    T.check("password change succeeds", "other sessions" in body.lower())

    a_status = T.http("GET", base + "/dashboard", headers={"Cookie": device_a},
                      allow_redirects=False)[0]
    b_status = T.http("GET", base + "/dashboard", headers={"Cookie": device_b},
                      allow_redirects=False)[0]
    T.check("device A stays logged in", a_status == 200, f"status={a_status}")
    T.check("device B revoked (redirect to login)", b_status == 302, f"status={b_status}")

    # Feature 13: custom 404
    st, _, _ = T.http("GET", base + "/no-such-page")
    T.check("custom 404 page", st == 404)

    # Feature 12: auth.log records events, no raw passwords
    log = ""
    p = os.path.join(HERE, "auth.log")
    if os.path.exists(p):
        log = open(p).read()
    T.check("auth.log has events and no raw passwords",
            "password changed" in log and PW not in log and "Very-Strong" not in log)

    T.finish(proc)


if __name__ == "__main__":
    main()
