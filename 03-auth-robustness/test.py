"""test.py — checks for 03-auth-robustness. Exits nonzero on failure."""
import os
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

    # Feature 4: hardened cookie flags
    st, hdr, _ = T.http("POST", base + "/login",
                        data={"email": EMAIL, "password": PW}, allow_redirects=False)
    cookie = hdr.get("Set-Cookie", "")
    T.check("login works", st == 302)
    T.check("cookie HttpOnly + SameSite", "HttpOnly" in cookie and "SameSite" in cookie, cookie)

    # Feature 5: per-account rate limit trips (5/min) -> 429 within a few tries
    statuses = []
    for i in range(7):
        st, _, _ = T.http("POST", base + "/login",
                          data={"email": "victim@example.com", "password": f"x{i}"},
                          allow_redirects=False)
        statuses.append(st)
    T.check("rate limiter returns 429 after repeated attempts", 429 in statuses,
            f"statuses={statuses}")

    T.finish(proc)


if __name__ == "__main__":
    main()
