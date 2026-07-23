"""test.py — checks for 02-secrets-transport. Exits nonzero on failure."""
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
    # Feature 1: refuse to boot without SECRET_KEY
    r = T.run(HERE, ["app.py"], env_extra={"SECRET_KEY": ""})
    T.check("server refuses to boot without SECRET_KEY",
            r.returncode != 0 and "SECRET_KEY" in (r.stderr + r.stdout))

    T.run(HERE, ["seed.py"], env_extra={"SECRET_KEY": KEY})
    proc, base = T.start_server(HERE, env_extra={"SECRET_KEY": KEY})

    st, hdr, _ = T.http("POST", base + "/login",
                        data={"email": EMAIL, "password": PW}, allow_redirects=False)
    cookie = hdr.get("Set-Cookie", "")
    T.check("login works with SECRET_KEY set",
            st == 302 and "/dashboard" in hdr.get("Location", ""))
    # Feature 4 preview: HttpOnly cookie (Secure relaxed for http test)
    T.check("session cookie is HttpOnly", "HttpOnly" in cookie, cookie)

    T.finish(proc)


if __name__ == "__main__":
    main()
