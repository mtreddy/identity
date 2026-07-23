"""test.py — checks for 01-login-password. Exits nonzero on failure."""
import os
import sqlite3
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import testlib as T  # noqa: E402

EMAIL, PW = "alice@example.com", "correct-horse-battery-staple"


def main():
    T.run(HERE, ["seed.py"])
    proc, base = T.start_server(HERE)
    jar = "/tmp/.c01"

    # anonymous dashboard -> redirect to login
    st, hdr, _ = T.http("GET", base + "/dashboard", allow_redirects=False)
    T.check("anonymous /dashboard redirects to /login",
            st == 302 and "/login" in hdr.get("Location", ""), f"status={st}")

    # correct login -> 302 to dashboard, capture cookie
    st, hdr, _ = T.http("POST", base + "/login",
                        data={"email": EMAIL, "password": PW}, allow_redirects=False)
    cookie = hdr.get("Set-Cookie", "").split(";")[0]
    T.check("correct login redirects to /dashboard",
            st == 302 and "/dashboard" in hdr.get("Location", ""), f"status={st}")

    # dashboard with cookie shows the user
    st, _, body = T.http("GET", base + "/dashboard", headers={"Cookie": cookie})
    T.check("authenticated /dashboard shows the user", EMAIL in body, f"status={st}")

    # wrong password rejected
    _, _, body = T.http("POST", base + "/login", data={"email": EMAIL, "password": "nope"})
    T.check("wrong password rejected", "Invalid" in body)

    # passwords stored as bcrypt hashes, never plaintext
    rows = sqlite3.connect(os.path.join(HERE, "identity.db")).execute(
        "SELECT password_hash FROM users").fetchall()
    T.check("passwords stored as bcrypt hashes (no plaintext)",
            rows and all(h[0].startswith("$2") and PW not in h[0] for h in rows))

    T.finish(proc)


if __name__ == "__main__":
    main()
