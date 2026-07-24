"""test.py — checks for 21-csrf. Exits nonzero on failure."""
import os
import secrets
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import testlib as T  # noqa: E402

ENV = {"SECRET_KEY": secrets.token_hex(32)}


def main():
    T.clean(HERE)
    proc, base = T.start_server(HERE, env_extra=ENV)

    os.environ["API_BASE"] = base
    sys.path.insert(0, HERE)
    import client_example as ce  # noqa: E402

    # cookie flags: HttpOnly + SameSite present (defense-in-depth layers)
    _, hdr, _ = T.http("GET", base + "/login", allow_redirects=False)
    sc = hdr.get("Set-Cookie", "")
    T.check("session cookie has HttpOnly + SameSite", "HttpOnly" in sc and "SameSite" in sc, sc)

    victim = ce.Browser()
    victim.req("GET", "/login")
    T.check("logged in; initial email is alice", victim.email() == "alice@example.com")

    # CSRF on the UNPROTECTED endpoint succeeds (forged, no token)
    st, _ = victim.req("POST", "/vuln/change-email", {"email": "attacker@evil.example"})
    T.check("forged POST /vuln (no token) succeeds -> account taken over",
            st == 200 and victim.email() == "attacker@evil.example")

    # CSRF on the PROTECTED endpoint is rejected (forged, no token)
    st, _ = victim.req("POST", "/safe/change-email", {"email": "attacker2@evil.example"})
    T.check("forged POST /safe (no token) -> 403", st == 403)
    T.check("protected email unchanged by the forged request",
            victim.email() == "attacker@evil.example")

    # legitimate same-site request WITH the token works
    st, _ = victim.req("POST", "/safe/change-email",
                       {"csrf_token": victim.csrf(), "email": "alice.new@example.com"})
    T.check("legit POST /safe (with token) succeeds",
            st == 200 and victim.email() == "alice.new@example.com")

    # a stale/forged token is rejected
    st, _ = victim.req("POST", "/safe/change-email",
                       {"csrf_token": "not-a-real-token", "email": "x@evil.example"})
    T.check("invalid CSRF token -> 403", st == 403)

    T.finish(proc)


if __name__ == "__main__":
    main()
