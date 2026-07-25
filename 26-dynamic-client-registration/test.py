"""test.py — checks for 26-dynamic-client-registration. Exits nonzero on failure.

Covers the happy path (register -> read/update -> OAuth flow -> delete) plus the
security negatives that define DCR: the registration gate, redirect_uri
validation, scope clamping, per-client management-token isolation, and
confidential-client secret auth at /token.
"""
import os
import secrets
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import testlib as T  # noqa: E402

PORT = os.environ.get("TEST_PORT", "5726")
BASE = f"http://127.0.0.1:{PORT}"
REG_TOKEN = secrets.token_urlsafe(24)
ENV = {"SECRET_KEY": secrets.token_hex(32), "JWT_SECRET": secrets.token_hex(32),
       "PUBLIC_BASE_URL": BASE, "REGISTRATION_TOKEN": REG_TOKEN}


def main():
    T.clean(HERE)
    try:
        os.remove(os.path.join(HERE, "demo_client.json"))
    except OSError:
        pass
    T.run(HERE, ["seed.py"], env_extra=ENV)
    proc, base = T.start_server(HERE, env_extra=ENV, port=PORT)

    # client_example needs these at import time.
    os.environ["API_BASE"] = BASE
    os.environ["REGISTRATION_TOKEN"] = REG_TOKEN
    sys.path.insert(0, HERE)
    import client_example as ce  # noqa: E402

    # Happy path: register -> read -> OAuth flow -> update -> delete.
    try:
        ce.main()
        T.check("register -> manage -> OAuth flow -> delete (RFC 7591/7592)", True)
    except Exception as e:  # noqa
        T.check("register -> manage -> OAuth flow -> delete (RFC 7591/7592)", False, repr(e))

    ru = BASE + "/cb"

    # --- registration gate: no / wrong initial access token -> 401 ----------
    st_noauth, _ = ce._json("POST", base + "/register",
        {"redirect_uris": [ru], "token_endpoint_auth_method": "none"}, bearer=None)
    T.check("registration without initial access token -> 401", st_noauth == 401,
            f"status={st_noauth}")
    st_badauth, _ = ce._json("POST", base + "/register",
        {"redirect_uris": [ru]}, bearer="wrong-token")
    T.check("registration with wrong initial access token -> 401", st_badauth == 401,
            f"status={st_badauth}")

    # --- redirect_uri validation --------------------------------------------
    st1, b1 = ce.register({"redirect_uris": ["not-a-uri"]})
    T.check("non-absolute redirect_uri rejected", st1 == 400 and b1.get("error") == "invalid_redirect_uri")
    st2, b2 = ce.register({"redirect_uris": ["https://ok.example/cb#frag"]})
    T.check("redirect_uri with fragment rejected", st2 == 400 and b2.get("error") == "invalid_redirect_uri")
    st3, b3 = ce.register({"redirect_uris": ["http://evil.example/cb"]})
    T.check("plain-http non-loopback redirect_uri rejected",
            st3 == 400 and b3.get("error") == "invalid_redirect_uri")
    st4, _ = ce.register({"client_name": "no-uris"})   # redirect_uris omitted
    T.check("missing redirect_uris rejected", st4 == 400)

    # --- scope clamping: a client cannot grant itself unsupported scope -----
    st5, b5 = ce.register({"redirect_uris": [ru], "token_endpoint_auth_method": "none",
                           "scope": "profile admin resources:read"})
    granted = set(b5.get("scope", "").split())
    T.check("requested scope clamped to server-supported subset",
            st5 == 201 and "admin" not in granted and "profile" in granted)
    # ...and /authorize refuses a scope beyond what was granted.
    st_auth, tok_over = ce.run_oauth_flow(b5["client_id"], ru, "profile admin")
    T.check("authorize with un-granted scope -> the flow fails (no token)",
            not (st_auth == 200 and tok_over.get("access_token")))

    # --- per-client management-token isolation (RFC 7592) -------------------
    _, ca = ce.register({"redirect_uris": [ru], "token_endpoint_auth_method": "none"})
    _, cb = ce.register({"redirect_uris": [ru], "token_endpoint_auth_method": "none"})
    st_iso, _ = ce._json("GET", ca["registration_client_uri"],
                         bearer=cb["registration_access_token"])
    T.check("client B's registration token cannot manage client A -> 401", st_iso == 401,
            f"status={st_iso}")
    st_wrongrat, _ = ce._json("GET", ca["registration_client_uri"], bearer="rat_wrong")
    T.check("wrong registration access token -> 401", st_wrongrat == 401)

    # --- confidential client: gets a secret, and it's enforced at /token ----
    st6, conf = ce.register({"redirect_uris": [ru],
                             "token_endpoint_auth_method": "client_secret_post",
                             "scope": "profile resources:read"})
    T.check("confidential client is issued a client_secret",
            st6 == 201 and conf.get("client_secret"))
    st_ok, tok_ok = ce.run_oauth_flow(conf["client_id"], ru, "profile resources:read",
                                      client_secret=conf["client_secret"])
    T.check("confidential client with correct secret gets a token",
            st_ok == 200 and tok_ok.get("access_token"))
    st_bad, tok_bad = ce.run_oauth_flow(conf["client_id"], ru, "profile resources:read",
                                        client_secret="wrong-secret")
    T.check("confidential client with wrong secret -> invalid_client (401)",
            st_bad == 401 and not tok_bad.get("access_token"), f"status={st_bad}")

    # --- secrets/tokens are stored hashed, never in the clear ---------------
    import db  # noqa: E402
    row = db.get_oauth_client(conf["client_id"])
    T.check("client_secret + registration token stored hashed",
            row["client_secret_hash"] and conf["client_secret"] != row["client_secret_hash"]
            and conf["registration_access_token"] != row["reg_access_token_hash"])

    T.finish(proc)


if __name__ == "__main__":
    main()
