"""test.py — checks for 09-oauth2-auth-code-pkce. Exits nonzero on failure."""
import os
import secrets
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import testlib as T  # noqa: E402

PORT = os.environ.get("TEST_PORT", "5709")
BASE = f"http://127.0.0.1:{PORT}"
ENV = {"SECRET_KEY": secrets.token_hex(32), "JWT_SECRET": secrets.token_hex(32),
       "PUBLIC_BASE_URL": BASE}
CLIENT = "demo-web-app"
RU = BASE + "/client/callback"
CH = "0000000000000000000000000000000000000000000"  # any S256-length challenge


def authz(**over):
    p = {"response_type": "code", "client_id": CLIENT, "redirect_uri": RU,
         "scope": "profile resources:read", "state": "s",
         "code_challenge": CH, "code_challenge_method": "S256"}
    p.update(over)
    return BASE + "/authorize?" + urllib.parse.urlencode(p)


def main():
    T.clean(HERE)
    T.run(HERE, ["seed.py"], env_extra=ENV)
    proc, base = T.start_server(HERE, env_extra=ENV, port=PORT)

    # happy path via the client_example driver (login -> consent -> token ->
    # resources -> one-time-code replay). Raises on any failure.
    os.environ["API_BASE"] = BASE
    sys.path.insert(0, HERE)
    import client_example as ce  # noqa: E402
    try:
        ce.main()
        T.check("full OAuth2 + PKCE flow (login/consent/token/resources)", True)
    except Exception as e:  # noqa
        T.check("full OAuth2 + PKCE flow (login/consent/token/resources)", False, repr(e))

    # security negatives (pre-login, no session needed)
    T.check("unknown client_id -> 400 (no redirect)",
            T.http("GET", authz(client_id="nope"), allow_redirects=False)[0] == 400)
    T.check("unregistered redirect_uri -> 400 (no redirect)",
            T.http("GET", authz(redirect_uri="http://evil.example/cb"), allow_redirects=False)[0] == 400)
    st, hdr, _ = T.http("GET", authz(scope="admin"), allow_redirects=False)
    T.check("invalid scope -> redirect error=invalid_scope",
            st == 302 and "invalid_scope" in hdr.get("Location", ""))
    st, hdr, _ = T.http("GET", authz(code_challenge="", code_challenge_method=""),
                        allow_redirects=False)
    T.check("missing PKCE -> redirect error=invalid_request",
            st == 302 and "invalid_request" in hdr.get("Location", ""))

    # code replay is one-time (drive a fresh flow, redeem twice)
    st_replay = _replay_code(ce)
    T.check("one-time code replay -> invalid_grant", st_replay == 400, f"status={st_replay}")

    # PKCE: redeem a fresh code with the WRONG verifier
    st_wrong = _wrong_verifier(ce)
    T.check("PKCE wrong verifier -> invalid_grant", st_wrong == 400, f"status={st_wrong}")

    T.finish(proc)


def _drive_to_code(ce):
    """Reuse client_example helpers to run login+consent and return (code, verifier)."""
    import oauth  # noqa: E402
    ce._jar.clear()  # start logged out so /authorize redirects to /login
    v, state = oauth.generate_code_verifier(), oauth.generate_state()
    au = ce.BASE + "/authorize?" + urllib.parse.urlencode({
        "response_type": "code", "client_id": ce.CLIENT_ID, "redirect_uri": ce.REDIRECT_URI,
        "scope": ce.SCOPE, "state": state,
        "code_challenge": oauth.code_challenge_s256(v), "code_challenge_method": "S256"})
    st, h, page = ce._open("GET", au)
    if st == 302:                                     # -> /login
        _, _, page = ce._open("GET", ce._abs(h["Location"]))
        csrf, nxt = ce._field(page, "csrf_token"), ce._field(page, "next")
        _, h, _ = ce._open("POST", ce.BASE + "/login",
                           {"csrf_token": csrf, "next": nxt,
                            "email": ce.USER_EMAIL, "password": ce.USER_PASSWORD})
        _, _, page = ce._open("GET", ce._abs(h["Location"]))
    form = {k: ce._field(page, k) for k in ("csrf_token", "client_id", "redirect_uri",
            "scope", "state", "code_challenge", "code_challenge_method")}
    _, h, _ = ce._open("POST", ce.BASE + "/authorize/decision", {**form, "decision": "approve"})
    code = urllib.parse.parse_qs(urllib.parse.urlparse(h["Location"]).query)["code"][0]
    return code, v


def _token(ce, code, verifier):
    st, _, _ = ce._open("POST", ce.BASE + "/token", {
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": ce.REDIRECT_URI, "client_id": ce.CLIENT_ID, "code_verifier": verifier})
    return st


def _replay_code(ce):
    code, v = _drive_to_code(ce)
    _token(ce, code, v)               # first redemption
    return _token(ce, code, v)        # replay -> 400


def _wrong_verifier(ce):
    code, v = _drive_to_code(ce)
    return _token(ce, code, v + "WRONG")


if __name__ == "__main__":
    main()
