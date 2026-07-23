"""test.py — checks for 10-openid-connect. Exits nonzero on failure."""
import json
import os
import secrets
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import testlib as T  # noqa: E402

PORT = os.environ.get("TEST_PORT", "5710")
BASE = f"http://127.0.0.1:{PORT}"
ENV = {"SECRET_KEY": secrets.token_hex(32), "OIDC_ISSUER": BASE, "PUBLIC_BASE_URL": BASE}
CLIENT_ID = "demo-web-app"


def main():
    T.clean(HERE)
    T.run(HERE, ["seed.py"], env_extra=ENV)
    proc, base = T.start_server(HERE, env_extra=ENV, port=PORT)
    os.environ.update(ENV)
    os.environ["API_BASE"] = BASE

    # discovery + JWKS
    st, disc = T.get_json(base + "/.well-known/openid-configuration")
    T.check("discovery advertises RS256 + issuer",
            st == 200 and "RS256" in disc["id_token_signing_alg_values_supported"]
            and disc["issuer"] == BASE)
    st, jwks = T.get_json(base + "/.well-known/jwks.json")
    T.check("JWKS serves an RSA signing key", st == 200 and jwks["keys"][0]["kty"] == "RSA")

    # happy path (login -> consent -> token -> id_token verified via JWKS + nonce
    # -> userinfo -> resources -> replay). Raises on failure.
    sys.path.insert(0, HERE)
    import client_example as ce  # noqa: E402
    try:
        ce.main()
        T.check("full OIDC flow (id_token verified via JWKS + nonce)", True)
    except Exception as e:  # noqa
        T.check("full OIDC flow (id_token verified via JWKS + nonce)", False, repr(e))

    # id_token validation negatives (done the way a real client validates)
    import crypto_keys  # noqa: E402
    import jwt  # noqa: E402
    import tokens  # noqa: E402
    user = {"id": 1, "email": "user@example.com", "name": "Ada Lovelace"}
    nonce = "the-nonce"
    idt = tokens.issue_id_token(user, CLIENT_ID, nonce, ["openid", "profile", "email"])
    pub = crypto_keys.PUBLIC_KEY

    def rejected(fn):
        try:
            fn(); return False
        except Exception:
            return True

    T.check("id_token happy verification",
            tokens.verify_id_token(idt, pub, CLIENT_ID, nonce=nonce)["email"] == user["email"])
    T.check("wrong nonce rejected", rejected(lambda: tokens.verify_id_token(idt, pub, CLIENT_ID, nonce="X")))
    T.check("wrong audience rejected", rejected(lambda: tokens.verify_id_token(idt, pub, "other-app", nonce=nonce)))
    T.check("tampered signature rejected", rejected(lambda: tokens.verify_id_token(idt[:-3] + "AAA", pub, CLIENT_ID, nonce=nonce)))
    forged = jwt.encode({"iss": tokens.ISS, "aud": CLIENT_ID, "sub": "1", "nonce": nonce},
                        key=None, algorithm="none")
    T.check("alg:none forgery rejected", rejected(lambda: tokens.verify_id_token(forged, pub, CLIENT_ID, nonce=nonce)))

    # token separation: an id_token must NOT work as an access token at the API
    st = T.get_json(base + "/api/resources", headers={"Authorization": f"Bearer {idt}"})[0]
    T.check("id_token rejected at resource API (401)", st == 401, f"status={st}")

    T.finish(proc)


if __name__ == "__main__":
    main()
