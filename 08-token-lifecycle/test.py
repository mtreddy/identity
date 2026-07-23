"""test.py — checks for 08-token-lifecycle. Exits nonzero on failure."""
import json
import os
import re
import secrets
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import testlib as T  # noqa: E402

KEY = secrets.token_hex(32)


def main():
    T.clean(HERE)
    seed = T.run(HERE, ["seed.py"], env_extra={"JWT_SECRET": KEY})
    api_key = re.findall(r"API key:\s*(sk_live_\S+)", seed.stdout)[0]  # billing
    proc, base = T.start_server(HERE, env_extra={"JWT_SECRET": KEY})

    def post(path, data=None, apikey=None):
        headers = {"X-API-Key": apikey} if apikey else {}
        st, _, text = T.http("POST", base + path, data=data or {}, headers=headers)
        return st, (json.loads(text) if text else {})

    def bearer(t):
        return {"Authorization": f"DPoP {t}"}  # unused; access tokens are Bearer here

    # 1. token pair
    st, tok = post("/v1/token", apikey=api_key)
    T.check("token issue returns access + refresh",
            st == 200 and "access_token" in tok and "refresh_token" in tok)
    access1, refresh1 = tok["access_token"], tok["refresh_token"]

    # 2. use access token
    st, _ = T.get_json(base + "/v1/whoami", headers={"Authorization": f"Bearer {access1}"})
    T.check("access token works", st == 200)

    # 3. refresh -> rotation
    st, tok2 = post("/v1/token/refresh", data={"refresh_token": refresh1})
    T.check("refresh rotates to a new pair",
            st == 200 and tok2["refresh_token"] != refresh1)
    refresh2 = tok2["refresh_token"]

    # 4. reuse the OLD refresh token -> 401 + family revoked
    st, _ = post("/v1/token/refresh", data={"refresh_token": refresh1})
    T.check("reused (rotated) refresh token rejected", st == 401)
    st, _ = post("/v1/token/refresh", data={"refresh_token": refresh2})
    T.check("reuse detection revokes the whole family", st == 401)

    # 5. jti revoke -> access token stops working before expiry
    fresh = post("/v1/token", apikey=api_key)[1]["access_token"]
    T.check("fresh token valid before revoke",
            T.get_json(base + "/v1/whoami", headers={"Authorization": f"Bearer {fresh}"})[0] == 200)
    post("/v1/token/revoke", data={"access_token": fresh})
    st, body = T.get_json(base + "/v1/whoami", headers={"Authorization": f"Bearer {fresh}"})
    T.check("revoked access token -> 401 token_revoked",
            st == 401 and body.get("error") == "token_revoked", f"{st} {body}")

    # 6. introspection requires api key; reports active/inactive
    T.check("introspect requires api key", post("/v1/introspect", data={"token": "x"})[0] == 401)
    good = post("/v1/token", apikey=api_key)[1]["access_token"]
    T.check("introspect active token",
            post("/v1/introspect", data={"token": good}, apikey=api_key)[1].get("active") is True)
    T.check("introspect revoked token inactive",
            post("/v1/introspect", data={"token": fresh}, apikey=api_key)[1].get("active") is False)

    T.finish(proc)


if __name__ == "__main__":
    main()
