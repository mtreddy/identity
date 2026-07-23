"""test.py — checks for 07-jwt. Exits nonzero on failure."""
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
    keys = dict(re.findall(r"(\w[\w-]*-agent).*?API key:\s*(sk_live_\S+)", seed.stdout, re.S))
    # fall back to positional if the labelled parse misses
    all_keys = re.findall(r"API key:\s*(sk_live_\S+)", seed.stdout)
    billing = keys.get("billing-agent", all_keys[0])
    analytics = keys.get("analytics-agent", all_keys[1])
    proc, base = T.start_server(HERE, env_extra={"JWT_SECRET": KEY})

    def token_for(apikey):
        st, _, text = T.http("POST", base + "/v1/token",
                             headers={"Authorization": f"Bearer {apikey}"})
        import json
        return st, (json.loads(text) if text else {})

    st, tok = token_for(billing)
    T.check("api key -> JWT issued", st == 200 and tok["access_token"].count(".") == 2)
    jwt_billing = tok["access_token"]

    T.check("token endpoint needs a valid api key", token_for("sk_live_bogus")[0] == 403 or token_for("sk_live_bogus")[0] == 401)

    def bearer(t):
        return {"Authorization": f"Bearer {t}"}

    T.check("JWT -> resources 200", T.get_json(base + "/v1/resources", headers=bearer(jwt_billing))[0] == 200)

    # scope: billing has admin, analytics does not
    _, atok = token_for(analytics)
    st_admin = T.get_json(base + "/v1/admin/stats", headers=bearer(atok["access_token"]))[0]
    T.check("insufficient scope -> 403", st_admin == 403, f"status={st_admin}")
    T.check("billing has admin scope -> 200",
            T.get_json(base + "/v1/admin/stats", headers=bearer(jwt_billing))[0] == 200)

    # tampered token / api key at jwt route / no token
    T.check("tampered JWT -> 401", T.get_json(base + "/v1/whoami", headers=bearer(jwt_billing + "x"))[0] == 401)
    T.check("api key used at JWT route -> 401", T.get_json(base + "/v1/resources", headers=bearer(billing))[0] == 401)
    T.check("no token -> 401", T.get_json(base + "/v1/whoami")[0] == 401)

    # alg:none forgery rejected (library-level)
    sys.path.insert(0, HERE)
    import jwt as pyjwt  # noqa: E402
    import tokens  # noqa: E402
    forged = pyjwt.encode({"iss": tokens.JWT_ISS, "aud": tokens.JWT_AUD, "sub": "1", "scope": "admin"},
                          key=None, algorithm="none")
    try:
        tokens.verify_token(forged)
        T.check("alg:none forgery rejected", False, "accepted")
    except Exception:
        T.check("alg:none forgery rejected", True)

    T.finish(proc)


if __name__ == "__main__":
    main()
