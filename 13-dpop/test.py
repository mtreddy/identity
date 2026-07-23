"""test.py — checks for 13-dpop. Exits nonzero on failure."""
import os
import re
import secrets
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import testlib as T  # noqa: E402

PORT = os.environ.get("TEST_PORT", "5713")
BASE = f"http://127.0.0.1:{PORT}"
ENV = {"JWT_SECRET": secrets.token_hex(32)}


def main():
    T.clean(HERE)
    seed = T.run(HERE, ["seed.py"], env_extra=ENV)
    api_key = re.findall(r"API key:\s*(sk_live_\S+)", seed.stdout)[0]  # billing
    proc, base = T.start_server(HERE, env_extra=ENV, port=PORT)

    os.environ["API_BASE"] = BASE
    os.environ["API_KEY"] = api_key
    sys.path.insert(0, HERE)
    import dpop  # noqa: E402
    import client_example as ce  # noqa: E402
    from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
    import jwt  # noqa: E402

    priv = ec.generate_private_key(ec.SECP256R1())
    attacker = ec.generate_private_key(ec.SECP256R1())

    st, tok = ce.get_token(api_key, priv)
    token = tok["access_token"]
    claims = jwt.decode(token, options={"verify_signature": False})
    T.check("token bound to DPoP key (cnf.jkt matches)",
            st == 200 and claims["cnf"]["jkt"] == dpop.jwk_thumbprint(dpop.public_jwk(priv)))
    T.check("token_type is DPoP", tok["token_type"] == "DPoP")

    # happy: fresh proof bound to this token
    proof = dpop.create_proof(priv, "GET", ce.RES_URL, access_token=token)
    T.check("proof + token -> 200", ce.call_resources(token, proof)[0] == 200)

    # stolen token, no proof
    st, _, _ = T.http("GET", ce.RES_URL, headers={"Authorization": f"DPoP {token}"})
    T.check("stolen token, no proof -> 401", st == 401)

    # stolen token + attacker's own valid proof (different key) -> jkt mismatch
    a_proof = dpop.create_proof(attacker, "GET", ce.RES_URL, access_token=token)
    T.check("stolen token + attacker's proof -> 401 (jkt mismatch)",
            ce.call_resources(token, a_proof)[0] == 401)

    # proof replay (same jti twice)
    replay = dpop.create_proof(priv, "GET", ce.RES_URL, access_token=token)
    T.check("first proof use -> 200", ce.call_resources(token, replay)[0] == 200)
    T.check("replayed proof -> 401", ce.call_resources(token, replay)[0] == 401)

    # wrong htu, and wrong ath
    wrong_url = dpop.create_proof(priv, "GET", BASE + "/v1/whoami", access_token=token)
    T.check("proof for wrong URL (htu) -> 401", ce.call_resources(token, wrong_url)[0] == 401)
    wrong_ath = dpop.create_proof(priv, "GET", ce.RES_URL, access_token="other.token.value")
    T.check("proof with wrong ath -> 401", ce.call_resources(token, wrong_ath)[0] == 401)

    T.finish(proc)


if __name__ == "__main__":
    main()
