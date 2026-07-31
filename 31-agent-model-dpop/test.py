"""test.py — checks for 31-agent-model-dpop. Exits nonzero on failure.

Focus: DPoP sender-constraint (RFC 9449). A stolen token is inert on the safe
endpoint (wrong key, no proof, replayed proof, wrong htu, missing ath) but
replays on the /vuln bearer path. Plus the mechanism-30 guarantees still hold
(audience, scope, per-client allow-list, client-auth).
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
import testlib as T  # noqa: E402


def main():
    T.clean(HERE)
    seed = T.run(HERE, ["seed.py"])
    secret = re.search(r"SECRET:\s*(cs_\S+)", seed.stdout).group(1)

    proc, base = T.start_server(HERE)
    import dpop
    import client_example as ce
    ce.BASE = base

    prm = ce.discover_and_verify_resource()
    resource = prm["resource"]
    tep = ce.discover_as()["token_endpoint"]
    T.check("PRM advertises resource + DPoP (ES256)",
            resource == "https://models.example/api"
            and "ES256" in prm.get("dpop_signing_alg_values_supported", []))

    # --- happy path: DPoP-bound token ---------------------------------------
    st, tok = ce.get_token_pk("agent-pk", tep, "model:invoke", resource)
    at = tok["access_token"]
    T.check("token is DPoP-bound (cnf.jkt + token_type DPoP)",
            st == 200 and tok.get("token_type") == "DPoP" and "jkt" in tok.get("cnf", {}))
    T.check("valid DPoP proof invokes gpt-sim",
            ce.invoke(at, "gpt-sim", "hi")[0] == 200)

    st, sec = ce.get_token_secret("agent-secret", secret, "model:invoke", resource)
    T.check("client_secret + DPoP -> bound token invokes",
            st == 200 and ce.invoke(sec["access_token"], "gpt-sim", "hi")[0] == 200)

    # A raw invoke so we can craft adversarial DPoP headers.
    def invoke_raw(token, model, proof, scheme="DPoP"):
        h = {"Authorization": f"{scheme} {token}"}
        if proof is not None:
            h["DPoP"] = proof
        return ce._req("POST", f"/v1/models/{model}:invoke", data={"prompt": "x"}, headers=h)

    inv_url = base + "/v1/models/gpt-sim:invoke"

    # --- a STOLEN token: attacker has the string, not the DPoP key -----------
    T.check("stolen token + attacker's own key -> 401 (jkt mismatch)",
            ce.invoke(at, "gpt-sim", "x", dpop_key=ce.new_dpop_key())[0] == 401)
    T.check("token presented with NO DPoP proof -> 401",
            invoke_raw(at, "gpt-sim", None)[0] == 401)
    T.check("token presented as plain Bearer on /safe -> 401",
            invoke_raw(at, "gpt-sim", None, scheme="Bearer")[0] == 401)

    # --- proof-level negatives ----------------------------------------------
    replay = dpop.create_proof(ce.DPOP_KEY, "POST", inv_url, access_token=at)
    T.check("fresh proof -> 200", invoke_raw(at, "gpt-sim", replay)[0] == 200)
    T.check("replayed proof (same jti) -> 401", invoke_raw(at, "gpt-sim", replay)[0] == 401)
    wrong_htu = dpop.create_proof(ce.DPOP_KEY, "POST", inv_url + "-not", access_token=at)
    T.check("proof with wrong htu -> 401", invoke_raw(at, "gpt-sim", wrong_htu)[0] == 401)
    no_ath = dpop.create_proof(ce.DPOP_KEY, "POST", inv_url)   # no access_token -> no ath
    T.check("proof missing ath -> 401", invoke_raw(at, "gpt-sim", no_ath)[0] == 401)

    # --- mechanism-30 guarantees still hold ---------------------------------
    _, other = ce.get_token_pk("agent-pk", tep, "model:invoke", "https://other-upstream.example")
    T.check("token for a different resource -> 401 (audience)",
            ce.invoke(other["access_token"], "gpt-sim", "x")[0] == 401)
    _, ro = ce.get_token_pk("agent-pk", tep, "models:read", resource)
    T.check("read-only token calling :invoke -> 403 (scope)",
            ce.invoke(ro["access_token"], "gpt-sim", "x")[0] == 403)
    T.check("agent-secret NOT allow-listed for embed-sim -> 403",
            ce.invoke(sec["access_token"], "embed-sim", "x")[0] == 403)
    T.check("agent-pk allow-listed for embed-sim -> 200",
            ce.invoke(at, "embed-sim", "x")[0] == 200)
    T.check("no token -> 401", T.get_json(base + "/v1/models")[0] == 401)

    # forged client assertion (signed by the wrong key) -> 401 invalid_client
    import time as _t
    import jwt as _jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    now = int(_t.time())
    rogue = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()
    forged = _jwt.encode({"iss": "agent-pk", "sub": "agent-pk", "aud": tep,
                          "iat": now, "exp": now + 60, "jti": "rogue-1"},
                         rogue, algorithm="RS256")
    st_forged, _, _ = T.http("POST", base + "/oauth/token", data={
        "grant_type": "client_credentials",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": forged, "scope": "model:invoke", "resource": resource})
    T.check("forged client assertion -> 401", st_forged == 401)

    # --- the /vuln contrast: the SAME token replays as a bearer -------------
    T.check("stolen token replays on /vuln bearer path -> 200",
            ce.invoke(at, "gpt-sim", "hi", path="/vuln/v1/models/", scheme="Bearer")[0] == 200)

    T.finish(proc)


if __name__ == "__main__":
    main()
