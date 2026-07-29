"""test.py — checks for 30-agent-model-oauth. Exits nonzero on failure.

Happy path (private_key_jwt + client_secret) plus the security negatives that
define the mechanism: audience binding, scope, per-client model allow-list,
assertion signature + replay, and the /vuln static-key contrast.
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
    api_key = re.search(r"static API key:\s*(sk-legacy-\S+)", seed.stdout).group(1)

    proc, base = T.start_server(HERE)
    import client_example as ce
    ce.BASE = base

    # --- discovery + endpoint verification ----------------------------------
    prm = ce.discover_and_verify_resource()   # raises if resource id mismatches
    resource = prm["resource"]
    tep = ce.discover_as()["token_endpoint"]
    T.check("PRM advertises the canonical resource (audience)",
            resource == "https://models.example/api")

    # --- happy path: private_key_jwt ----------------------------------------
    st, tok = ce.get_token_pk("agent-pk", tep, "model:invoke", resource)
    T.check("private_key_jwt -> access token", st == 200 and "access_token" in tok)
    st, body = ce.invoke(tok["access_token"], "gpt-sim", "hello world")
    T.check("valid token invokes gpt-sim", st == 200 and body.get("model") == "gpt-sim")

    # --- happy path: client_secret ------------------------------------------
    st, sec = ce.get_token_secret("agent-secret", secret, "model:invoke", resource)
    T.check("client_secret_basic -> access token", st == 200 and "access_token" in sec)
    T.check("client_secret token invokes gpt-sim",
            ce.invoke(sec["access_token"], "gpt-sim", "hi")[0] == 200)

    # --- audience binding (RFC 8707): token for another resource is refused --
    _, other = ce.get_token_pk("agent-pk", tep, "model:invoke", "https://other-upstream.example")
    T.check("token minted for a DIFFERENT resource is rejected (401)",
            ce.invoke(other["access_token"], "gpt-sim", "x")[0] == 401)

    # --- scope: a read-only token can't invoke ------------------------------
    _, ro = ce.get_token_pk("agent-pk", tep, "models:read", resource)
    ro_hdr = {"Authorization": f"Bearer {ro['access_token']}"}
    T.check("read-only token can list models",
            T.get_json(base + "/v1/models", headers=ro_hdr)[0] == 200)
    T.check("read-only token calling :invoke -> 403 insufficient_scope",
            ce.invoke(ro["access_token"], "gpt-sim", "x")[0] == 403)

    # --- per-client model allow-list ----------------------------------------
    T.check("agent-secret NOT allow-listed for embed-sim -> 403",
            ce.invoke(sec["access_token"], "embed-sim", "x")[0] == 403)
    T.check("agent-pk IS allow-listed for embed-sim -> 200",
            ce.invoke(tok["access_token"], "embed-sim", "x")[0] == 200)

    # --- no token / garbage token -------------------------------------------
    T.check("no token -> 401", T.get_json(base + "/v1/models")[0] == 401)
    T.check("garbage token -> 401", ce.invoke("not.a.jwt", "gpt-sim", "x")[0] == 401)

    # --- client_assertion negatives -----------------------------------------
    # Replay: reusing the SAME assertion (same jti) must fail the 2nd time.
    import time as _t
    import jwt as _jwt
    now = int(_t.time())
    assertion = _jwt.encode(
        {"iss": "agent-pk", "sub": "agent-pk", "aud": tep,
         "iat": now, "exp": now + 60, "jti": "fixed-jti-123"},
        ce.AGENT_KEY_FILE.read_text(), algorithm="RS256")

    def token_with(assn):
        st, _, txt = T.http("POST", base + "/oauth/token", data={
            "grant_type": "client_credentials",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": assn, "scope": "model:invoke", "resource": resource})
        return st

    T.check("first use of an assertion -> 200", token_with(assertion) == 200)
    T.check("replayed assertion (same jti) -> 401", token_with(assertion) == 401)

    # Wrong signing key (attacker signs their own assertion as agent-pk).
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    rogue = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()
    forged = _jwt.encode({"iss": "agent-pk", "sub": "agent-pk", "aud": tep,
                          "iat": now, "exp": now + 60, "jti": "rogue-1"},
                         rogue, algorithm="RS256")
    T.check("assertion signed by the wrong key -> 401 invalid_client",
            token_with(forged) == 401)

    # --- the /vuln foil: static key works with NO aud/scope/expiry check -----
    st, body = ce.invoke(api_key, "gpt-sim", "hi", path="/vuln/v1/models/")
    T.check("/vuln static key invokes any model (the anti-pattern)",
            st == 200 and body.get("model") == "gpt-sim")
    T.check("that same static key is useless on the /safe endpoint (401)",
            ce.invoke(api_key, "gpt-sim", "hi")[0] == 401)

    T.finish(proc)


if __name__ == "__main__":
    main()
