"""test.py — checks for 32-agent-obo. Exits nonzero on failure.

Focus: on-behalf-of delegation (RFC 8693 token exchange). An agent acting for a
user gets a token DOWNSCOPED to sub=user / act=agent whose authority is the
user ∩ agent intersection — so the agent can never exceed the user it serves. The
/vuln path shows the confused deputy: the agent's own broad token reaches a model
the user may not use. DPoP (31) and audience/scope (30) guarantees still hold.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
import testlib as T  # noqa: E402


def _exchange_secret(ce, client_id, secret, subject_token, scope, resource):
    """Token exchange authenticating with a client_secret (agent-secret path)."""
    import dpop
    proof = dpop.create_proof(ce.DPOP_KEY, "POST", ce.BASE + "/oauth/token")
    return ce._req("POST", "/oauth/token", headers={"DPoP": proof}, form={
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": client_id, "client_secret": secret,
        "subject_token": subject_token,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "scope": scope, "resource": resource})


def main():
    T.clean(HERE)
    seed = T.run(HERE, ["seed.py"])
    secret = re.search(r"SECRET:\s*(cs_\S+)", seed.stdout).group(1)

    proc, base = T.start_server(HERE)
    import jwt
    import dpop
    import client_example as ce
    ce.BASE = base

    prm = ce.discover_and_verify_resource()
    resource = prm["resource"]
    meta = ce.discover_as()
    tep = meta["token_endpoint"]
    T.check("AS advertises the token-exchange grant",
            "urn:ietf:params:oauth:grant-type:token-exchange"
            in meta.get("grant_types_supported", []))

    # --- carol delegates to agent-pk; agent exchanges for an OBO token -------
    _, ut = ce.mint_user_token("carol", "agent-pk")
    subject = ut["user_token"]
    T.check("user-token names the delegatee (may_act)", ut.get("may_act") == "agent-pk")

    st, tok = ce.exchange_pk("agent-pk", tep, subject, "model:invoke", resource)
    at = tok["access_token"]
    claims = jwt.decode(at, options={"verify_signature": False})
    T.check("exchange -> OBO token sub=user, act=agent, DPoP-bound",
            st == 200 and claims["sub"] == "carol"
            and claims.get("act", {}).get("sub") == "agent-pk"
            and tok.get("token_type") == "DPoP" and "jkt" in tok.get("cnf", {})
            and tok.get("issued_token_type") == "urn:ietf:params:oauth:token-type:access_token")

    # --- the core lesson: held to CAROL's authority, not the agent's ---------
    T.check("OBO invoke gpt-sim (carol may) -> 200",
            ce.invoke(at, "gpt-sim", "hi")[0] == 200)
    st_e, body_e = ce.invoke(at, "embed-sim", "x")
    T.check("OBO invoke embed-sim (agent may, carol may NOT) -> 403",
            st_e == 403 and body_e.get("error") == "access_denied")

    # dave IS allowed embed-sim -> proves the 403 is the user's limit, not a block
    _, ud = ce.mint_user_token("dave", "agent-pk")
    _, dtok = ce.exchange_pk("agent-pk", tep, ud["user_token"], "model:invoke", resource)
    T.check("OBO for dave (who may) invokes embed-sim -> 200",
            ce.invoke(dtok["access_token"], "embed-sim", "x")[0] == 200)

    # --- scope downscoping: user lacks a scope the agent has -----------------
    # carol has only model:invoke; a read-scoped exchange yields nothing.
    st_ro, ro = ce.exchange_pk("agent-pk", tep, subject, "models:read", resource)
    T.check("exchange requesting a scope the user lacks -> 400 invalid_scope",
            st_ro == 400 and ro.get("error") == "invalid_scope")

    # --- may_act: a DIFFERENT agent cannot act for carol ---------------------
    st_wrong, wr = _exchange_secret(ce, "agent-secret", secret, subject,
                                    "model:invoke", resource)
    T.check("a different agent presenting carol's token -> 403 (may_act pin)",
            st_wrong == 403 and wr.get("error") == "invalid_client")

    # --- an ACCESS token cannot be laundered as a subject token --------------
    _, own = ce.get_token_pk("agent-pk", tep, "model:invoke", resource)
    own_at = own["access_token"]
    st_bad, bad = ce.exchange_pk("agent-pk", tep, own_at, "model:invoke", resource)
    T.check("access token replayed as subject_token -> 400 (wrong aud/token_use)",
            st_bad == 400 and bad.get("error") == "invalid_grant")

    # --- /v1 requires delegation: the agent's OWN token is refused -----------
    T.check("agent's own client_credentials token on /v1 -> 403 delegation_required",
            ce.invoke(own_at, "gpt-sim", "x")[0] == 403)

    # --- the /vuln confused-deputy contrast ----------------------------------
    T.check("agent's own token reaches embed-sim on /vuln -> 200 (confused deputy)",
            ce.invoke(own_at, "embed-sim", "x", path="/vuln/v1/models/")[0] == 200)

    # --- DPoP still enforced on the OBO token (31 guarantee) ------------------
    T.check("stolen OBO token + attacker's own key -> 401 (jkt mismatch)",
            ce.invoke(at, "gpt-sim", "x", dpop_key=ce.new_dpop_key())[0] == 401)

    def invoke_raw(token, model, proof):
        h = {"Authorization": f"DPoP {token}"}
        if proof is not None:
            h["DPoP"] = proof
        return ce._req("POST", f"/v1/models/{model}:invoke", data={"prompt": "x"}, headers=h)

    inv_url = base + "/v1/models/gpt-sim:invoke"
    replay = dpop.create_proof(ce.DPOP_KEY, "POST", inv_url, access_token=at)
    T.check("fresh proof -> 200", invoke_raw(at, "gpt-sim", replay)[0] == 200)
    T.check("replayed proof (same jti) -> 401", invoke_raw(at, "gpt-sim", replay)[0] == 401)
    T.check("OBO token with no DPoP proof -> 401", invoke_raw(at, "gpt-sim", None)[0] == 401)

    # --- audience still enforced (30 guarantee) ------------------------------
    _, other = ce.exchange_pk("agent-pk", tep, subject, "model:invoke",
                              "https://other-upstream.example")
    T.check("OBO token for a different resource -> 401 (audience)",
            ce.invoke(other["access_token"], "gpt-sim", "x")[0] == 401)

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
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": forged, "subject_token": subject,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "scope": "model:invoke", "resource": resource})
    T.check("forged client assertion on exchange -> 401", st_forged == 401)

    T.finish(proc)


if __name__ == "__main__":
    main()
