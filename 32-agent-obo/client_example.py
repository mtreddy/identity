"""
client_example.py — the AGENT acting ON BEHALF OF a user (RFC 8693). Reusable
helpers (imported by test.py) plus a main() that walks the flow and contrasts the
downscoped OBO call with the /vuln confused-deputy call.

The flow:
  1. the user "logs in" and delegates to this agent  -> a user (subject) token
  2. the agent EXCHANGES that token for a downscoped access token (sub=user,
     act=agent), DPoP-bound to the agent's key
  3. the agent invokes the model — and is held to the USER's authority, so it
     cannot reach a model the user may not use, even one the agent itself may.

The agent still holds two keys as in 31: its private_key_jwt RSA key (identity)
and an ephemeral EC DPoP key (proof-of-possession). DPoP is unchanged here.
"""

import json
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import jwt  # PyJWT
from cryptography.hazmat.primitives.asymmetric import ec

import config
import dpop

BASE = os.environ.get("BASE_URL", "http://127.0.0.1:5000")
EXPECTED_RESOURCE = os.environ.get("GATEWAY_RESOURCE", "https://models.example/api")
AGENT_KEY_FILE = Path(os.environ.get(
    "AGENT_KEY_FILE", Path(__file__).parent / "agent_private_key.pem"))

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

# The agent's DPoP key (proof-of-possession). Ephemeral — per session.
DPOP_KEY = ec.generate_private_key(ec.SECP256R1())


def new_dpop_key():
    """A fresh EC key — used in tests to play an attacker with a *different* key."""
    return ec.generate_private_key(ec.SECP256R1())


def _req(method, path, data=None, headers=None, form=None):
    body, hdrs = None, dict(headers or {})
    if form is not None:
        body = urllib.parse.urlencode(form).encode()
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    elif data is not None:
        body = json.dumps(data).encode()
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(BASE + path, data=body, method=method, headers=hdrs)
    try:
        r = urllib.request.urlopen(req)
        return r.status, json.loads(r.read() or "{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or "{}")


# --- discovery + endpoint verification --------------------------------------

def discover_and_verify_resource():
    _, prm = _req("GET", "/.well-known/oauth-protected-resource")
    if prm.get("resource") != EXPECTED_RESOURCE:
        raise RuntimeError(f"endpoint verification failed: {prm.get('resource')!r}")
    return prm


def discover_as():
    _, meta = _req("GET", "/.well-known/oauth-authorization-server")
    return meta


# --- the user login (OIDC stand-in) -> a subject token ----------------------

def mint_user_token(user_id, delegatee):
    """Simulate the user signing in and delegating to `delegatee`. In production
    this is an OIDC login (mechanism 10); the agent receives the user's token."""
    return _req("POST", "/oauth/user-token",
                form={"user_id": user_id, "delegatee": delegatee})


# --- token acquisition ------------------------------------------------------

def _client_assertion(client_id, token_endpoint):
    now = int(time.time())
    return jwt.encode(
        {"iss": client_id, "sub": client_id, "aud": token_endpoint,
         "iat": now, "exp": now + 60, "jti": secrets.token_urlsafe(16)},
        AGENT_KEY_FILE.read_text(), algorithm="RS256")


def get_token_pk(client_id, token_endpoint, scope, resource, dpop_key=DPOP_KEY):
    """client_credentials via private_key_jwt -> the AGENT'S OWN DPoP-bound token
    (sub == agent, no delegation). This is what the /vuln path misuses."""
    proof = dpop.create_proof(dpop_key, "POST", BASE + "/oauth/token")
    return _req("POST", "/oauth/token", headers={"DPoP": proof}, form={
        "grant_type": "client_credentials",
        "client_assertion_type": ASSERTION_TYPE,
        "client_assertion": _client_assertion(client_id, token_endpoint),
        "scope": scope, "resource": resource})


def exchange_pk(client_id, token_endpoint, subject_token, scope, resource,
                dpop_key=DPOP_KEY):
    """RFC 8693 token exchange via private_key_jwt -> a DOWNSCOPED OBO token
    (sub == user, act == agent), DPoP-bound to `dpop_key`."""
    proof = dpop.create_proof(dpop_key, "POST", BASE + "/oauth/token")
    return _req("POST", "/oauth/token", headers={"DPoP": proof}, form={
        "grant_type": config.TE_GRANT,
        "client_assertion_type": ASSERTION_TYPE,
        "client_assertion": _client_assertion(client_id, token_endpoint),
        "subject_token": subject_token,
        "subject_token_type": config.TT_ACCESS,
        "scope": scope, "resource": resource})


def invoke(token, model, prompt, dpop_key=DPOP_KEY, path="/v1/models/", scheme="DPoP"):
    """Call the gateway with a DPoP proof (both /v1 and /vuln require one here —
    the difference between them is delegation, not proof-of-possession)."""
    url_path = f"{path}{model}:invoke"
    headers = {"Authorization": f"{scheme} {token}"}
    if scheme == "DPoP":
        headers["DPoP"] = dpop.create_proof(dpop_key, "POST", BASE + url_path,
                                            access_token=token)
    return _req("POST", url_path, data={"prompt": prompt}, headers=headers)


def main():
    prm = discover_and_verify_resource()
    resource = prm["resource"]
    tep = discover_as()["token_endpoint"]
    print(f"verified gateway resource = {resource}")

    # 1. carol logs in and delegates to agent-pk (OIDC stand-in).
    _, ut = mint_user_token("carol", "agent-pk")
    subject = ut["user_token"]
    print(f"\nuser carol delegated to agent-pk (may_act={ut['may_act']})")

    # 2. the agent exchanges carol's token for a downscoped OBO token.
    st, tok = exchange_pk("agent-pk", tep, subject, "model:invoke", resource)
    at = tok["access_token"]
    claims = jwt.decode(at, options={"verify_signature": False})
    print(f"exchanged -> OBO token: sub={claims['sub']} act={claims['act']} "
          f"scope={claims['scope']!r} cnf={tok.get('cnf')}")

    # 3. held to carol's authority: gpt-sim OK, embed-sim refused.
    print("  invoke gpt-sim  (carol may)     ->", invoke(at, "gpt-sim", "hello")[0])
    st_e, body_e = invoke(at, "embed-sim", "x")
    print("  invoke embed-sim (carol may NOT) ->", st_e,
          f"({body_e.get('error')}) — the agent CANNOT exceed carol")

    # --- the /vuln contrast: the agent uses its OWN broad token ---------------
    print("\n-- /vuln: agent uses its OWN client_credentials token for carol --")
    _, own = get_token_pk("agent-pk", tep, "model:invoke", resource)
    own_at = own["access_token"]
    print("  own token, embed-sim on /v1  ->",
          invoke(own_at, "embed-sim", "x")[0], "(delegation_required)")
    print("  own token, embed-sim on /vuln ->",
          invoke(own_at, "embed-sim", "x", path="/vuln/v1/models/")[0],
          "(confused deputy — the agent exceeds carol; what OBO prevents)")


if __name__ == "__main__":
    main()
