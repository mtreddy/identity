"""
client_example.py — the AGENT, now with DPoP (RFC 9449). Reusable helpers
(imported by test.py) plus a main() that walks the flow and then shows a
*stolen* token failing on the safe endpoint but replaying on the /vuln one.

The agent holds two keys: its private_key_jwt RSA key (identity, from seed) and
an ephemeral EC **DPoP key** (proof-of-possession) it generates here. It proves
possession of the DPoP key when it fetches the token (so the token gets
`cnf.jkt`) and again on every call. Whoever lacks that key can't use the token.
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

import dpop

BASE = os.environ.get("BASE_URL", "http://127.0.0.1:5000")
EXPECTED_RESOURCE = os.environ.get("GATEWAY_RESOURCE", "https://models.example/api")
AGENT_KEY_FILE = Path(os.environ.get(
    "AGENT_KEY_FILE", Path(__file__).parent / "agent_private_key.pem"))

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


# --- token acquisition (DPoP-bound) -----------------------------------------

def _client_assertion(client_id, token_endpoint):
    now = int(time.time())
    return jwt.encode(
        {"iss": client_id, "sub": client_id, "aud": token_endpoint,
         "iat": now, "exp": now + 60, "jti": secrets.token_urlsafe(16)},
        AGENT_KEY_FILE.read_text(), algorithm="RS256")


def get_token_pk(client_id, token_endpoint, scope, resource, dpop_key=DPOP_KEY):
    """private_key_jwt + a DPoP proof -> a DPoP-bound access token."""
    proof = dpop.create_proof(dpop_key, "POST", BASE + "/oauth/token")
    return _req("POST", "/oauth/token", headers={"DPoP": proof}, form={
        "grant_type": "client_credentials",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": _client_assertion(client_id, token_endpoint),
        "scope": scope, "resource": resource})


def get_token_secret(client_id, secret, scope, resource, dpop_key=DPOP_KEY):
    proof = dpop.create_proof(dpop_key, "POST", BASE + "/oauth/token")
    return _req("POST", "/oauth/token", headers={"DPoP": proof}, form={
        "grant_type": "client_credentials", "client_id": client_id,
        "client_secret": secret, "scope": scope, "resource": resource})


def invoke(token, model, prompt, dpop_key=DPOP_KEY, path="/v1/models/", scheme="DPoP"):
    """Call the gateway. scheme='DPoP' attaches a proof (safe path); scheme=
    'Bearer' sends the token with no proof (the /vuln path an attacker uses)."""
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

    st, tok = get_token_pk("agent-pk", tep, "model:invoke", resource)
    at = tok["access_token"]
    print("DPoP-bound token via private_key_jwt:", st, "cnf=", tok.get("cnf"))
    print("  invoke gpt-sim (with proof):", invoke(at, "gpt-sim", "hello")[1]["output"])

    print("\n-- a STOLEN token (attacker has the string, not the DPoP key) --")
    attacker = new_dpop_key()
    print("  attacker on /safe, proof from a different key ->",
          invoke(at, "gpt-sim", "x", dpop_key=attacker)[0], "(jkt mismatch)")
    print("  attacker on /vuln, plain bearer, no proof ->",
          invoke(at, "gpt-sim", "x", path="/vuln/v1/models/", scheme="Bearer")[0],
          "(replay works — what DPoP prevents)")


if __name__ == "__main__":
    main()
