"""
client_example.py — the AGENT. Reusable helpers (imported by test.py) plus a
main() that walks the whole flow and contrasts it with the /vuln anti-pattern.

The safe flow, end to end:
  1. discover the gateway's Protected Resource Metadata and VERIFY the endpoint
     (its canonical `resource` id matches what we expect) before sending a prompt;
  2. discover the authorization server;
  3. mint a short-lived, audience-bound, scoped token (private_key_jwt);
  4. call the model.
Then it shows the rejections that make the design hold (wrong audience, missing
scope, disallowed model) and the /vuln static-key call it replaces.
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

BASE = os.environ.get("BASE_URL", "http://127.0.0.1:5000")
# What the agent EXPECTS the gateway's canonical resource id to be (its pin).
EXPECTED_RESOURCE = os.environ.get("GATEWAY_RESOURCE", "https://models.example/api")
AGENT_KEY_FILE = Path(os.environ.get(
    "AGENT_KEY_FILE", Path(__file__).parent / "agent_private_key.pem"))


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
    """Fetch Protected Resource Metadata and pin the canonical resource id."""
    _, prm = _req("GET", "/.well-known/oauth-protected-resource")
    if prm.get("resource") != EXPECTED_RESOURCE:
        raise RuntimeError(f"endpoint verification failed: {prm.get('resource')!r}")
    return prm


def discover_as():
    _, meta = _req("GET", "/.well-known/oauth-authorization-server")
    return meta


# --- token acquisition ------------------------------------------------------

def _client_assertion(client_id, token_endpoint):
    now = int(time.time())
    return jwt.encode(
        {"iss": client_id, "sub": client_id, "aud": token_endpoint,
         "iat": now, "exp": now + 60, "jti": secrets.token_urlsafe(16)},
        AGENT_KEY_FILE.read_text(), algorithm="RS256")


def get_token_pk(client_id, token_endpoint, scope, resource):
    """private_key_jwt: sign an assertion, exchange it for an access token."""
    return _req("POST", "/oauth/token", form={
        "grant_type": "client_credentials",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": _client_assertion(client_id, token_endpoint),
        "scope": scope, "resource": resource})


def get_token_secret(client_id, secret, scope, resource):
    return _req("POST", "/oauth/token", form={
        "grant_type": "client_credentials", "client_id": client_id,
        "client_secret": secret, "scope": scope, "resource": resource})


def invoke(token, model, prompt, path="/v1/models/"):
    return _req("POST", f"{path}{model}:invoke", data={"prompt": prompt},
                headers={"Authorization": f"Bearer {token}"})


def main():
    prm = discover_and_verify_resource()
    resource = prm["resource"]
    meta = discover_as()
    tep = meta["token_endpoint"]
    print(f"verified gateway resource = {resource}")

    st, tok = get_token_pk("agent-pk", tep, "model:invoke", resource)
    print("token via private_key_jwt:", st, "scope=", tok.get("scope"))
    print("  invoke gpt-sim:", invoke(tok["access_token"], "gpt-sim", "hello there")[1]["output"])

    print("\n-- rejections that make it hold --")
    _, wrong = get_token_pk("agent-pk", tep, "model:invoke", "https://other-upstream.example")
    print("  token for a DIFFERENT resource, used here ->",
          invoke(wrong["access_token"], "gpt-sim", "x")[0], "(audience mismatch)")
    _, ro = get_token_pk("agent-pk", tep, "models:read", resource)
    print("  read-only token calling :invoke ->",
          invoke(ro["access_token"], "gpt-sim", "x")[0], "(insufficient scope)")
    st, sec_tok = get_token_secret("agent-secret",
                                   os.environ.get("AGENT_SECRET", ""), "model:invoke", resource)
    if st == 200:
        print("  agent-secret calling embed-sim ->",
              invoke(sec_tok["access_token"], "embed-sim", "x")[0], "(model not allow-listed)")

    print("\n-- the /vuln anti-pattern it replaces --")
    key = os.environ.get("LEGACY_API_KEY", "")
    if key:
        st, body = invoke(key, "gpt-sim", "hello", path="/vuln/v1/models/")
        print("  static key, no aud/scope/expiry ->", st, body.get("output"))


if __name__ == "__main__":
    main()
