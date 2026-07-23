"""
client_example.py — obtain and use a DPoP-bound token, and show why a stolen
one can't be replayed.

The client generates its own EC keypair, signs a fresh DPoP proof for every
request, and gets an access token bound to that key. Then it demonstrates:

  1. happy path (proof + token) -> works
  2. stolen token, NO proof -> rejected
  3. stolen token + an ATTACKER's own valid proof (different key) -> rejected
  4. proof REPLAY (reuse a jti) -> rejected
  5. proof for the WRONG url -> rejected

Pure standard library HTTP (urllib) + cryptography (EC key) + PyJWT (via dpop.py).
"""

import json
import os
import sys
import urllib.error
import urllib.request

from cryptography.hazmat.primitives.asymmetric import ec

import dpop

BASE = os.environ.get("API_BASE", "http://127.0.0.1:5000").rstrip("/")
TOKEN_URL = BASE + "/v1/token"
RES_URL = BASE + "/v1/resources"


def _send(method, url, headers, data=None):
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def get_token(api_key, priv):
    proof = dpop.create_proof(priv, "POST", TOKEN_URL)
    return _send("POST", TOKEN_URL, {"X-API-Key": api_key, "DPoP": proof})


def call_resources(token, proof):
    return _send("GET", RES_URL, {"Authorization": f"DPoP {token}", "DPoP": proof})


def main():
    api_key = os.environ.get("API_KEY") or (sys.argv[1] if len(sys.argv) > 1 else None)
    if not api_key:
        print("Set API_KEY (or pass it as arg 1)."); sys.exit(2)

    priv = ec.generate_private_key(ec.SECP256R1())          # the client's key
    attacker = ec.generate_private_key(ec.SECP256R1())      # a different key

    st, tok = get_token(api_key, priv)
    token = tok["access_token"]
    print(f"1. POST /v1/token                       -> {st} bound jkt={tok['cnf']['jkt'][:12]}…")

    # 1. happy path: fresh proof bound to this token
    proof = dpop.create_proof(priv, "GET", RES_URL, access_token=token)
    print(f"   GET /v1/resources (proof + token)    -> {call_resources(token, proof)}")

    # 2. stolen token, no proof header at all
    st, body = _send("GET", RES_URL, {"Authorization": f"DPoP {token}"})
    print(f"2. stolen token, NO proof               -> {st} {body}")

    # 3. stolen token + attacker's own valid proof (signed with the WRONG key)
    a_proof = dpop.create_proof(attacker, "GET", RES_URL, access_token=token)
    print(f"3. stolen token + attacker's proof      -> {call_resources(token, a_proof)}  (jkt mismatch)")

    # 4. proof replay: reuse the exact same proof twice
    replay = dpop.create_proof(priv, "GET", RES_URL, access_token=token)
    print(f"4a. first use of a proof                -> {call_resources(token, replay)[0]}")
    print(f"4b. REPLAY the same proof               -> {call_resources(token, replay)}")

    # 5. proof made for a different URL (htu mismatch)
    wrong = dpop.create_proof(priv, "GET", BASE + "/v1/whoami", access_token=token)
    print(f"5. proof for wrong URL (htu mismatch)   -> {call_resources(token, wrong)}")


if __name__ == "__main__":
    main()
