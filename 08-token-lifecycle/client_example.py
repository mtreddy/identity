"""
client_example.py — the full token lifecycle from a client's point of view.

Pure standard library (urllib). Pass the API key via API_KEY or arg 1:

    API_KEY=sk_live_XXXX python client_example.py

Demonstrates:
  1. API key      -> access + refresh token
  2. use the access token
  3. refresh      -> new access + rotated refresh (old refresh now dead)
  4. REUSE the old refresh -> 401, and the whole refresh family is revoked
  5. revoke an access token by jti -> it stops working before it expires
  6. introspect a token (API-key gated)
"""

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get("API_BASE", "http://127.0.0.1:5000")


def _do(method, path, data=None, bearer=None):
    body = urllib.parse.urlencode(data).encode() if data else None
    req = urllib.request.Request(BASE + path, data=body, method=method)
    if bearer:
        req.add_header("Authorization", f"Bearer {bearer}")
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.load(resp)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def main():
    api_key = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("API_KEY")
    if not api_key:
        print("No API key given. Set API_KEY or pass it as arg 1.")
        sys.exit(2)

    # 1. API key -> token pair
    status, body = _do("POST", "/v1/token", bearer=api_key)
    print(f"1. POST /v1/token                 -> {status} scope={body.get('scope')!r}")
    access1, refresh1 = body["access_token"], body["refresh_token"]

    # 2. use the access token
    print(f"2. GET  /v1/whoami (access1)      -> {_do('GET', '/v1/whoami', bearer=access1)[0]}")

    # 3. refresh -> rotation
    status, body = _do("POST", "/v1/token/refresh", data={"refresh_token": refresh1})
    print(f"3. POST /v1/token/refresh (r1)    -> {status} (rotated)")
    access2, refresh2 = body["access_token"], body["refresh_token"]
    print(f"   GET  /v1/whoami (access2)      -> {_do('GET', '/v1/whoami', bearer=access2)[0]}")

    # 4. reuse the OLD refresh token -> theft signal, family revoked
    status, body = _do("POST", "/v1/token/refresh", data={"refresh_token": refresh1})
    print(f"4. POST /v1/token/refresh (r1 REUSE) -> {status} {body} (family revoked)")
    status, _ = _do("POST", "/v1/token/refresh", data={"refresh_token": refresh2})
    print(f"   POST /v1/token/refresh (r2)    -> {status} (r2 killed by reuse response)")

    # 5. revoke an access token by jti (pre-expiry revocation)
    print(f"5. POST /v1/token/revoke (access2)-> {_do('POST', '/v1/token/revoke', data={'access_token': access2})[0]}")
    print(f"   GET  /v1/whoami (access2)      -> {_do('GET', '/v1/whoami', bearer=access2)}")

    # 6. introspection (requires the API key)
    print(f"6. POST /v1/introspect (access1)  -> {_do('POST', '/v1/introspect', data={'token': access1}, bearer=api_key)[1]}")
    print(f"   POST /v1/introspect (access2)  -> {_do('POST', '/v1/introspect', data={'token': access2}, bearer=api_key)[1]}")


if __name__ == "__main__":
    main()
