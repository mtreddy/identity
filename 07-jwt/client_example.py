"""
client_example.py — how a machine/agent uses the token flow.

Pure standard library (urllib). Pass the API key via API_KEY or arg 1:

    API_KEY=sk_live_XXXX python client_example.py

Steps demonstrated:
  1. exchange the API key at POST /v1/token for a short-lived JWT
  2. call /v1/whoami and /v1/resources with the JWT
  3. try /v1/admin/stats (200 only if the client has the 'admin' scope, else 403)
  4. show that a garbage token is rejected (401)
"""

import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("API_BASE", "http://127.0.0.1:5000")


def call(method: str, path: str, bearer: str | None):
    req = urllib.request.Request(BASE + path, method=method)
    if bearer:
        req.add_header("Authorization", f"Bearer {bearer}")
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.load(resp)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def main():
    key = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("API_KEY")
    if not key:
        print("No API key given. Set API_KEY or pass it as arg 1.")
        sys.exit(2)

    # 1) API key -> JWT
    status, body = call("POST", "/v1/token", key)
    print(f"POST /v1/token             -> ({status}, {body})")
    if status != 200:
        sys.exit(1)
    token = body["access_token"]

    # 2) use the JWT
    print(f"GET  /v1/whoami   (JWT)    -> {call('GET', '/v1/whoami', token)}")
    print(f"GET  /v1/resources (JWT)   -> {call('GET', '/v1/resources', token)}")
    # 3) scope-gated endpoint
    print(f"GET  /v1/admin/stats (JWT) -> {call('GET', '/v1/admin/stats', token)}")
    # 4) tampered / garbage token
    print(f"GET  /v1/whoami (bad JWT)  -> {call('GET', '/v1/whoami', token + 'x')}")


if __name__ == "__main__":
    main()
