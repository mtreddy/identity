"""
client_example.py — how a machine/agent calls the API with its key.

Pure standard library (urllib) so there are no extra dependencies. Pass the
key via the API_KEY environment variable or as the first argument:

    API_KEY=sk_live_XXXX python client_example.py
    python client_example.py sk_live_XXXX

It demonstrates an authenticated call AND what happens with no key (401).
"""

import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("API_BASE", "http://127.0.0.1:5000")


def call(path: str, key: str | None):
    req = urllib.request.Request(BASE + path)
    if key:
        req.add_header("Authorization", f"Bearer {key}")
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.load(resp)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def main():
    key = (sys.argv[1] if len(sys.argv) > 1 else os.environ.get("API_KEY"))
    if not key:
        print("No API key given. Set API_KEY or pass it as arg 1.")
        sys.exit(2)

    print(f"GET /v1/whoami (with key)   -> {call('/v1/whoami', key)}")
    print(f"GET /v1/resources (with key)-> {call('/v1/resources', key)}")
    print(f"GET /v1/whoami (NO key)     -> {call('/v1/whoami', None)}")


if __name__ == "__main__":
    main()
