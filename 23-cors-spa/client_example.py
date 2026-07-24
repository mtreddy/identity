"""
client_example.py — show the CORS headers the API returns for different origins.

CORS is enforced by the BROWSER, so a headless client can't be "blocked" — but it
CAN see exactly what headers the server sends, which is what the browser bases its
decision on. Each result notes what a browser would do.

    ALLOWED_ORIGINS=http://spa.example python client_example.py
"""

import os
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("API_BASE", "http://127.0.0.1:5000").rstrip("/")
SPA = os.environ.get("SPA_ORIGIN", "http://127.0.0.1:5001")   # an allow-listed origin
EVIL = "http://evil.example"
TOKEN = "demo-spa-token"


def req(method, path, origin, preflight=False):
    headers = {"Origin": origin}
    if preflight:
        headers["Access-Control-Request-Method"] = "GET"
        headers["Access-Control-Request-Headers"] = "authorization"
    else:
        headers["Authorization"] = f"Bearer {TOKEN}"
    r = urllib.request.Request(BASE + path, method=method, headers=headers)
    try:
        resp = urllib.request.urlopen(r)
        return resp.status, resp.headers
    except urllib.error.HTTPError as e:
        return e.code, e.headers


def show(label, status, hdr):
    acao = hdr.get("Access-Control-Allow-Origin")
    creds = hdr.get("Access-Control-Allow-Credentials")
    would = ("browser EXPOSES response" if acao else "browser BLOCKS response")
    print(f"  {label}: {status}  ACAO={acao!r} creds={creds!r}  -> {would}")


def main():
    print(f"allow-listed SPA origin: {SPA}\n")

    print("SAFE endpoint /api/data:")
    show("preflight (allowed origin)", *req("OPTIONS", "/api/data", SPA, preflight=True))
    show("GET (allowed origin)      ", *req("GET", "/api/data", SPA))
    show("GET (disallowed origin)   ", *req("GET", "/api/data", EVIL))

    print("\nMISCONFIGURED endpoint /vuln/data:")
    show("GET (attacker origin)     ", *req("GET", "/vuln/data", EVIL))
    print("  ^ reflects the attacker's origin WITH credentials -> any site can read it")


if __name__ == "__main__":
    if not BASE.startswith("http"):
        print("Set API_BASE."); sys.exit(2)
    main()
