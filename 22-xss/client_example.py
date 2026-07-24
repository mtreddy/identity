"""
client_example.py — send an XSS payload to the vulnerable vs. safe endpoints and
show whether it comes back as executable HTML or inert text.

(Headless: we can't run the JavaScript, but we can see whether the server
reflected the payload verbatim — which a browser WOULD execute — or encoded it.)

    python client_example.py     (server must be running)
"""

import os
import sys
import urllib.parse
import urllib.request

BASE = os.environ.get("API_BASE", "http://127.0.0.1:5000").rstrip("/")
PAYLOAD = "<script>alert(document.domain)</script>"


def get(path):
    with urllib.request.urlopen(BASE + path) as r:
        return r.status, r.read().decode(), r.headers


def post(path, data):
    body = urllib.parse.urlencode(data).encode()
    with urllib.request.urlopen(urllib.request.Request(BASE + path, data=body)) as r:
        return r.status, r.read().decode()


def verdict(body):
    if PAYLOAD in body:
        return "RAW <script> reflected -> would EXECUTE in a browser"
    if "&lt;script&gt;" in body:
        return "encoded as text -> inert"
    return "not found"


def main():
    q = "?q=" + urllib.parse.quote(PAYLOAD)
    print("REFLECTED:")
    _, body, _ = get("/vuln/search" + q)
    print(f"  /vuln/search -> {verdict(body)}")
    _, body, hdr = get("/safe/search" + q)
    print(f"  /safe/search -> {verdict(body)}  | CSP: {hdr.get('Content-Security-Policy', '(none)')[:32]}…")

    print("STORED:")
    post("/vuln/comments", {"comment": PAYLOAD})
    _, body = get("/vuln/comments")[:2]
    print(f"  /vuln/comments -> {verdict(body)}")
    post("/safe/comments", {"comment": PAYLOAD})
    _, body = get("/safe/comments")[:2]
    print(f"  /safe/comments -> {verdict(body)}")

    print("COOKIE:")
    _, _, hdr = get("/")
    sc = hdr.get("Set-Cookie", "")
    print(f"  session cookie HttpOnly? {'HttpOnly' in sc}  (so document.cookie can't read it)")


if __name__ == "__main__":
    if not BASE.startswith("http"):
        print("Set API_BASE."); sys.exit(2)
    main()
