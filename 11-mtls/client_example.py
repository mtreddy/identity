"""
client_example.py — call the mTLS API by presenting a client certificate.

Pure standard library (ssl + http.client). Pick which agent's cert to use:

    python client_example.py billing-agent

It shows an authenticated call with the cert, and what happens with NO client
cert (the TLS handshake fails — the request never reaches the app).
"""

import http.client
import json
import os
import ssl
import sys
from pathlib import Path

CERT_DIR = Path(os.environ.get("CERT_DIR", Path(__file__).parent / "certs"))
HOST = os.environ.get("SERVER_HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "5000"))


def _context(client_cert=None, client_key=None):
    # PROTOCOL_TLS_CLIENT verifies the SERVER cert (against our CA) and checks
    # the hostname — that's the "mutual" other half. If a client cert is given,
    # we present it so the server can verify US.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(CERT_DIR / "ca.crt")
    if client_cert:
        ctx.load_cert_chain(client_cert, client_key)
    return ctx


def call(path, client_cert=None, client_key=None):
    ctx = _context(client_cert, client_key)
    conn = http.client.HTTPSConnection(HOST, PORT, context=ctx)
    conn.request("GET", path)
    resp = conn.getresponse()
    body = resp.read().decode()
    conn.close()
    return resp.status, json.loads(body)


def main():
    agent = sys.argv[1] if len(sys.argv) > 1 else "billing-agent"
    cert, key = CERT_DIR / f"{agent}.crt", CERT_DIR / f"{agent}.key"
    if not cert.exists():
        print(f"No cert for {agent}. Run: python seed.py"); sys.exit(2)

    print(f"Using client cert: {cert.name}")
    print(f"  GET /v1/whoami     -> {call('/v1/whoami', cert, key)}")
    print(f"  GET /v1/resources  -> {call('/v1/resources', cert, key)}")

    print("\nNow WITHOUT a client certificate (must fail at the TLS handshake):")
    try:
        print(f"  GET /v1/whoami     -> {call('/v1/whoami')}")
        print("  UNEXPECTED: the server accepted a connection with no client cert!")
    except (ssl.SSLError, OSError) as e:
        print(f"  handshake refused -> {type(e).__name__}: {e}")


if __name__ == "__main__":
    main()
