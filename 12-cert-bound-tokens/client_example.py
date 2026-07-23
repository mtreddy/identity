"""
client_example.py — obtain and use a certificate-bound token, and show why a
stolen one can't be replayed.

Pure standard library (ssl + http.client). It:
  1. gets a token for billing-agent over mTLS (bound to billing's cert),
  2. uses it WITH billing's cert (works),
  3. simulates theft: replays billing's token WITH analytics's cert (rejected),
  4. and (control) uses analytics's own token with analytics's cert (works).
"""

import http.client
import json
import os
import ssl
from pathlib import Path

CERT_DIR = Path(os.environ.get("CERT_DIR", Path(__file__).parent / "certs"))
HOST = os.environ.get("SERVER_HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "5000"))


def _conn(agent):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(CERT_DIR / "ca.crt")
    ctx.load_cert_chain(CERT_DIR / f"{agent}.crt", CERT_DIR / f"{agent}.key")
    return http.client.HTTPSConnection(HOST, PORT, context=ctx)


def req(agent, method, path, bearer=None):
    """Make a request over mTLS using `agent`'s client cert."""
    conn = _conn(agent)
    headers = {"Authorization": f"Bearer {bearer}"} if bearer else {}
    conn.request(method, path, headers=headers)
    r = conn.getresponse()
    body = json.loads(r.read().decode())
    conn.close()
    return r.status, body


def main():
    # 1. billing-agent gets a token over mTLS (bound to billing's cert)
    st, tok = req("billing-agent", "POST", "/v1/token")
    billing_token = tok["access_token"]
    print(f"1. billing POST /v1/token            -> {st} "
          f"bound x5t={tok['cnf']['x5t#S256'][:12]}…")

    # 2. billing uses its token WITH its own cert -> works
    st, body = req("billing-agent", "GET", "/v1/resources", billing_token)
    titles = [r["title"] for r in body.get("resources", [])]
    print(f"2. billing token + billing cert      -> {st} {titles}")

    # 3. THEFT: analytics replays billing's token WITH analytics's cert
    st, body = req("analytics-agent", "GET", "/v1/resources", billing_token)
    print(f"3. billing token + ANALYTICS cert    -> {st} {body}  (replay blocked)")

    # 4. control: analytics gets + uses its OWN cert-bound token
    _, tok2 = req("analytics-agent", "POST", "/v1/token")
    st, body = req("analytics-agent", "GET", "/v1/resources", tok2["access_token"])
    titles = [r["title"] for r in body.get("resources", [])]
    print(f"4. analytics token + analytics cert  -> {st} {titles}")


if __name__ == "__main__":
    main()
