"""
client_example.py — call the SPIFFE API as different workloads.

Shows:
  1. billing X.509-SVID (mTLS) -> whoami + resources
  2. analytics X.509-SVID -> only its own resources (isolation)
  3. rogue X.509-SVID (valid cert, in-domain, but not in policy) -> 403
  4. foreign SVID (signed by a non-bundle CA) -> TLS handshake refused
  5. JWT-SVID (no client cert): correct audience works; wrong audience is rejected

Note: SPIFFE peers verify each other by SPIFFE ID, not hostname — so we disable
hostname checking, verify the server cert against the trust bundle, and then
confirm the server's SPIFFE ID.
"""

import http.client
import json
import os
import ssl
from pathlib import Path

from cryptography import x509

import spiffe
import trust  # stands in for the SPIFFE Workload API when minting a JWT-SVID

SVID_DIR = Path(os.environ.get("SVID_DIR", Path(__file__).parent / "svids"))
HOST = os.environ.get("SERVER_HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "5000"))
TRUST_DOMAIN = trust.TRUST_DOMAIN
SERVER_ID = f"spiffe://{TRUST_DOMAIN}/workload/api-server"


def _ctx(client=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(SVID_DIR / "bundle_ca.pem")
    ctx.check_hostname = False   # SPIFFE identifies the server by its SPIFFE ID
    if client:
        ctx.load_cert_chain(SVID_DIR / f"{client}.pem", SVID_DIR / f"{client}_key.pem")
    return ctx


def call(path, client=None, bearer=None):
    conn = http.client.HTTPSConnection(HOST, PORT, context=_ctx(client))
    conn.connect()
    der = conn.sock.getpeercert(binary_form=True)
    server_sid = spiffe.spiffe_id_from_cert(x509.load_der_x509_certificate(der))
    if server_sid != SERVER_ID:
        conn.close()
        raise ssl.SSLError(f"unexpected server SPIFFE ID: {server_sid}")
    headers = {"Authorization": f"Bearer {bearer}"} if bearer else {}
    conn.request("GET", path, headers=headers)
    r = conn.getresponse()
    body = json.loads(r.read().decode())
    conn.close()
    return r.status, body


def main():
    print(f"server verified as {SERVER_ID}\n")

    print("X.509-SVID (mTLS):")
    print(f"  billing   /x509/whoami     -> {call('/x509/whoami', client='billing')}")
    print(f"  billing   /x509/resources  -> {call('/x509/resources', client='billing')[1]}")
    print(f"  analytics /x509/resources  -> {call('/x509/resources', client='analytics')[1]}")
    print(f"  rogue     /x509/whoami     -> {call('/x509/whoami', client='rogue')}  (valid SVID, no grant)")

    print("\nForeign SVID (signed by a CA not in the trust bundle):")
    try:
        call("/x509/whoami", client="foreign")
        print("  UNEXPECTED: accepted")
    except ssl.SSLError as e:
        print(f"  handshake refused -> {getattr(e, 'reason', e)}")

    print("\nJWT-SVID (no client certificate):")
    billing_id = f"spiffe://{TRUST_DOMAIN}/workload/billing"
    good = trust.issue_jwt_svid(billing_id, audience=SERVER_ID)
    print(f"  billing JWT-SVID (aud=server) -> {call('/jwt/whoami', bearer=good)}")
    wrong = trust.issue_jwt_svid(billing_id, audience=f"spiffe://{TRUST_DOMAIN}/workload/other")
    print(f"  JWT-SVID wrong audience       -> {call('/jwt/whoami', bearer=wrong)}")


if __name__ == "__main__":
    main()
