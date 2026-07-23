"""
seed.py — stand up the demo PKI and register the machine/agent clients.

Run once:  python seed.py

It creates (idempotently, under certs/):
  * ca.crt / ca.key       the Certificate Authority (the trust root)
  * server.crt / server.key   the API server's TLS certificate
  * <agent>.crt / <agent>.key one client certificate per agent (CN = agent name)

and registers each client + its cert fingerprint in the database, with some
resources. The private keys never leave this machine; certs/ is git-ignored.
"""

import os
from pathlib import Path

import db
import pki

CERT_DIR = Path(os.environ.get("CERT_DIR", Path(__file__).parent / "certs"))
SERVER_IP = os.environ.get("SERVER_IP", "127.0.0.1")

AGENTS = {
    "billing-agent": [
        ("invoice template", "Net-30 terms, remit to Acme Inc."),
        ("tax rate", "8.75%"),
    ],
    "analytics-agent": [
        ("dashboard token", "grafana-ro-abc123"),
    ],
}


def _load_or_make_ca():
    if (CERT_DIR / "ca.crt").exists():
        print("using existing CA (certs/ca.crt)")
        return pki.load_cert(CERT_DIR / "ca.crt"), pki.load_key(CERT_DIR / "ca.key")
    ca_cert, ca_key = pki.create_ca()
    pki.save_cert(CERT_DIR / "ca.crt", ca_cert)
    pki.save_key(CERT_DIR / "ca.key", ca_key)
    print("created CA -> certs/ca.crt")
    return ca_cert, ca_key


def main():
    CERT_DIR.mkdir(exist_ok=True)
    db.init_schema()
    ca_cert, ca_key = _load_or_make_ca()

    if not (CERT_DIR / "server.crt").exists():
        sc, sk = pki.issue_cert(ca_cert, ca_key, "identity-11 server",
                                server=True, ip=SERVER_IP, dns="localhost")
        pki.save_cert(CERT_DIR / "server.crt", sc)
        pki.save_key(CERT_DIR / "server.key", sk)
        print(f"created server cert (SAN {SERVER_IP}, localhost) -> certs/server.crt")

    print("\nClient certificates (CN = identity):")
    for name, resources in AGENTS.items():
        cert_path, key_path = CERT_DIR / f"{name}.crt", CERT_DIR / f"{name}.key"
        if cert_path.exists():
            cert = pki.load_cert(cert_path)
        else:
            cert, key = pki.issue_cert(ca_cert, ca_key, name, server=False)
            pki.save_cert(cert_path, cert)
            pki.save_key(key_path, key)

        client = db.get_client_by_name(name)
        if client is None:
            client_id = db.create_client(name)
            for title, body in resources:
                db.add_resource(client_id, title, body)
        else:
            client_id = client["id"]

        db.register_cert(pki.fingerprint(cert), client_id, name)
        print(f"  {name}: certs/{name}.crt  (fp {pki.fingerprint(cert)[:16]}…)")

    print("\nStart the server:  python app.py")
    print("Call it (curl needs the client cert):")
    print("  curl --cacert certs/ca.crt --cert certs/billing-agent.crt \\")
    print("       --key certs/billing-agent.key https://127.0.0.1:5000/v1/whoami")
    print("Or:  python client_example.py billing-agent")


if __name__ == "__main__":
    main()
