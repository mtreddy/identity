"""
seed.py — provision the demo agents (clients) and print their secrets ONCE.

Three clients, to contrast the techniques:

  * agent-pk       — private_key_jwt (RFC 7523). We generate its RSA keypair,
                     store the PUBLIC key on the AS, and write the PRIVATE key to
                     agent_private_key.pem (the agent's to keep). Nothing secret
                     is stored server-side. May call gpt-sim and embed-sim.
  * agent-secret   — client_secret_basic. The secret is printed once and stored
                     only as a hash. May call gpt-sim.
  * legacy-agent   — the /vuln foil: a static, long-lived API key.

Run once before the server (like every AS mechanism, secrets are shown once):
    python seed.py
"""

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import db

AGENT_KEY_FILE = Path(os.environ.get(
    "AGENT_KEY_FILE", Path(__file__).parent / "agent_private_key.pem"))


def main():
    db.init_schema()
    if db.get_client("agent-pk"):
        print("Already seeded (clients exist). Delete app.db to re-seed.")
        return

    # --- agent-pk: generate the agent's keypair (private_key_jwt) ------------
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    AGENT_KEY_FILE.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    db.create_pk_client("agent-pk", "PK-JWT agent", public_pem,
                        "models:read model:invoke", "gpt-sim embed-sim")

    # --- agent-secret: client_secret_basic ----------------------------------
    secret = db.create_secret_client("agent-secret", "Secret agent",
                                     "models:read model:invoke", "gpt-sim")

    # --- legacy-agent: the static-key foil ----------------------------------
    api_key = db.create_api_key("legacy-agent")

    print("Provisioned 3 agents.\n")
    print(f"  agent-pk       private_key_jwt; private key -> {AGENT_KEY_FILE.name}")
    print(f"  agent-secret   client_secret_basic; SECRET: {secret}")
    print(f"  legacy-agent   /vuln static API key:  {api_key}")
    print(f"\nGateway resource (audience): {__import__('config').GATEWAY_RESOURCE}")
    print("Start the server:  python app.py   then:  python client_example.py")


if __name__ == "__main__":
    main()
