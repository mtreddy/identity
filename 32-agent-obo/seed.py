"""
seed.py — provision the demo agents (clients) AND the users they act for.

Two clients, contrasting how the agent authenticates to the token endpoint:

  * agent-pk       — private_key_jwt (RFC 7523). We generate its RSA keypair,
                     store the PUBLIC key on the AS, and write the PRIVATE key to
                     agent_private_key.pem (the agent's to keep). Nothing secret
                     is stored server-side. May call gpt-sim and embed-sim.
  * agent-secret   — client_secret_basic. The secret is printed once and stored
                     only as a hash. May call gpt-sim.

Two users, with DIFFERENT authority — this is what the OBO lesson turns on:

  * carol          — may only invoke gpt-sim (NOT embed-sim).
  * dave            — may read + invoke gpt-sim and embed-sim.

agent-pk is allow-listed for embed-sim, but carol is not. So when the agent acts
*on behalf of carol* it must NOT be able to reach embed-sim — the OBO token is
downscoped to carol's authority. The /vuln path (agent uses its OWN token) shows
what breaks without that: the agent reaches embed-sim for carol anyway.

The DPoP proof-of-possession key is separate and ephemeral: the agent generates
it at runtime (see client_example.py), not here.

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

    # --- users the agents act on behalf of (each with its own authority) -----
    db.create_user("carol", "Carol", "model:invoke", "gpt-sim")
    db.create_user("dave", "Dave", "models:read model:invoke", "gpt-sim embed-sim")

    print("Provisioned 2 agents and 2 users.\n")
    print(f"  agent-pk       private_key_jwt; private key -> {AGENT_KEY_FILE.name}")
    print(f"  agent-secret   client_secret_basic; SECRET: {secret}")
    print("  user carol     may invoke gpt-sim only (NOT embed-sim)")
    print("  user dave      may read+invoke gpt-sim and embed-sim")
    print(f"\nGateway resource (audience): {__import__('config').GATEWAY_RESOURCE}")
    print("Start the server:  python app.py   then:  python client_example.py")


if __name__ == "__main__":
    main()
