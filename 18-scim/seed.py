"""
seed.py — create a provisioning bearer token.

Run once:  python seed.py

This token is the credential the Identity Provider (Okta / Entra ID / …) uses to
authenticate to this SCIM endpoint. It's printed exactly once (only its hash is
stored). Users/Groups are created *through* the SCIM API, not seeded here.
"""

import db


def main():
    db.init_schema()
    token = db.create_token("demo-idp")
    print("SCIM provisioning bearer token (save it — shown once):\n")
    print(f"  {token}\n")
    print("Start the server:  python app.py")
    print(f"Then:  SCIM_TOKEN={token} python client_example.py")
    print("Or curl, e.g.:")
    print(f'  curl -H "Authorization: Bearer {token}" \\')
    print('       -H "Content-Type: application/scim+json" \\')
    print("       http://127.0.0.1:5000/scim/v2/ServiceProviderConfig")


if __name__ == "__main__":
    main()
