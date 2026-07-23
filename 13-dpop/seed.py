"""
seed.py — create sample clients, mint one API key each (printed once), and give
each some resources.

Run once:  python seed.py

The API key authenticates the client at the token endpoint; the access token it
receives is then DPoP-bound to the client's own key. Delete identity.db to reset.
"""

import db

SAMPLE_CLIENTS = {
    "billing-agent": (["resources:read"], [
        ("invoice template", "Net-30 terms, remit to Acme Inc."),
        ("tax rate", "8.75%"),
    ]),
    "analytics-agent": (["resources:read"], [
        ("dashboard token", "grafana-ro-abc123"),
    ]),
}


def main():
    db.init_schema()
    print("Sample clients and their API keys (shown once — save one):\n")
    for name, (scopes, resources) in SAMPLE_CLIENTS.items():
        cid = db.create_client(name, scopes)
        key = db.create_api_key(cid)
        for title, body in resources:
            db.add_resource(cid, title, body)
        print(f"  {name} (client_id={cid})  scopes={' '.join(scopes)}")
        print(f"    API key: {key}\n")

    print("Start the server:  python app.py")
    print("Then run the DPoP demo:  API_KEY=<key> python client_example.py")


if __name__ == "__main__":
    main()
