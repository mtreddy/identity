"""
seed.py — create sample machine/agent clients, mint one API key each, and
give each some resources.

Run once:  python seed.py

The full API keys are printed EXACTLY ONCE here (only their hashes are stored).
Copy them somewhere; you'll pass them to the API. Re-running won't reprint an
existing client's key — delete identity.db to start over.
"""

import db

SAMPLE_CLIENTS = {
    "billing-agent": [
        ("invoice template", "Net-30 terms, remit to Acme Inc."),
        ("tax rate", "8.75%"),
    ],
    "analytics-agent": [
        ("dashboard token", "grafana-ro-abc123"),
    ],
}


def main():
    db.init_schema()

    print("Sample clients and their API keys (shown once — save them!):\n")
    for name, resources in SAMPLE_CLIENTS.items():
        client_id = db.create_client(name)
        full_key = db.create_api_key(client_id)
        for title, body in resources:
            db.add_resource(client_id, title, body)
        print(f"  {name} (client_id={client_id})")
        print(f"    API key: {full_key}\n")

    print("Try it (replace <KEY> with one of the keys above):")
    print('  curl -H "Authorization: Bearer <KEY>" http://127.0.0.1:5000/v1/whoami')
    print('  curl -H "Authorization: Bearer <KEY>" http://127.0.0.1:5000/v1/resources')


if __name__ == "__main__":
    main()
