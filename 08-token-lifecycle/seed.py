"""
seed.py — create sample machine/agent clients (each with SCOPES), mint one API
key each, and give each some resources.

Run once:  python seed.py

The full API keys are printed EXACTLY ONCE here (only their hashes are stored).
Copy one; you'll exchange it at POST /v1/token for a short-lived JWT.
Delete identity.db to start over.

Scopes demonstrate least privilege:
  * billing-agent   -> resources:read AND admin  (can hit /v1/admin/stats)
  * analytics-agent -> resources:read only       (gets 403 on /v1/admin/stats)
"""

import db

# name -> (scopes, resources)
SAMPLE_CLIENTS = {
    "billing-agent": (
        ["resources:read", "admin"],
        [
            ("invoice template", "Net-30 terms, remit to Acme Inc."),
            ("tax rate", "8.75%"),
        ],
    ),
    "analytics-agent": (
        ["resources:read"],
        [
            ("dashboard token", "grafana-ro-abc123"),
        ],
    ),
}


def main():
    db.init_schema()

    print("Sample clients and their API keys (shown once — save them!):\n")
    for name, (scopes, resources) in SAMPLE_CLIENTS.items():
        client_id = db.create_client(name, scopes)
        full_key = db.create_api_key(client_id)
        for title, body in resources:
            db.add_resource(client_id, title, body)
        print(f"  {name} (client_id={client_id})  scopes={' '.join(scopes)}")
        print(f"    API key: {full_key}\n")

    print("Try it (replace <KEY> with a key above):")
    print("  # exchange the API key for an access + refresh token pair")
    print('  curl -s -X POST -H "Authorization: Bearer <KEY>" \\')
    print("       http://127.0.0.1:5000/v1/token")
    print("  # then: /v1/token/refresh, /v1/token/revoke, /v1/introspect")
    print("  # or run the full lifecycle demo:")
    print("  #   API_KEY=<KEY> python client_example.py")


if __name__ == "__main__":
    main()
