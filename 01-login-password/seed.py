"""
seed.py — build a fresh database with sample identities and resources.

Run this once before starting the server:

    python seed.py

It creates identity.db, two sample users, and a few protected resources
owned by each, so you have something to log in as and something to see
after logging in.
"""

import db

# email -> password (these are the TEST credentials you'll log in with)
SAMPLE_USERS = {
    "alice@example.com": "correct-horse-battery-staple",
    "bob@example.com": "hunter2",
}

# email -> list of (title, body) resources owned by that user
SAMPLE_RESOURCES = {
    "alice@example.com": [
        ("Alice's API key", "sk-alice-1234567890"),
        ("Alice's note", "Remember to rotate the signing key next month."),
    ],
    "bob@example.com": [
        ("Bob's API key", "sk-bob-0987654321"),
    ],
}


def main():
    db.init_schema()

    for email, password in SAMPLE_USERS.items():
        if db.get_user_by_email(email):
            print(f"  user already exists, skipping: {email}")
            continue
        user_id = db.create_user(email, password)
        print(f"  created user: {email} (id={user_id})")

        for title, body in SAMPLE_RESOURCES.get(email, []):
            db.add_resource(user_id, title, body)
            print(f"    + resource: {title}")

    print("\nDone. Sample login credentials:")
    for email, password in SAMPLE_USERS.items():
        print(f"  {email}  /  {password}")


if __name__ == "__main__":
    main()
