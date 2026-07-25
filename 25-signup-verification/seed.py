"""
seed.py — create the schema and one PRE-VERIFIED sample account.

Unlike earlier mechanisms, the point here is that users provision *themselves*
via /signup + the emailed link. So seed.py stays deliberately small: it creates
one already-verified account so you have something to log into immediately, and
leaves the interesting path — signup → verify → login — for you to walk through
in the browser (or see driven end to end in test.py / client_example.py).

Run once:  python seed.py
"""

import db

# A pre-verified account, so you can log in without doing the email dance first.
VERIFIED_EMAIL = "alice@example.com"
VERIFIED_PASSWORD = "correct-horse-battery-staple"

SAMPLE_RESOURCES = [
    ("Alice's note", "Remember to rotate the signing key next month."),
    ("Alice's API key", "sk-alice-1234567890"),
]


def main():
    db.init_schema()

    if db.get_user_by_email(VERIFIED_EMAIL):
        print(f"  user already exists, skipping: {VERIFIED_EMAIL}")
    else:
        user_id = db.create_user(VERIFIED_EMAIL, VERIFIED_PASSWORD, email_verified=1)
        for title, body in SAMPLE_RESOURCES:
            db.add_resource(user_id, title, body)
        print(f"  created PRE-VERIFIED user: {VERIFIED_EMAIL} (id={user_id})")

    print("\nDone.")
    print(f"  Log in now with:  {VERIFIED_EMAIL} / {VERIFIED_PASSWORD}")
    print("  Or provision a NEW account at /signup and confirm via the link")
    print("  printed to the server log / written to outbox.log.")


if __name__ == "__main__":
    main()
