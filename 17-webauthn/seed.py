"""
seed.py — initialise the database.

There's nothing to pre-seed: a user row is created on first /register/begin, and
a passkey is stored on /register/finish. Run this once (or just start the
server, which also creates the schema).
"""

import db


def main():
    db.init_schema()
    print("Database ready.")
    print("\nStart the server:  python app.py")
    print("Open http://localhost:5000/ and register a passkey,")
    print("or run headless:  python client_example.py")


if __name__ == "__main__":
    main()
