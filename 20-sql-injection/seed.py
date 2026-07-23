"""
seed.py — (re)create and populate the demo database.

The server also seeds on startup; run this to reset between experiments.
"""

import db


def main():
    db.init_schema()
    db.seed()
    print("Database reset with 3 users (admin/alice/bob) and 3 products.")
    print("Start the server:  python app.py")
    print("Run the attacks:   python client_example.py")


if __name__ == "__main__":
    main()
