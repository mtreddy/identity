"""
seed.py — reset the demo database to a known state (users + notes).

Unlike most mechanisms, there are no secrets to print once: bearer tokens are
minted at POST /login, not seeded. This just gives you three accounts and two
notes to attack. app.py also seeds itself on startup, so running this by hand
is only needed to reset between experiments.
"""

import db


def main():
    db.reset()
    print("Seeded app.db. Accounts (password):")
    print("  alice@example.com  correct-horse-battery-staple   (regular)")
    print("  bob@example.com    hunter2                        (regular)")
    print("  admin@example.com  admin-pw-do-not-ship           (admin)")
    print("\nNotes: id 1 owned by alice, id 2 owned by bob.")
    print("\nLog in to get a token:")
    print("  curl -sX POST http://127.0.0.1:5000/login \\")
    print("    -H 'Content-Type: application/json' \\")
    print("    -d '{\"username\":\"alice@example.com\",\"password\":\"correct-horse-battery-staple\"}'")


if __name__ == "__main__":
    main()
