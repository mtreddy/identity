"""
db.py — the backend / data layer.

Everything about *how identities and their secrets are stored* lives here.
We use SQLite: a full SQL database that is just a single file on disk
(identity.db). No server to install or run — perfect for a self-contained,
testable example.

Key security idea for this first mechanism (login + password):
  We NEVER store the password itself. We store a bcrypt *hash* of it.
  bcrypt is a deliberately-slow, salted hashing function. Given the hash,
  an attacker cannot cheaply recover the password, and because each hash
  has its own random salt, two users with the same password get different
  hashes.
"""

import sqlite3
from pathlib import Path

import bcrypt

# The database is a single file sitting next to this script.
DB_PATH = Path(__file__).parent / "identity.db"


def get_connection():
    """Open a connection to the SQLite file.

    row_factory = sqlite3.Row lets us access columns by name (row["email"])
    instead of by numeric index, which keeps the code readable.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_schema():
    """Create the tables if they don't exist yet.

    - users:     the identities (who can log in) and their password hashes.
    - resources: sample protected data, owned by a user, that you can only
                 see once you've authenticated. This is what login *protects*.
    """
    conn = get_connection()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            email         TEXT    NOT NULL UNIQUE,
            -- We store the bcrypt hash, never the raw password.
            password_hash TEXT    NOT NULL,
            created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS resources (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            title    TEXT    NOT NULL,
            body     TEXT    NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        );
        """
    )
    conn.commit()
    conn.close()


# --- password helpers -------------------------------------------------------
# These two functions are the heart of the "password" mechanism.

def hash_password(plain_password: str) -> str:
    """Turn a plaintext password into a salted bcrypt hash for storage."""
    # bcrypt works on bytes. gensalt() creates a fresh random salt each time.
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(plain_password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, stored_hash: str) -> bool:
    """Check a login attempt against the stored hash.

    bcrypt.checkpw re-derives the hash using the salt embedded in stored_hash
    and compares in constant time (resistant to timing attacks).
    """
    return bcrypt.checkpw(
        plain_password.encode("utf-8"), stored_hash.encode("utf-8")
    )


# --- data access ------------------------------------------------------------

def create_user(email: str, plain_password: str) -> int:
    conn = get_connection()
    cur = conn.execute(
        "INSERT INTO users (email, password_hash) VALUES (?, ?)",
        (email, hash_password(plain_password)),
    )
    conn.commit()
    user_id = cur.lastrowid
    conn.close()
    return user_id


def get_user_by_email(email: str):
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM users WHERE email = ?", (email,)
    ).fetchone()
    conn.close()
    return row


def add_resource(owner_id: int, title: str, body: str):
    conn = get_connection()
    conn.execute(
        "INSERT INTO resources (owner_id, title, body) VALUES (?, ?, ?)",
        (owner_id, title, body),
    )
    conn.commit()
    conn.close()


def get_resources_for_user(owner_id: int):
    conn = get_connection()
    rows = conn.execute(
        "SELECT title, body FROM resources WHERE owner_id = ? ORDER BY id",
        (owner_id,),
    ).fetchall()
    conn.close()
    return rows
