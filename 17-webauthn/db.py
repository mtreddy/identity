"""
db.py — users and their registered passkeys (WebAuthn credentials).

There are no passwords here: a passkey IS the credential. We store only public
data — for each credential, its ID, the COSE public key, and the last-seen
signature counter (for clone detection). A database leak reveals nothing that
lets an attacker log in.
"""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "identity.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_schema():
    conn = get_connection()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            email      TEXT    NOT NULL UNIQUE,
            name       TEXT,
            created_at TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS credentials (
            credential_id BLOB    PRIMARY KEY,   -- raw credential ID
            user_id       INTEGER NOT NULL,
            public_key    BLOB    NOT NULL,       -- COSE-encoded public key
            sign_count    INTEGER NOT NULL DEFAULT 0,
            created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        """
    )
    conn.commit()
    conn.close()


def create_user(email, name=None):
    conn = get_connection()
    cur = conn.execute("INSERT INTO users (email, name) VALUES (?, ?)", (email, name))
    conn.commit()
    uid = cur.lastrowid
    conn.close()
    return uid


def get_user_by_email(email):
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()
    return row


def get_user_by_id(uid):
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    conn.close()
    return row


def add_credential(credential_id, user_id, public_key, sign_count):
    conn = get_connection()
    conn.execute(
        "INSERT INTO credentials (credential_id, user_id, public_key, sign_count) "
        "VALUES (?, ?, ?, ?)",
        (credential_id, user_id, public_key, sign_count))
    conn.commit()
    conn.close()


def get_credentials_for_user(user_id):
    conn = get_connection()
    rows = conn.execute(
        "SELECT credential_id FROM credentials WHERE user_id = ?", (user_id,)).fetchall()
    conn.close()
    return [r["credential_id"] for r in rows]


def get_credential(credential_id):
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM credentials WHERE credential_id = ?", (credential_id,)).fetchone()
    conn.close()
    return row


def update_sign_count(credential_id, sign_count):
    conn = get_connection()
    conn.execute("UPDATE credentials SET sign_count = ? WHERE credential_id = ?",
                 (sign_count, credential_id))
    conn.commit()
    conn.close()
