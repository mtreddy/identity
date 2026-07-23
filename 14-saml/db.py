"""
db.py — users (resource owners) for the IdP, with bcrypt passwords.

SAML federates *access* between an IdP and SPs, but the user still authenticates
somewhere — here, at the IdP with a password (mechanism 01). The IdP then
asserts the user's identity + attributes to the SP.
"""

import sqlite3
from pathlib import Path

import bcrypt

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
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            email         TEXT    NOT NULL UNIQUE,
            name          TEXT,
            password_hash TEXT    NOT NULL,
            created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
        );
        """
    )
    conn.commit()
    conn.close()


def create_user(email: str, plain_password: str, name: str | None = None) -> int:
    pw = bcrypt.hashpw(plain_password.encode(), bcrypt.gensalt()).decode()
    conn = get_connection()
    cur = conn.execute(
        "INSERT INTO users (email, name, password_hash) VALUES (?, ?, ?)",
        (email, name, pw),
    )
    conn.commit()
    uid = cur.lastrowid
    conn.close()
    return uid


def get_user_by_email(email: str):
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()
    return row


def verify_password(plain_password: str, stored_hash: str) -> bool:
    return bcrypt.checkpw(plain_password.encode(), stored_hash.encode())
