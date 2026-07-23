"""
db.py — users with a password (mechanism 01) plus an optional TOTP second factor.

The TOTP secret is the shared key an authenticator app holds. (In a
higher-assurance system it would be encrypted at rest; here it's stored
plainly to keep the demo focused on the TOTP mechanism.)
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
            totp_secret   TEXT,
            totp_enabled  INTEGER NOT NULL DEFAULT 0,
            created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
        );
        """
    )
    conn.commit()
    conn.close()


def create_user(email, plain_password, name=None):
    pw = bcrypt.hashpw(plain_password.encode(), bcrypt.gensalt()).decode()
    conn = get_connection()
    cur = conn.execute(
        "INSERT INTO users (email, name, password_hash) VALUES (?, ?, ?)",
        (email, name, pw))
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


def verify_password(plain_password, stored_hash):
    return bcrypt.checkpw(plain_password.encode(), stored_hash.encode())


def set_totp(uid, secret, enabled):
    conn = get_connection()
    conn.execute("UPDATE users SET totp_secret = ?, totp_enabled = ? WHERE id = ?",
                 (secret, 1 if enabled else 0, uid))
    conn.commit()
    conn.close()
