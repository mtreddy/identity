"""
db.py — data layer.

Adds a `session_epoch` column to users (Feature 10). It is a counter that is
bumped whenever we want to invalidate ALL of a user's existing sessions
(e.g. after a password change). Each logged-in session remembers the epoch it
was created under; if the stored epoch no longer matches the DB, the session
is stale and rejected — this is how "log out everywhere" works with
server-side sessions.
"""

import base64
import hashlib
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
            password_hash TEXT    NOT NULL,
            -- Feature 10: bump this to invalidate all of the user's sessions.
            session_epoch INTEGER NOT NULL DEFAULT 0,
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

def _prehash(plain_password: str) -> bytes:
    digest = hashlib.sha256(plain_password.encode("utf-8")).digest()
    return base64.b64encode(digest)


def hash_password(plain_password: str) -> str:
    return bcrypt.hashpw(_prehash(plain_password), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, stored_hash: str) -> bool:
    return bcrypt.checkpw(_prehash(plain_password), stored_hash.encode("utf-8"))


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


def get_user_by_id(user_id: int):
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    conn.close()
    return row


def update_password(user_id: int, new_password: str) -> int:
    """Change the password AND bump session_epoch so every existing session
    for this user becomes invalid. Returns the new epoch."""
    conn = get_connection()
    conn.execute(
        "UPDATE users SET password_hash = ?, session_epoch = session_epoch + 1 "
        "WHERE id = ?",
        (hash_password(new_password), user_id),
    )
    conn.commit()
    new_epoch = conn.execute(
        "SELECT session_epoch FROM users WHERE id = ?", (user_id,)
    ).fetchone()[0]
    conn.close()
    return new_epoch


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
