"""
db.py — data layer.

Same schema and queries as before, but the password hashing now defends
against bcrypt's 72-byte input limit (Feature 8).

  bcrypt only considers the first 72 bytes of its input and silently ignores
  the rest. Two different long passwords that share a 72-byte prefix would
  therefore produce the SAME hash and both validate. We fix this by first
  running the password through SHA-256 and base64-encoding the digest, giving
  a fixed 44-byte value that (a) is always within bcrypt's limit and (b)
  depends on the ENTIRE password. bcrypt is then applied to that value.
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
    """Feature 8: collapse any-length password into a fixed 44-byte value
    (base64 of its SHA-256 digest) so bcrypt's 72-byte truncation can't cause
    two distinct passwords to collide."""
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
