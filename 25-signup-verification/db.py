"""
db.py — data layer for self-service signup + email verification.

Builds on 05-defense-in-depth (server-side sessions, session_epoch) and adds
the two things a real user-provisioning path needs:

  users.email_verified   — a gate: an account exists but cannot sign in until
                           its email has been proven controllable. This stops
                           someone registering under an address they don't own
                           (and stops the account being *usable* if they do).

  email_verifications    — single-use, short-TTL verification tokens, stored
                           ONLY as a SHA-256 hash. The raw token travels in the
                           emailed link; a DB leak therefore can't be replayed
                           into a verified account. High-entropy token, so a
                           fast hash is the right choice (same reasoning as API
                           keys in 06 — slow hashing only helps human passwords).
"""

import base64
import hashlib
import sqlite3
import time
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
            -- The verification gate. 0 = signed up but unproven; 1 = usable.
            email_verified INTEGER NOT NULL DEFAULT 0,
            -- Feature 10 (carried from 05): bump to invalidate all sessions.
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

        CREATE TABLE IF NOT EXISTS email_verifications (
            token_hash TEXT    PRIMARY KEY,      -- SHA-256 of the emailed token
            user_id    INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,          -- unix seconds
            used       INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        """
    )
    conn.commit()
    conn.close()


# --- password helpers (identical to 05) -------------------------------------

def _prehash(plain_password: str) -> bytes:
    digest = hashlib.sha256(plain_password.encode("utf-8")).digest()
    return base64.b64encode(digest)


def hash_password(plain_password: str) -> str:
    return bcrypt.hashpw(_prehash(plain_password), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, stored_hash: str) -> bool:
    return bcrypt.checkpw(_prehash(plain_password), stored_hash.encode("utf-8"))


# --- users ------------------------------------------------------------------

def create_user(email: str, plain_password: str, email_verified: int = 0) -> int:
    conn = get_connection()
    cur = conn.execute(
        "INSERT INTO users (email, password_hash, email_verified) VALUES (?, ?, ?)",
        (email, hash_password(plain_password), email_verified),
    )
    conn.commit()
    user_id = cur.lastrowid
    conn.close()
    return user_id


def get_user_by_email(email: str):
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()
    return row


def get_user_by_id(user_id: int):
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return row


def mark_email_verified(user_id: int):
    conn = get_connection()
    conn.execute("UPDATE users SET email_verified = 1 WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()


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


# --- email verification tokens ----------------------------------------------

def create_verification(token: str, user_id: int, ttl_seconds: int):
    """Store only the HASH of the token. Invalidate any earlier outstanding
    tokens for this user first, so the newest link is the only live one."""
    import verify  # local import avoids a cycle at module load
    conn = get_connection()
    conn.execute(
        "UPDATE email_verifications SET used = 1 WHERE user_id = ? AND used = 0",
        (user_id,),
    )
    now = int(time.time())
    conn.execute(
        "INSERT INTO email_verifications "
        "(token_hash, user_id, expires_at, used, created_at) VALUES (?, ?, ?, 0, ?)",
        (verify.hash_token(token), user_id, now + ttl_seconds, now),
    )
    conn.commit()
    conn.close()


def consume_verification(token: str):
    """Atomically claim a verification token. Returns the user_id if the token
    was valid, unexpired and unused; None otherwise. The one-shot UPDATE makes
    a token redeemable at most once even under concurrent requests."""
    import verify
    token_hash = verify.hash_token(token)
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM email_verifications WHERE token_hash = ?", (token_hash,)
        ).fetchone()
        if row is None:
            return None
        cur = conn.execute(
            "UPDATE email_verifications SET used = 1 "
            "WHERE token_hash = ? AND used = 0",
            (token_hash,),
        )
        conn.commit()
        if cur.rowcount != 1:
            return None                       # already used (replay)
        if int(row["expires_at"]) <= int(time.time()):
            return None                       # expired
        return row["user_id"]
    finally:
        conn.close()


def count_recent_verifications(user_id: int, within_seconds: int) -> int:
    """How many tokens we've minted for this user recently — used to rate-limit
    'resend' so the endpoint can't be turned into a mail bomb."""
    conn = get_connection()
    n = conn.execute(
        "SELECT COUNT(*) FROM email_verifications WHERE user_id = ? AND created_at > ?",
        (user_id, int(time.time()) - within_seconds),
    ).fetchone()[0]
    conn.close()
    return n
