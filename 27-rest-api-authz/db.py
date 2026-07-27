"""
db.py — SQLite data layer for the REST authorization demo.

Three tables: `users` (accounts, with a couple of deliberately sensitive
columns — `password_hash`, `recovery_code`, `is_admin` — so the
excessive-data-exposure demo has something to leak), `notes` (per-user objects,
the target of the BOLA demo), and `tokens` (opaque bearer tokens issued at
login, stored only as a SHA-256 hash — high-entropy secrets don't need bcrypt).

Every query here is parameterized (see mechanism 20 for why). Note in
particular `update_user`: the *column names* it will write come from a fixed
allow-list (`UPDATABLE_COLUMNS`), never from caller-supplied keys, so the
mass-assignment demo can't turn into a SQL-injection demo. The mass-assignment
bug lives one layer up, in app.py, where the vulnerable handler forwards the
whole request body into this function.
"""

import hashlib
import secrets
import sqlite3
from pathlib import Path

import bcrypt

DB_PATH = Path(__file__).parent / "app.db"

# Real columns a profile update is *ever* allowed to touch. This is a
# SQL-safety allow-list (identifiers can't be bound as `?` parameters), NOT the
# authorization allow-list — that one (`WRITABLE_PROFILE_FIELDS`, in authz.py)
# is narrower and is what the /safe handler enforces. `is_admin` is here so the
# /vuln handler's mass-assignment bug is expressible.
UPDATABLE_COLUMNS = {"full_name", "email", "is_admin", "recovery_code"}


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
            username      TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,         -- bcrypt; must never be returned
            full_name     TEXT NOT NULL,
            email         TEXT NOT NULL,
            recovery_code TEXT NOT NULL,          -- sensitive; must never be returned
            is_admin      INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS notes (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            title    TEXT NOT NULL,
            body     TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS tokens (
            token_hash TEXT PRIMARY KEY,
            user_id    INTEGER NOT NULL
        );
        """
    )
    conn.commit()
    conn.close()


def _hash_pw(plaintext: str) -> str:
    return bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt()).decode()


def seed():
    """Insert demo users + notes if the DB is empty (idempotent)."""
    conn = get_connection()
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
        conn.close()
        return
    conn.executemany(
        "INSERT INTO users (username, password_hash, full_name, email, recovery_code, is_admin)"
        " VALUES (?,?,?,?,?,?)",
        [
            ("alice@example.com", _hash_pw("correct-horse-battery-staple"),
             "Alice Anders", "alice@example.com", "RC-ALICE-7f3a", 0),
            ("bob@example.com", _hash_pw("hunter2"),
             "Bob Barker", "bob@example.com", "RC-BOB-91c2", 0),
            ("admin@example.com", _hash_pw("admin-pw-do-not-ship"),
             "Ada Admin", "admin@example.com", "RC-ADMIN-0000", 1),
        ],
    )
    conn.executemany(
        "INSERT INTO notes (owner_id, title, body) VALUES (?,?,?)",
        [
            (1, "Alice's diary", "alice's private thoughts"),
            (2, "Bob's passwords", "bob's private secrets"),
        ],
    )
    conn.commit()
    conn.close()


def reset():
    """Drop everything and re-seed — used by seed.py for a clean demo."""
    conn = get_connection()
    conn.executescript("DROP TABLE IF EXISTS users;"
                       "DROP TABLE IF EXISTS notes;"
                       "DROP TABLE IF EXISTS tokens;")
    conn.commit()
    conn.close()
    init_schema()
    seed()


# --- users ------------------------------------------------------------------

def get_user_by_username(username: str):
    conn = get_connection()
    try:
        return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    finally:
        conn.close()


def get_user_by_id(user_id: int):
    conn = get_connection()
    try:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    finally:
        conn.close()


def get_all_users():
    conn = get_connection()
    try:
        return conn.execute("SELECT * FROM users ORDER BY id").fetchall()
    finally:
        conn.close()


def update_user(user_id: int, fields: dict):
    """Apply a profile update. Column names are taken ONLY from the fixed
    UPDATABLE_COLUMNS allow-list (so this stays injection-safe regardless of
    what keys the caller sent); values are bound parameters. Whether a given
    field *should* be writable by the caller is an authorization question the
    handler decides before calling us — that's the mass-assignment lesson."""
    cols = [(k, fields[k]) for k in fields if k in UPDATABLE_COLUMNS]
    if not cols:
        return
    set_clause = ", ".join(f"{k} = ?" for k, _ in cols)     # k ∈ fixed allow-list
    params = [int(v) if k == "is_admin" else v for k, v in cols] + [user_id]
    conn = get_connection()
    try:
        conn.execute(f"UPDATE users SET {set_clause} WHERE id = ?", params)
        conn.commit()
    finally:
        conn.close()


# --- notes ------------------------------------------------------------------

def get_note(note_id: int):
    conn = get_connection()
    try:
        return conn.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    finally:
        conn.close()


# --- tokens -----------------------------------------------------------------

def _token_hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def create_token(user_id: int) -> str:
    """Mint an opaque bearer token, store only its hash, return the raw token."""
    raw = "tok_" + secrets.token_urlsafe(32)     # 256 bits of entropy
    conn = get_connection()
    try:
        conn.execute("INSERT INTO tokens (token_hash, user_id) VALUES (?,?)",
                     (_token_hash(raw), user_id))
        conn.commit()
    finally:
        conn.close()
    return raw


def user_for_token(raw: str):
    conn = get_connection()
    try:
        return conn.execute(
            "SELECT u.* FROM users u JOIN tokens t ON t.user_id = u.id"
            " WHERE t.token_hash = ?", (_token_hash(raw),)).fetchone()
    finally:
        conn.close()
