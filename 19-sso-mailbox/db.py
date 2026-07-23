"""
db.py — backend for the authorization-code + PKCE flow.

Four things live here:

  users        — resource owners (humans). Passwords are bcrypt-hashed, exactly
                 as in mechanism 01: OAuth delegates *access*, but the user
                 still authenticates with a password somewhere.
  oauth_clients— the registered apps that may request access. Each has an
                 allow-list of redirect URIs and scopes (this allow-list is a
                 primary security control).
  auth_codes   — short-lived, one-time authorization codes, stored hashed and
                 bound to (client, user, redirect_uri, scope, code_challenge).
  messages     — the user's MAILBOX: the protected resource a client reads once
                 the user has granted it the `mail:read` scope.
"""

import sqlite3
import time
from pathlib import Path

import bcrypt
import oauth

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

        CREATE TABLE IF NOT EXISTS oauth_clients (
            client_id      TEXT PRIMARY KEY,
            name           TEXT NOT NULL,
            -- Newline-separated allow-lists. Exact-match enforced at runtime.
            redirect_uris  TEXT NOT NULL,
            allowed_scopes TEXT NOT NULL DEFAULT '',
            -- Public clients (SPA/mobile/CLI) use PKCE and hold no secret.
            is_public      INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS auth_codes (
            code_hash             TEXT PRIMARY KEY,
            client_id             TEXT    NOT NULL,
            user_id               INTEGER NOT NULL,
            redirect_uri          TEXT    NOT NULL,
            scope                 TEXT    NOT NULL,
            nonce                 TEXT,               -- OIDC: echoed into id_token
            code_challenge        TEXT    NOT NULL,
            code_challenge_method TEXT    NOT NULL,
            expires_at            INTEGER NOT NULL,   -- unix seconds
            used                  INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS messages (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_user_id INTEGER NOT NULL,
            from_addr     TEXT    NOT NULL,
            subject       TEXT    NOT NULL,
            body          TEXT    NOT NULL,
            received_at   TEXT    NOT NULL,
            unread        INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY (owner_user_id) REFERENCES users(id)
        );
        """
    )
    conn.commit()
    conn.close()


# --- users (resource owners) ------------------------------------------------

def create_user(email: str, plain_password: str, name: str | None = None) -> int:
    pw_hash = bcrypt.hashpw(plain_password.encode(), bcrypt.gensalt()).decode()
    conn = get_connection()
    cur = conn.execute(
        "INSERT INTO users (email, name, password_hash) VALUES (?, ?, ?)",
        (email, name, pw_hash),
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


def get_user_by_id(user_id: int):
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return row


def verify_password(plain_password: str, stored_hash: str) -> bool:
    return bcrypt.checkpw(plain_password.encode(), stored_hash.encode())


# --- oauth clients ----------------------------------------------------------

def create_oauth_client(client_id, name, redirect_uris, allowed_scopes, is_public=1):
    conn = get_connection()
    conn.execute(
        "INSERT OR REPLACE INTO oauth_clients "
        "(client_id, name, redirect_uris, allowed_scopes, is_public) "
        "VALUES (?, ?, ?, ?, ?)",
        (client_id, name, "\n".join(redirect_uris), " ".join(allowed_scopes), is_public),
    )
    conn.commit()
    conn.close()


def get_oauth_client(client_id: str):
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM oauth_clients WHERE client_id = ?", (client_id,)
    ).fetchone()
    conn.close()
    return row


def client_redirect_uris(row) -> list[str]:
    return [u for u in row["redirect_uris"].split("\n") if u]


def client_allowed_scopes(row) -> list[str]:
    return row["allowed_scopes"].split()


# --- authorization codes ----------------------------------------------------

def create_auth_code(
    code, client_id, user_id, redirect_uri, scope,
    code_challenge, code_challenge_method, nonce=None, ttl_seconds=60,
):
    conn = get_connection()
    conn.execute(
        "INSERT INTO auth_codes (code_hash, client_id, user_id, redirect_uri, "
        "scope, nonce, code_challenge, code_challenge_method, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            oauth.hash_code(code), client_id, user_id, redirect_uri, scope, nonce,
            code_challenge, code_challenge_method, int(time.time()) + ttl_seconds,
        ),
    )
    conn.commit()
    conn.close()


def consume_auth_code(code: str):
    """Atomically fetch-and-mark-used a code. Returns the row if it was valid
    and unused; None otherwise. Marking used inside one UPDATE guarantees a
    code can be redeemed at most once even under concurrent requests."""
    code_hash = oauth.hash_code(code)
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM auth_codes WHERE code_hash = ?", (code_hash,)
        ).fetchone()
        if row is None:
            return None
        # One-shot claim: only succeeds if it was still unused.
        cur = conn.execute(
            "UPDATE auth_codes SET used = 1 WHERE code_hash = ? AND used = 0",
            (code_hash,),
        )
        conn.commit()
        if cur.rowcount != 1:
            return None  # already used (possible replay / interception)
        if int(row["expires_at"]) <= int(time.time()):
            return None
        return row
    finally:
        conn.close()


# --- mailbox ----------------------------------------------------------------

def add_message(owner_user_id, from_addr, subject, body, received_at, unread=1):
    conn = get_connection()
    conn.execute(
        "INSERT INTO messages (owner_user_id, from_addr, subject, body, "
        "received_at, unread) VALUES (?, ?, ?, ?, ?, ?)",
        (owner_user_id, from_addr, subject, body, received_at, unread),
    )
    conn.commit()
    conn.close()


def get_messages_for_user(owner_user_id):
    conn = get_connection()
    rows = conn.execute(
        "SELECT from_addr, subject, body, received_at, unread FROM messages "
        "WHERE owner_user_id = ? ORDER BY received_at DESC, id DESC",
        (owner_user_id,),
    ).fetchall()
    conn.close()
    return rows
