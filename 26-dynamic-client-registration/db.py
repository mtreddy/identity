"""
db.py — backend for OAuth2 with Dynamic Client Registration.

Extends 09's data layer. The big change is `oauth_clients`: instead of a single
row hand-written by seed.py, clients are created at runtime via /register, so
each row now also carries the material that registration produces —

  client_secret_hash   — SHA-256 of the secret (confidential clients only).
  reg_access_token_hash— SHA-256 of the per-client registration access token,
                         which authorizes read/update/delete of THIS client
                         (RFC 7592). Scoping management to one token per client
                         is what stops client A from editing client B.
  token_endpoint_auth_method, client_id_issued_at — reflected back per RFC 7591.

users / auth_codes / resources are unchanged from 09.
"""

import sqlite3
import time
from pathlib import Path

import bcrypt
import oauth
import registration

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

        CREATE TABLE IF NOT EXISTS oauth_clients (
            client_id                  TEXT PRIMARY KEY,
            name                       TEXT NOT NULL,
            redirect_uris              TEXT NOT NULL,   -- newline-separated allow-list
            allowed_scopes             TEXT NOT NULL DEFAULT '',
            is_public                  INTEGER NOT NULL DEFAULT 1,
            -- Dynamic Client Registration additions:
            client_secret_hash         TEXT,            -- confidential clients only
            reg_access_token_hash      TEXT,            -- authorizes RFC 7592 management
            token_endpoint_auth_method TEXT NOT NULL DEFAULT 'none',
            client_id_issued_at        INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS auth_codes (
            code_hash             TEXT PRIMARY KEY,
            client_id             TEXT    NOT NULL,
            user_id               INTEGER NOT NULL,
            redirect_uri          TEXT    NOT NULL,
            scope                 TEXT    NOT NULL,
            code_challenge        TEXT    NOT NULL,
            code_challenge_method TEXT    NOT NULL,
            expires_at            INTEGER NOT NULL,
            used                  INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS resources (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_user_id INTEGER NOT NULL,
            title         TEXT    NOT NULL,
            body          TEXT    NOT NULL,
            FOREIGN KEY (owner_user_id) REFERENCES users(id)
        );
        """
    )
    conn.commit()
    conn.close()


# --- users (resource owners) — unchanged from 09 ----------------------------

def create_user(email: str, plain_password: str) -> int:
    pw_hash = bcrypt.hashpw(plain_password.encode(), bcrypt.gensalt()).decode()
    conn = get_connection()
    cur = conn.execute(
        "INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, pw_hash)
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


# --- oauth clients (now created by registration, not seed) ------------------

def register_client(meta: dict) -> dict:
    """Create a client from validated metadata. Returns a dict that includes the
    RAW client_secret / registration_access_token — shown to the caller once and
    NEVER stored in the clear. Caller must not log the raw values."""
    client_id = registration.new_client_id()
    now = int(time.time())

    client_secret = None
    secret_hash = None
    if meta["token_endpoint_auth_method"] != "none":
        client_secret = registration.new_client_secret()
        secret_hash = registration.hash_secret(client_secret)

    rat = registration.new_registration_access_token()

    conn = get_connection()
    conn.execute(
        "INSERT INTO oauth_clients (client_id, name, redirect_uris, allowed_scopes, "
        "is_public, client_secret_hash, reg_access_token_hash, "
        "token_endpoint_auth_method, client_id_issued_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            client_id, meta["client_name"], "\n".join(meta["redirect_uris"]),
            meta["scope"], meta["is_public"], secret_hash,
            registration.hash_secret(rat), meta["token_endpoint_auth_method"], now,
        ),
    )
    conn.commit()
    conn.close()
    return {
        "client_id": client_id,
        "client_secret": client_secret,          # None for public clients
        "registration_access_token": rat,
        "client_id_issued_at": now,
    }


def update_client(client_id: str, meta: dict):
    conn = get_connection()
    conn.execute(
        "UPDATE oauth_clients SET name = ?, redirect_uris = ?, allowed_scopes = ?, "
        "is_public = ?, token_endpoint_auth_method = ? WHERE client_id = ?",
        (
            meta["client_name"], "\n".join(meta["redirect_uris"]), meta["scope"],
            meta["is_public"], meta["token_endpoint_auth_method"], client_id,
        ),
    )
    conn.commit()
    conn.close()


def delete_client(client_id: str):
    conn = get_connection()
    conn.execute("DELETE FROM oauth_clients WHERE client_id = ?", (client_id,))
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


def verify_registration_access_token(row, presented: str) -> bool:
    return registration.verify_secret(presented, row["reg_access_token_hash"])


def verify_client_secret(row, presented: str) -> bool:
    return registration.verify_secret(presented, row["client_secret_hash"])


# --- authorization codes — unchanged from 09 --------------------------------

def create_auth_code(
    code, client_id, user_id, redirect_uri, scope,
    code_challenge, code_challenge_method, ttl_seconds=60,
):
    conn = get_connection()
    conn.execute(
        "INSERT INTO auth_codes (code_hash, client_id, user_id, redirect_uri, "
        "scope, code_challenge, code_challenge_method, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            oauth.hash_code(code), client_id, user_id, redirect_uri, scope,
            code_challenge, code_challenge_method, int(time.time()) + ttl_seconds,
        ),
    )
    conn.commit()
    conn.close()


def consume_auth_code(code: str):
    code_hash = oauth.hash_code(code)
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM auth_codes WHERE code_hash = ?", (code_hash,)
        ).fetchone()
        if row is None:
            return None
        cur = conn.execute(
            "UPDATE auth_codes SET used = 1 WHERE code_hash = ? AND used = 0",
            (code_hash,),
        )
        conn.commit()
        if cur.rowcount != 1:
            return None
        if int(row["expires_at"]) <= int(time.time()):
            return None
        return row
    finally:
        conn.close()


# --- resources — unchanged from 09 ------------------------------------------

def add_resource(owner_user_id, title, body):
    conn = get_connection()
    conn.execute(
        "INSERT INTO resources (owner_user_id, title, body) VALUES (?, ?, ?)",
        (owner_user_id, title, body),
    )
    conn.commit()
    conn.close()


def get_resources_for_user(owner_user_id):
    conn = get_connection()
    rows = conn.execute(
        "SELECT title, body FROM resources WHERE owner_user_id = ? ORDER BY id",
        (owner_user_id,),
    ).fetchall()
    conn.close()
    return rows
