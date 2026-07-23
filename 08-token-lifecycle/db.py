"""
db.py — the backend / data layer for the token lifecycle.

Identities here are *machines/agents*, not people, so the model is:

  clients        — the machine/agent identities that may call the API.
  api_keys       — long-lived root credentials (hashed, revocable).
  resources      — sample data owned by a client.
  refresh_tokens — long-lived, opaque, hashed, REVOCABLE handles that a client
                   exchanges for fresh short-lived access tokens. Rotated on
                   every use (with reuse detection).
  revoked_jti    — deny-list of access-token ids (`jti`) revoked before they
                   naturally expire. Checked on every request.

The api_key/refresh_token are the durable, revocable credentials; the access
JWT is the disposable one. The refresh + jti machinery here is what gives back
the revocation that a bare stateless JWT (mechanism 07) lacked.
"""

import sqlite3
import time
from pathlib import Path

import keys

DB_PATH = Path(__file__).parent / "identity.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_schema():
    conn = get_connection()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS clients (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT    NOT NULL UNIQUE,
            -- Space-delimited scopes granted to this client (least privilege).
            -- These become the JWT's `scope` claim at token-issue time.
            scopes     TEXT    NOT NULL DEFAULT '',
            active     INTEGER NOT NULL DEFAULT 1,
            created_at TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS api_keys (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id      INTEGER NOT NULL,
            -- SHA-256 hash of the full key; unique so we can look up by it.
            key_hash       TEXT    NOT NULL UNIQUE,
            -- Non-secret label for humans (e.g. 'sk_live_Xw9a…').
            display_prefix TEXT    NOT NULL,
            revoked        INTEGER NOT NULL DEFAULT 0,
            created_at     TEXT    NOT NULL DEFAULT (datetime('now')),
            last_used_at   TEXT,
            FOREIGN KEY (client_id) REFERENCES clients(id)
        );

        CREATE TABLE IF NOT EXISTS resources (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_client_id INTEGER NOT NULL,
            title           TEXT    NOT NULL,
            body            TEXT    NOT NULL,
            FOREIGN KEY (owner_client_id) REFERENCES clients(id)
        );

        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id    INTEGER NOT NULL,
            token_hash   TEXT    NOT NULL UNIQUE,   -- SHA-256 of the full token
            scopes       TEXT    NOT NULL DEFAULT '',
            revoked      INTEGER NOT NULL DEFAULT 0,
            rotated_from INTEGER,                   -- id of the token replaced
            created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
            expires_at   INTEGER NOT NULL,          -- unix seconds
            FOREIGN KEY (client_id) REFERENCES clients(id)
        );

        -- Deny-list of access-token ids revoked before their natural expiry.
        CREATE TABLE IF NOT EXISTS revoked_jti (
            jti        TEXT    PRIMARY KEY,
            expires_at INTEGER NOT NULL,            -- unix seconds; prune after
            revoked_at TEXT    NOT NULL DEFAULT (datetime('now'))
        );
        """
    )
    conn.commit()
    conn.close()


# --- clients & keys ---------------------------------------------------------

def create_client(name: str, scopes: list[str] | None = None) -> int:
    conn = get_connection()
    cur = conn.execute(
        "INSERT INTO clients (name, scopes) VALUES (?, ?)",
        (name, " ".join(scopes or [])),
    )
    conn.commit()
    client_id = cur.lastrowid
    conn.close()
    return client_id


def get_client_scopes(client_id: int) -> list[str]:
    conn = get_connection()
    row = conn.execute(
        "SELECT scopes FROM clients WHERE id = ?", (client_id,)
    ).fetchone()
    conn.close()
    return row["scopes"].split() if row and row["scopes"] else []


def get_client(client_id: int):
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM clients WHERE id = ? AND active = 1", (client_id,)
    ).fetchone()
    conn.close()
    return row


def create_api_key(client_id: int) -> str:
    """Mint a new key for a client and return the FULL key. This is the only
    moment the plaintext key exists — the caller must show/save it now; we keep
    only its hash."""
    full_key = keys.generate_api_key()
    conn = get_connection()
    conn.execute(
        "INSERT INTO api_keys (client_id, key_hash, display_prefix) "
        "VALUES (?, ?, ?)",
        (client_id, keys.hash_api_key(full_key), keys.display_prefix(full_key)),
    )
    conn.commit()
    conn.close()
    return full_key


def authenticate(full_key: str):
    """Resolve a presented key to its client. Returns a row with client_id,
    name and key_id, or None. Also stamps last_used_at for the key so unused
    or suspicious keys are visible."""
    key_hash = keys.hash_api_key(full_key)
    conn = get_connection()
    row = conn.execute(
        """
        SELECT k.id AS key_id, c.id AS client_id, c.name AS name
        FROM api_keys k
        JOIN clients c ON c.id = k.client_id
        WHERE k.key_hash = ? AND k.revoked = 0 AND c.active = 1
        """,
        (key_hash,),
    ).fetchone()
    if row is not None:
        conn.execute(
            "UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?",
            (row["key_id"],),
        )
        conn.commit()
    conn.close()
    return row


def revoke_api_key(key_id: int):
    conn = get_connection()
    conn.execute("UPDATE api_keys SET revoked = 1 WHERE id = ?", (key_id,))
    conn.commit()
    conn.close()


# --- refresh tokens ---------------------------------------------------------

def create_refresh_token(
    client_id: int, scopes: list[str], ttl_seconds: int, rotated_from=None
) -> tuple[str, int]:
    """Mint a new refresh token. Returns (full_token, row_id). Only the hash is
    stored — the caller must return the full token to the client now."""
    full = keys.generate_refresh_token()
    expires_at = int(time.time()) + int(ttl_seconds)
    conn = get_connection()
    cur = conn.execute(
        "INSERT INTO refresh_tokens (client_id, token_hash, scopes, rotated_from, "
        "expires_at) VALUES (?, ?, ?, ?, ?)",
        (client_id, keys.hash_token(full), " ".join(scopes), rotated_from, expires_at),
    )
    conn.commit()
    row_id = cur.lastrowid
    conn.close()
    return full, row_id


def get_refresh_record(full_token: str):
    """Look up a refresh token by hash. Returns the row (including revoked /
    expires_at) or None — the caller decides validity so it can distinguish
    'unknown', 'revoked' (reuse!) and 'expired'."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM refresh_tokens WHERE token_hash = ?",
        (keys.hash_token(full_token),),
    ).fetchone()
    conn.close()
    return row


def refresh_is_expired(row) -> bool:
    return int(row["expires_at"]) <= int(time.time())


def revoke_refresh_token_id(row_id: int):
    conn = get_connection()
    conn.execute("UPDATE refresh_tokens SET revoked = 1 WHERE id = ?", (row_id,))
    conn.commit()
    conn.close()


def revoke_all_refresh_for_client(client_id: int) -> int:
    """Revoke every refresh token for a client. Used as the response to refresh
    token REUSE, which signals the token was stolen."""
    conn = get_connection()
    cur = conn.execute(
        "UPDATE refresh_tokens SET revoked = 1 WHERE client_id = ? AND revoked = 0",
        (client_id,),
    )
    conn.commit()
    count = cur.rowcount
    conn.close()
    return count


# --- access-token (jti) revocation ------------------------------------------

def revoke_jti(jti: str, expires_at: int):
    """Add an access token's id to the deny-list until it would have expired."""
    conn = get_connection()
    conn.execute(
        "INSERT OR IGNORE INTO revoked_jti (jti, expires_at) VALUES (?, ?)",
        (jti, int(expires_at)),
    )
    conn.commit()
    conn.close()


def is_jti_revoked(jti: str) -> bool:
    conn = get_connection()
    row = conn.execute(
        "SELECT 1 FROM revoked_jti WHERE jti = ?", (jti,)
    ).fetchone()
    conn.close()
    return row is not None


# --- resources --------------------------------------------------------------

def add_resource(owner_client_id: int, title: str, body: str):
    conn = get_connection()
    conn.execute(
        "INSERT INTO resources (owner_client_id, title, body) VALUES (?, ?, ?)",
        (owner_client_id, title, body),
    )
    conn.commit()
    conn.close()


def get_resources_for_client(owner_client_id: int):
    conn = get_connection()
    rows = conn.execute(
        "SELECT title, body FROM resources WHERE owner_client_id = ? ORDER BY id",
        (owner_client_id,),
    ).fetchall()
    conn.close()
    return rows
