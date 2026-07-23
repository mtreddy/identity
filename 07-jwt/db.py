"""
db.py — the backend / data layer for API-key auth.

Identities here are *machines/agents*, not people, so the model is:

  clients   — the machine/agent identities that may call the API.
  api_keys  — one or more keys per client (supports rotation & revocation);
              we store only the SHA-256 hash of each key.
  resources — sample data owned by a client and returned only to that client.

Storing multiple keys per client is deliberate: to rotate a key you issue a
new one, move the caller over, then revoke the old one — with no downtime.
"""

import sqlite3
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
