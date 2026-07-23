"""
db.py — backend for the DPoP demo (reused from mechanism 07).

  clients   — machine/agent identities (with scopes).
  api_keys  — hashed, revocable keys used to authenticate at the token endpoint.
  resources — data owned by a client.

The DPoP key-binding lives in the token itself (cnf.jkt), not here; the DB only
covers who the client is and what they may do.
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
            scopes     TEXT    NOT NULL DEFAULT '',
            active     INTEGER NOT NULL DEFAULT 1,
            created_at TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS api_keys (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id      INTEGER NOT NULL,
            key_hash       TEXT    NOT NULL UNIQUE,
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


def create_client(name: str, scopes: list[str] | None = None) -> int:
    conn = get_connection()
    cur = conn.execute(
        "INSERT INTO clients (name, scopes) VALUES (?, ?)",
        (name, " ".join(scopes or [])),
    )
    conn.commit()
    cid = cur.lastrowid
    conn.close()
    return cid


def get_client_scopes(client_id: int) -> list[str]:
    conn = get_connection()
    row = conn.execute("SELECT scopes FROM clients WHERE id = ?", (client_id,)).fetchone()
    conn.close()
    return row["scopes"].split() if row and row["scopes"] else []


def create_api_key(client_id: int) -> str:
    full_key = keys.generate_api_key()
    conn = get_connection()
    conn.execute(
        "INSERT INTO api_keys (client_id, key_hash, display_prefix) VALUES (?, ?, ?)",
        (client_id, keys.hash_api_key(full_key), keys.display_prefix(full_key)),
    )
    conn.commit()
    conn.close()
    return full_key


def authenticate(full_key: str):
    """Resolve an API key to its client (for the token endpoint). Returns a row
    with client_id + name, or None."""
    conn = get_connection()
    row = conn.execute(
        """
        SELECT k.id AS key_id, c.id AS client_id, c.name AS name
        FROM api_keys k JOIN clients c ON c.id = k.client_id
        WHERE k.key_hash = ? AND k.revoked = 0 AND c.active = 1
        """,
        (keys.hash_api_key(full_key),),
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
