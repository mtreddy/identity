"""
db.py — backend for mTLS auth.

The TLS handshake already proves the client holds a private key for a cert our
CA signed. The database then decides WHO that is and WHETHER it's still allowed:

  clients      — the machine/agent identities (name == certificate CN).
  client_certs — the exact issued client certificates, by SHA-256 fingerprint,
                 with a `revoked` flag. This is our lightweight revocation:
                 flip `revoked` and that specific cert stops working
                 immediately — no CRL/OCSP infrastructure needed for the demo.
  resources    — data owned by a client.

Two layers of trust: CA-signed (handshake) + registered-and-not-revoked
fingerprint (here). A stolen-but-revoked cert, or any cert we didn't issue for
this client, is rejected even though it chains to the CA.
"""

import sqlite3
from pathlib import Path

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
            scopes     TEXT    NOT NULL DEFAULT '',   -- granted at token issue
            active     INTEGER NOT NULL DEFAULT 1,
            created_at TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS client_certs (
            fingerprint TEXT    PRIMARY KEY,   -- SHA-256 of the cert DER
            client_id   INTEGER NOT NULL,
            subject_cn  TEXT    NOT NULL,
            revoked     INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
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


def get_client_by_name(name: str):
    conn = get_connection()
    row = conn.execute("SELECT * FROM clients WHERE name = ?", (name,)).fetchone()
    conn.close()
    return row


def get_client_scopes(client_id: int) -> list[str]:
    conn = get_connection()
    row = conn.execute("SELECT scopes FROM clients WHERE id = ?", (client_id,)).fetchone()
    conn.close()
    return row["scopes"].split() if row and row["scopes"] else []


def register_cert(fingerprint: str, client_id: int, subject_cn: str):
    conn = get_connection()
    conn.execute(
        "INSERT OR REPLACE INTO client_certs (fingerprint, client_id, subject_cn) "
        "VALUES (?, ?, ?)",
        (fingerprint, client_id, subject_cn),
    )
    conn.commit()
    conn.close()


def authenticate(fingerprint: str, presented_cn: str):
    """Resolve a verified client cert to its client. Returns a row with
    client_id + name, or None if the cert is unknown, revoked, its client is
    inactive, or the CN doesn't match what we registered."""
    conn = get_connection()
    row = conn.execute(
        """
        SELECT c.id AS client_id, c.name AS name, cc.subject_cn, cc.revoked, c.active
        FROM client_certs cc
        JOIN clients c ON c.id = cc.client_id
        WHERE cc.fingerprint = ?
        """,
        (fingerprint,),
    ).fetchone()
    conn.close()
    if row is None or row["revoked"] or not row["active"]:
        return None
    if row["subject_cn"] != presented_cn:
        return None
    return row


def revoke_cert(fingerprint: str):
    conn = get_connection()
    conn.execute(
        "UPDATE client_certs SET revoked = 1 WHERE fingerprint = ?", (fingerprint,)
    )
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
