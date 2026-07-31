"""
db.py — SQLite data layer for the AS + gateway.

Tables:
  * clients   — registered agents: how each authenticates (client_secret vs.
                private_key_jwt), its allowed scopes, and the models it may call.
                Secrets are stored only as a SHA-256 hash; public keys (for
                private_key_jwt) are stored as PEM.
  * seen_jti  — replay cache for private_key_jwt assertions.

Everything is parameterized (mechanism 20). High-entropy secrets use SHA-256,
not bcrypt — a fast hash is correct for random secrets (mechanism 06).
"""

import hashlib
import secrets
import sqlite3
import time
from pathlib import Path

DB_PATH = Path(__file__).parent / "app.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_schema():
    conn = get_connection()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS clients (
            client_id          TEXT PRIMARY KEY,
            name               TEXT NOT NULL,
            auth_method        TEXT NOT NULL,      -- client_secret_basic | private_key_jwt
            client_secret_hash TEXT,               -- secret clients only
            public_key_pem     TEXT,               -- private_key_jwt clients only
            allowed_scopes     TEXT NOT NULL DEFAULT '',
            allowed_models     TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS seen_jti (
            jti TEXT PRIMARY KEY,
            exp INTEGER NOT NULL
        );
        """
    )
    conn.commit()
    conn.close()


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


# --- clients ----------------------------------------------------------------

def create_secret_client(client_id, name, allowed_scopes, allowed_models) -> str:
    """Create a client_secret_basic client; return the RAW secret (shown once)."""
    secret = "cs_" + secrets.token_urlsafe(24)
    conn = get_connection()
    conn.execute(
        "INSERT INTO clients (client_id, name, auth_method, client_secret_hash,"
        " allowed_scopes, allowed_models) VALUES (?,?,?,?,?,?)",
        (client_id, name, "client_secret_basic", _sha256(secret),
         allowed_scopes, allowed_models),
    )
    conn.commit()
    conn.close()
    return secret


def create_pk_client(client_id, name, public_key_pem, allowed_scopes, allowed_models):
    conn = get_connection()
    conn.execute(
        "INSERT INTO clients (client_id, name, auth_method, public_key_pem,"
        " allowed_scopes, allowed_models) VALUES (?,?,?,?,?,?)",
        (client_id, name, "private_key_jwt", public_key_pem,
         allowed_scopes, allowed_models),
    )
    conn.commit()
    conn.close()


def get_client(client_id: str):
    conn = get_connection()
    try:
        return conn.execute("SELECT * FROM clients WHERE client_id = ?",
                            (client_id,)).fetchone()
    finally:
        conn.close()


def verify_client_secret(row, presented: str) -> bool:
    if not row["client_secret_hash"]:
        return False
    return secrets.compare_digest(row["client_secret_hash"], _sha256(presented))


def allowed_models(row) -> set:
    return set(row["allowed_models"].split()) if row else set()


# --- assertion replay cache -------------------------------------------------

def remember_jti(jti: str, exp: int) -> bool:
    """Record a client_assertion jti; return False if already seen (a replay).
    Opportunistically evicts expired entries so the table doesn't grow."""
    conn = get_connection()
    try:
        conn.execute("DELETE FROM seen_jti WHERE exp < ?", (int(time.time()),))
        try:
            conn.execute("INSERT INTO seen_jti (jti, exp) VALUES (?,?)", (jti, exp))
        except sqlite3.IntegrityError:
            return False
        conn.commit()
        return True
    finally:
        conn.close()
