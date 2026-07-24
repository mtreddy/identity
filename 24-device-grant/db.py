"""
db.py — backend for the Device Authorization Grant.

  users         — resource owners (bcrypt passwords), who approve on a browser.
  oauth_clients — the device apps (public clients: a TV, CLI, …).
  device_codes  — one row per device-login attempt: the hashed device_code, the
                  human user_code, status (pending/approved/denied/consumed),
                  the approving user, poll interval, and expiry.
  resources     — sample per-user data the device reads once approved.
"""

import sqlite3
import time
from pathlib import Path

import bcrypt
import device

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
            id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE,
            name TEXT, password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS oauth_clients (
            client_id TEXT PRIMARY KEY, name TEXT NOT NULL,
            allowed_scopes TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS device_codes (
            device_code_hash TEXT PRIMARY KEY,
            user_code   TEXT    NOT NULL UNIQUE,
            client_id   TEXT    NOT NULL,
            scope       TEXT    NOT NULL,
            status      TEXT    NOT NULL DEFAULT 'pending',
            user_id     INTEGER,
            interval    INTEGER NOT NULL DEFAULT 5,
            expires_at  INTEGER NOT NULL,
            last_polled REAL
        );
        CREATE TABLE IF NOT EXISTS resources (
            id INTEGER PRIMARY KEY AUTOINCREMENT, owner_user_id INTEGER NOT NULL,
            title TEXT NOT NULL, body TEXT NOT NULL
        );
        """
    )
    conn.commit()
    conn.close()


# --- users / clients / resources -------------------------------------------

def create_user(email, plain_password, name=None):
    pw = bcrypt.hashpw(plain_password.encode(), bcrypt.gensalt()).decode()
    conn = get_connection()
    cur = conn.execute("INSERT INTO users (email, name, password_hash) VALUES (?,?,?)",
                       (email, name, pw))
    conn.commit(); uid = cur.lastrowid; conn.close()
    return uid


def get_user_by_email(email):
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close(); return row


def get_user_by_id(uid):
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    conn.close(); return row


def verify_password(plain, stored):
    return bcrypt.checkpw(plain.encode(), stored.encode())


def create_client(client_id, name, allowed_scopes):
    conn = get_connection()
    conn.execute("INSERT OR REPLACE INTO oauth_clients (client_id, name, allowed_scopes) "
                 "VALUES (?,?,?)", (client_id, name, " ".join(allowed_scopes)))
    conn.commit(); conn.close()


def get_client(client_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM oauth_clients WHERE client_id = ?", (client_id,)).fetchone()
    conn.close(); return row


def add_resource(owner_user_id, title, body):
    conn = get_connection()
    conn.execute("INSERT INTO resources (owner_user_id, title, body) VALUES (?,?,?)",
                 (owner_user_id, title, body))
    conn.commit(); conn.close()


def get_resources_for_user(owner_user_id):
    conn = get_connection()
    rows = conn.execute("SELECT title, body FROM resources WHERE owner_user_id = ? ORDER BY id",
                        (owner_user_id,)).fetchall()
    conn.close(); return rows


# --- device codes -----------------------------------------------------------

def create_device_code(device_code, user_code, client_id, scope, interval, ttl):
    conn = get_connection()
    conn.execute(
        "INSERT INTO device_codes (device_code_hash, user_code, client_id, scope, "
        "interval, expires_at) VALUES (?,?,?,?,?,?)",
        (device.hash_code(device_code), user_code, client_id, scope, interval,
         int(time.time()) + ttl))
    conn.commit(); conn.close()


def get_by_device_code(device_code):
    conn = get_connection()
    row = conn.execute("SELECT * FROM device_codes WHERE device_code_hash = ?",
                       (device.hash_code(device_code),)).fetchone()
    conn.close(); return row


def get_by_user_code(user_code):
    conn = get_connection()
    row = conn.execute("SELECT * FROM device_codes WHERE user_code = ?", (user_code,)).fetchone()
    conn.close(); return row


def touch_poll(device_code_hash, when):
    conn = get_connection()
    conn.execute("UPDATE device_codes SET last_polled = ? WHERE device_code_hash = ?",
                 (when, device_code_hash))
    conn.commit(); conn.close()


def set_status(user_code, status, user_id=None):
    conn = get_connection()
    conn.execute("UPDATE device_codes SET status = ?, user_id = ? WHERE user_code = ?",
                 (status, user_id, user_code))
    conn.commit(); conn.close()


def consume(device_code_hash):
    conn = get_connection()
    conn.execute("UPDATE device_codes SET status = 'consumed' WHERE device_code_hash = ?",
                 (device_code_hash,))
    conn.commit(); conn.close()
