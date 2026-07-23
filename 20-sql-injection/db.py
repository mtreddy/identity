"""
db.py — VULNERABLE vs SAFE SQL, side by side.

This mechanism is a teaching demo of SQL-injection defense. It deliberately
contains vulnerable query builders (clearly marked "DANGER") next to the correct
parameterized versions, so the difference — and the exploits the vulnerable ones
enable — is visible. Everything runs against a local SQLite file; the vulnerable
functions exist only to be attacked inside this sandbox, never in real code.

The one rule that prevents almost all SQL injection:

    Never build SQL by concatenating/formatting untrusted input into the query
    string. Pass values as bound PARAMETERS (`?`) so the driver keeps them as
    DATA, never as SQL.

Identifiers (table/column names, ORDER BY) can't be bound as parameters — for
those, validate against an ALLOW-LIST (see list_sorted_safe).
"""

import sqlite3
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
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS products;

        CREATE TABLE users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT NOT NULL UNIQUE,
            -- NOTE: storing/comparing plaintext passwords in SQL is itself a
            -- legacy anti-pattern (real apps hash — see mechanism 01/bcrypt).
            -- It's used here only to make the classic auth-bypass injection
            -- legible.
            password    TEXT NOT NULL,
            secret_note TEXT,
            is_admin    INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE products (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            name     TEXT NOT NULL,
            category TEXT NOT NULL,
            price    REAL NOT NULL
        );
        """
    )
    conn.commit()
    conn.close()


def seed():
    conn = get_connection()
    conn.executemany(
        "INSERT INTO users (username, password, secret_note, is_admin) VALUES (?,?,?,?)",
        [
            ("admin", "s3cr3t-admin-pw", "root recovery code: RC-9931-ADMIN", 1),
            ("alice", "alice-pw", "alice's private note", 0),
            ("bob", "bob-pw", "bob's private note", 0),
        ],
    )
    conn.executemany(
        "INSERT INTO products (name, category, price) VALUES (?,?,?)",
        [
            ("Widget", "hardware", 9.99),
            ("Gadget", "hardware", 19.99),
            ("Manual", "books", 4.99),
        ],
    )
    conn.commit()
    conn.close()


# ===========================================================================
# VULNERABLE — string-built SQL. NEVER do this. (Here only to be exploited.)
# ===========================================================================

def login_vulnerable(username: str, password: str):
    # DANGER: untrusted input formatted straight into the query.
    sql = ("SELECT id, username, is_admin FROM users "
           f"WHERE username = '{username}' AND password = '{password}'")
    conn = get_connection()
    try:
        rows = conn.execute(sql).fetchall()
    finally:
        conn.close()
    return rows, sql


def search_vulnerable(category: str):
    # DANGER: enables UNION-based data exfiltration.
    sql = f"SELECT name, category FROM products WHERE category = '{category}'"
    conn = get_connection()
    try:
        rows = conn.execute(sql).fetchall()
    finally:
        conn.close()
    return rows, sql


def list_sorted_vulnerable(sort: str):
    # DANGER: identifiers concatenated in — injectable ORDER BY expression.
    sql = f"SELECT name, price FROM products ORDER BY {sort}"
    conn = get_connection()
    try:
        rows = conn.execute(sql).fetchall()
    finally:
        conn.close()
    return rows, sql


# ===========================================================================
# SAFE — parameterized values + allow-listed identifiers.
# ===========================================================================

def login_safe(username: str, password: str):
    sql = "SELECT id, username, is_admin FROM users WHERE username = ? AND password = ?"
    conn = get_connection()
    try:
        rows = conn.execute(sql, (username, password)).fetchall()  # values are DATA
    finally:
        conn.close()
    return rows, sql + f"   -- params: {(username, password)}"


def search_safe(category: str):
    sql = "SELECT name, category FROM products WHERE category = ?"
    conn = get_connection()
    try:
        rows = conn.execute(sql, (category,)).fetchall()
    finally:
        conn.close()
    return rows, sql + f"   -- params: {(category,)}"


# Identifiers can't be bound with `?`, so they MUST come from an allow-list.
ALLOWED_SORT_COLUMNS = {"name", "price"}


def list_sorted_safe(sort: str):
    if sort not in ALLOWED_SORT_COLUMNS:
        raise ValueError(f"invalid sort column: {sort!r}")
    # `sort` is now guaranteed to be one of a fixed, safe set of identifiers.
    sql = f"SELECT name, price FROM products ORDER BY {sort}"
    conn = get_connection()
    try:
        rows = conn.execute(sql).fetchall()
    finally:
        conn.close()
    return rows, sql
