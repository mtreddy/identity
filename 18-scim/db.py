"""
db.py — storage for SCIM Users, Groups, memberships, and the provisioning
bearer tokens the IdP uses to authenticate.
"""

import hashlib
import sqlite3
import uuid
from pathlib import Path

import scim

DB_PATH = Path(__file__).parent / "identity.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_schema():
    conn = get_connection()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS scim_users (
            id            TEXT PRIMARY KEY,
            user_name     TEXT NOT NULL UNIQUE,
            external_id   TEXT,
            given_name    TEXT,
            family_name   TEXT,
            display_name  TEXT,
            active        INTEGER NOT NULL DEFAULT 1,
            emails        TEXT NOT NULL DEFAULT '[]',
            created       TEXT NOT NULL,
            last_modified TEXT NOT NULL,
            version       TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scim_groups (
            id            TEXT PRIMARY KEY,
            display_name  TEXT NOT NULL UNIQUE,
            external_id   TEXT,
            created       TEXT NOT NULL,
            last_modified TEXT NOT NULL,
            version       TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scim_group_members (
            group_id TEXT NOT NULL,
            user_id  TEXT NOT NULL,
            PRIMARY KEY (group_id, user_id)
        );

        CREATE TABLE IF NOT EXISTS provisioning_tokens (
            token_hash TEXT PRIMARY KEY,
            name       TEXT NOT NULL,
            revoked    INTEGER NOT NULL DEFAULT 0
        );
        """
    )
    conn.commit()
    conn.close()


# --- provisioning tokens ----------------------------------------------------

def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_token(name: str) -> str:
    import secrets
    token = "scim_" + secrets.token_urlsafe(32)
    conn = get_connection()
    conn.execute("INSERT INTO provisioning_tokens (token_hash, name) VALUES (?, ?)",
                 (_hash(token), name))
    conn.commit()
    conn.close()
    return token


def token_valid(token: str) -> bool:
    conn = get_connection()
    row = conn.execute(
        "SELECT 1 FROM provisioning_tokens WHERE token_hash = ? AND revoked = 0",
        (_hash(token),)).fetchone()
    conn.close()
    return row is not None


# --- users ------------------------------------------------------------------

def _touch(fields: dict, created: str):
    fields["last_modified"] = scim.now_iso()
    fields["version"] = scim.version_of(
        fields.get("user_name"), fields.get("active"), fields.get("display_name"),
        fields.get("given_name"), fields.get("family_name"), fields.get("emails"),
        fields["last_modified"])


def create_user(fields: dict) -> str:
    uid = str(uuid.uuid4())
    now = scim.now_iso()
    fields = {**fields, "id": uid, "created": now}
    _touch(fields, now)
    conn = get_connection()
    conn.execute(
        """INSERT INTO scim_users
           (id, user_name, external_id, given_name, family_name, display_name,
            active, emails, created, last_modified, version)
           VALUES (:id,:user_name,:external_id,:given_name,:family_name,:display_name,
                   :active,:emails,:created,:last_modified,:version)""", fields)
    conn.commit()
    conn.close()
    return uid


def get_user(uid: str):
    conn = get_connection()
    row = conn.execute("SELECT * FROM scim_users WHERE id = ?", (uid,)).fetchone()
    conn.close()
    return row


def get_user_by_username(user_name: str):
    conn = get_connection()
    row = conn.execute("SELECT * FROM scim_users WHERE user_name = ?", (user_name,)).fetchone()
    conn.close()
    return row


def replace_user(uid: str, fields: dict):
    row = get_user(uid)
    if row is None:
        return None
    fields = {**fields, "id": uid}
    _touch(fields, row["created"])
    conn = get_connection()
    conn.execute(
        """UPDATE scim_users SET user_name=:user_name, external_id=:external_id,
           given_name=:given_name, family_name=:family_name, display_name=:display_name,
           active=:active, emails=:emails, last_modified=:last_modified, version=:version
           WHERE id=:id""", fields)
    conn.commit()
    conn.close()
    return get_user(uid)


def list_users(where_attr=None, where_value=None, start_index=1, count=100):
    attr_map = {"userName": "user_name", "externalId": "external_id", "active": "active"}
    conn = get_connection()
    if where_attr in attr_map:
        val = (1 if where_value else 0) if where_attr == "active" else where_value
        total = conn.execute(f"SELECT COUNT(*) FROM scim_users WHERE {attr_map[where_attr]} = ?",
                             (val,)).fetchone()[0]
        rows = conn.execute(
            f"SELECT * FROM scim_users WHERE {attr_map[where_attr]} = ? "
            f"ORDER BY created LIMIT ? OFFSET ?",
            (val, count, max(start_index - 1, 0))).fetchall()
    else:
        total = conn.execute("SELECT COUNT(*) FROM scim_users").fetchone()[0]
        rows = conn.execute("SELECT * FROM scim_users ORDER BY created LIMIT ? OFFSET ?",
                            (count, max(start_index - 1, 0))).fetchall()
    conn.close()
    return rows, total


def delete_user(uid: str) -> bool:
    conn = get_connection()
    cur = conn.execute("DELETE FROM scim_users WHERE id = ?", (uid,))
    conn.execute("DELETE FROM scim_group_members WHERE user_id = ?", (uid,))
    conn.commit()
    n = cur.rowcount
    conn.close()
    return n > 0


# --- groups -----------------------------------------------------------------

def create_group(display_name, external_id, member_ids):
    gid = str(uuid.uuid4())
    now = scim.now_iso()
    version = scim.version_of(display_name, member_ids, now)
    conn = get_connection()
    conn.execute("INSERT INTO scim_groups (id, display_name, external_id, created, "
                 "last_modified, version) VALUES (?,?,?,?,?,?)",
                 (gid, display_name, external_id, now, now, version))
    for uid in member_ids:
        conn.execute("INSERT OR IGNORE INTO scim_group_members (group_id, user_id) VALUES (?,?)",
                     (gid, uid))
    conn.commit()
    conn.close()
    return gid


def get_group(gid):
    conn = get_connection()
    row = conn.execute("SELECT * FROM scim_groups WHERE id = ?", (gid,)).fetchone()
    conn.close()
    return row


def group_members(gid):
    conn = get_connection()
    rows = conn.execute(
        "SELECT u.id, u.user_name FROM scim_group_members m "
        "JOIN scim_users u ON u.id = m.user_id WHERE m.group_id = ?", (gid,)).fetchall()
    conn.close()
    return rows


def add_group_members(gid, user_ids):
    conn = get_connection()
    for uid in user_ids:
        conn.execute("INSERT OR IGNORE INTO scim_group_members (group_id, user_id) VALUES (?,?)",
                     (gid, uid))
    _bump_group(conn, gid)
    conn.commit()
    conn.close()


def remove_group_member(gid, uid):
    conn = get_connection()
    conn.execute("DELETE FROM scim_group_members WHERE group_id = ? AND user_id = ?", (gid, uid))
    _bump_group(conn, gid)
    conn.commit()
    conn.close()


def _bump_group(conn, gid):
    now = scim.now_iso()
    conn.execute("UPDATE scim_groups SET last_modified = ?, version = ? WHERE id = ?",
                 (now, scim.version_of(gid, now), gid))


def delete_group(gid) -> bool:
    conn = get_connection()
    cur = conn.execute("DELETE FROM scim_groups WHERE id = ?", (gid,))
    conn.execute("DELETE FROM scim_group_members WHERE group_id = ?", (gid,))
    conn.commit()
    n = cur.rowcount
    conn.close()
    return n > 0
