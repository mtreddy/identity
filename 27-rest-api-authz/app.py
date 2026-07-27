"""
app.py — a REST API exposing VULNERABLE and SAFE variants of four
authorization bugs, side by side, so you can fire the same request at both and
watch one leak/escalate and the other hold. Every endpoint requires a valid
bearer token (get one from POST /login) — these are *authorization* bugs, so
the caller is always authenticated; the question is what they're allowed to do.

  GET   /vuln|/safe/notes/<id>   — BOLA / IDOR      (OWASP API1: object-level authz)
  GET   /vuln|/safe/me           — excessive data   (OWASP API3: over-serialization)
  GET   /vuln|/safe/admin/users  — BFLA             (OWASP API5: function-level authz)
  PATCH /vuln|/safe/me           — mass assignment  (OWASP API6: field-level authz)

The /vuln/* handlers are intentionally broken — this app is a localhost sandbox
for learning API authorization, not something to deploy.
"""

import os

import bcrypt
from flask import Flask, g, jsonify, request

import authz
import db

app = Flask(__name__)


@app.post("/login")
def login():
    """Authenticate (bcrypt) and issue an opaque bearer token. Authentication
    is deliberately ordinary here; the lessons are all downstream of it."""
    body = request.get_json(silent=True) or {}
    user = db.get_user_by_username(body.get("username", ""))
    ok = user is not None and bcrypt.checkpw(
        body.get("password", "").encode(), user["password_hash"].encode())
    if not ok:
        return jsonify(error="invalid credentials"), 401
    return jsonify(token=db.create_token(user["id"]))


# --- BOLA / IDOR (API1) — may you touch THIS object? -----------------------

@app.get("/vuln/notes/<int:note_id>")
@authz.require_user
def vuln_get_note(note_id):
    note = db.get_note(note_id)
    if note is None:
        return jsonify(error="not found"), 404
    # DANGER: authenticated == authorized. Any logged-in user can read any
    # note by guessing/enumerating its id — the object owner is never checked.
    return jsonify(note=dict(note))


@app.get("/safe/notes/<int:note_id>")
@authz.require_user
def safe_get_note(note_id):
    note = db.get_note(note_id)
    # Object-level check: you may only read a note you own. Return 404 (not 403)
    # for someone else's note so the API doesn't confirm which ids exist.
    if note is None or note["owner_id"] != g.user["id"]:
        return jsonify(error="not found"), 404
    return jsonify(note=dict(note))


# --- Excessive data exposure (API3) — which fields may you read back? ------

@app.get("/vuln/me")
@authz.require_user
def vuln_me():
    # DANGER: dumping the whole row leaks password_hash, recovery_code and
    # is_admin. "The client only shows a few fields" is not a control — the
    # data is on the wire.
    return jsonify(user=dict(g.user))


@app.get("/safe/me")
@authz.require_user
def safe_me():
    # Serialize through an explicit public allow-list.
    return jsonify(user=authz.user_public(g.user))


# --- BFLA (API5) — may you call THIS operation at all? ---------------------

@app.get("/vuln/admin/users")
@authz.require_user
def vuln_admin_users():
    # DANGER: an admin-only listing function with no role check. The route
    # isn't linked in the normal UI, but obscurity isn't authorization — any
    # authenticated user can call it directly.
    return jsonify(users=[authz.user_public(u) for u in db.get_all_users()])


@app.get("/safe/admin/users")
@authz.require_user
def safe_admin_users():
    if not g.user["is_admin"]:
        return jsonify(error="forbidden"), 403
    return jsonify(users=[authz.user_public(u) for u in db.get_all_users()])


# --- Mass assignment (API6) — which fields may you write? ------------------

@app.patch("/vuln/me")
@authz.require_user
def vuln_update_me():
    body = request.get_json(silent=True) or {}
    # DANGER: the whole request body is forwarded into the update. A caller can
    # add "is_admin": true and escalate to administrator on their own account.
    db.update_user(g.user["id"], body)
    return jsonify(user=authz.user_public(db.get_user_by_id(g.user["id"])))


@app.patch("/safe/me")
@authz.require_user
def safe_update_me():
    body = request.get_json(silent=True) or {}
    # Field-level allow-list: bind only the fields a user may set on themselves.
    fields = {k: v for k, v in body.items() if k in authz.WRITABLE_PROFILE_FIELDS}
    db.update_user(g.user["id"], fields)
    return jsonify(user=authz.user_public(db.get_user_by_id(g.user["id"])))


if __name__ == "__main__":
    db.init_schema()
    db.seed()
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=os.environ.get("FLASK_DEBUG") == "1")
