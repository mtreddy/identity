"""
authz.py — the authorization primitives this mechanism is about.

Authentication (who are you?) is the easy part here: a bearer token in the
`Authorization` header identifies the caller. The interesting, and most
commonly botched, part is *authorization* (what may you do?):

  - object-level   — may you touch THIS object? (BOLA / IDOR)
  - function-level  — may you call THIS operation at all? (BFLA)
  - field-level     — which fields of an object may you write? (mass assignment)
  - response shape  — which fields may you read back? (excessive data exposure)

The vulnerable handlers in app.py skip one of these checks; the safe handlers
use the helpers below. Keeping the rules in one module (allow-lists, the
serializer, the auth decorator) is what makes "safe" a one-liner at each call
site — the pattern real codebases should copy.
"""

from functools import wraps

from flask import g, jsonify, request

import db

# Response projection: the ONLY user fields safe to expose over the API.
# Anything not listed here (password_hash, recovery_code, is_admin, …) stays
# server-side. Serialize with an allow-list, never `dict(row)`.
PUBLIC_USER_FIELDS = ("id", "username", "full_name", "email")

# Field-level write allow-list for a self-service profile update. Note this is
# NARROWER than db.UPDATABLE_COLUMNS — a user may change their name/email but
# must never set their own `is_admin`. That gap is the mass-assignment bug.
WRITABLE_PROFILE_FIELDS = {"full_name", "email"}


def user_public(row):
    """Serialize a user row to its safe public projection."""
    return {k: row[k] for k in PUBLIC_USER_FIELDS}


def bearer_token(req):
    header = req.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        return header[len("Bearer "):].strip()
    return None


def require_user(view):
    """Decorator: reject anonymous callers (401) and stash the authenticated
    user on `g.user`. Both /vuln and /safe use this — the demos assume a valid
    login; the point is what an *authenticated* user is then allowed to do."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        token = bearer_token(request)
        user = db.user_for_token(token) if token else None
        if user is None:
            resp = jsonify(error="unauthorized")
            resp.headers["WWW-Authenticate"] = "Bearer"
            return resp, 401
        g.user = user
        return view(*args, **kwargs)
    return wrapped
