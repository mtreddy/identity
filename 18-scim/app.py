"""
app.py — a SCIM 2.0 Service Provider (the app an IdP provisions into).

Implements the RFC 7644 REST protocol under /scim/v2:

  Users:  POST /Users, GET /Users/{id}, GET /Users?filter=&startIndex=&count=,
          PUT /Users/{id}, PATCH /Users/{id}, DELETE /Users/{id}
  Groups: POST /Groups, GET /Groups/{id}, GET /Groups, PATCH /Groups/{id}, DELETE
  Discovery: GET /ServiceProviderConfig, /ResourceTypes, /Schemas

Auth is a bearer token the IdP presents (created by seed.py). Responses use
`application/scim+json` and SCIM's List/Error message shapes.
"""

import functools
import json
import os
import re

from flask import Flask, request

import db
import scim

app = Flask(__name__)


def scim_response(obj, status=200, location=None):
    resp = app.response_class(json.dumps(obj), status=status,
                              mimetype="application/scim+json")
    if location:
        resp.headers["Location"] = location
    return resp


@app.errorhandler(scim.ScimError)
def _handle_scim_error(e):
    return scim_response(e.to_json(), e.status)


def require_token(view):
    @functools.wraps(view)
    def wrapped(*a, **k):
        h = request.headers.get("Authorization", "")
        if not h.startswith("Bearer ") or not db.token_valid(h[len("Bearer "):].strip()):
            raise scim.ScimError(401, "missing or invalid bearer token")
        return view(*a, **k)
    return wrapped


def _json():
    data = request.get_json(force=True, silent=True)
    if data is None:
        raise scim.ScimError(400, "request body is not valid JSON", "invalidSyntax")
    return data


def _root():
    return request.url_root.rstrip("/") + "/scim/v2"


def _user_loc(uid):
    return f"{_root()}/Users/{uid}"


def _group_loc(gid):
    return f"{_root()}/Groups/{gid}"


def _row_to_fields(row) -> dict:
    return {k: row[k] for k in ("user_name", "external_id", "given_name",
                                "family_name", "display_name", "active", "emails")}


# --- Users ------------------------------------------------------------------

@app.route("/scim/v2/Users", methods=["POST"])
@require_token
def create_user():
    fields = scim.user_fields_from_scim(_json())
    if db.get_user_by_username(fields["user_name"]):
        raise scim.ScimError(409, "userName already exists", "uniqueness")
    uid = db.create_user(fields)
    row = db.get_user(uid)
    return scim_response(scim.user_to_scim(row, _user_loc(uid)), 201, _user_loc(uid))


@app.route("/scim/v2/Users/<uid>", methods=["GET"])
@require_token
def get_user(uid):
    row = db.get_user(uid)
    if row is None:
        raise scim.ScimError(404, f"User {uid} not found")
    return scim_response(scim.user_to_scim(row, _user_loc(uid)))


@app.route("/scim/v2/Users", methods=["GET"])
@require_token
def list_users():
    parsed = scim.parse_filter(request.args.get("filter"))
    attr, val = parsed if parsed else (None, None)
    start = max(int(request.args.get("startIndex", 1)), 1)
    count = max(int(request.args.get("count", 100)), 0)
    rows, total = db.list_users(attr, val, start, count)
    resources = [scim.user_to_scim(r, _user_loc(r["id"])) for r in rows]
    return scim_response(scim.list_response(resources, total, start, len(resources)))


@app.route("/scim/v2/Users/<uid>", methods=["PUT"])
@require_token
def replace_user(uid):
    if db.get_user(uid) is None:
        raise scim.ScimError(404, f"User {uid} not found")
    fields = scim.user_fields_from_scim(_json())
    other = db.get_user_by_username(fields["user_name"])
    if other and other["id"] != uid:
        raise scim.ScimError(409, "userName already exists", "uniqueness")
    row = db.replace_user(uid, fields)
    return scim_response(scim.user_to_scim(row, _user_loc(uid)))


@app.route("/scim/v2/Users/<uid>", methods=["PATCH"])
@require_token
def patch_user(uid):
    row = db.get_user(uid)
    if row is None:
        raise scim.ScimError(404, f"User {uid} not found")
    fields = scim.apply_user_patch(_row_to_fields(row), _json())
    row = db.replace_user(uid, fields)
    return scim_response(scim.user_to_scim(row, _user_loc(uid)))


@app.route("/scim/v2/Users/<uid>", methods=["DELETE"])
@require_token
def delete_user(uid):
    if not db.delete_user(uid):
        raise scim.ScimError(404, f"User {uid} not found")
    return app.response_class("", 204)


# --- Groups -----------------------------------------------------------------

@app.route("/scim/v2/Groups", methods=["POST"])
@require_token
def create_group():
    payload = _json()
    if scim.GROUP_SCHEMA not in payload.get("schemas", []):
        raise scim.ScimError(400, "Payload must include the Group schema", "invalidSyntax")
    display = payload.get("displayName")
    if not display:
        raise scim.ScimError(400, "displayName is required", "invalidValue")
    member_ids = [m["value"] for m in payload.get("members", []) if m.get("value")]
    gid = db.create_group(display, payload.get("externalId"), member_ids)
    row = db.get_group(gid)
    return scim_response(scim.group_to_scim(row, db.group_members(gid), _group_loc(gid)),
                         201, _group_loc(gid))


@app.route("/scim/v2/Groups/<gid>", methods=["GET"])
@require_token
def get_group(gid):
    row = db.get_group(gid)
    if row is None:
        raise scim.ScimError(404, f"Group {gid} not found")
    return scim_response(scim.group_to_scim(row, db.group_members(gid), _group_loc(gid)))


@app.route("/scim/v2/Groups/<gid>", methods=["PATCH"])
@require_token
def patch_group(gid):
    row = db.get_group(gid)
    if row is None:
        raise scim.ScimError(404, f"Group {gid} not found")
    for op in _json().get("Operations", []):
        action = (op.get("op") or "").lower()
        path = (op.get("path") or "").strip()
        value = op.get("value")
        if path.lower() == "members":
            ids = [m["value"] for m in (value or []) if m.get("value")]
            if action == "add":
                db.add_group_members(gid, ids)
            elif action == "replace":
                for m in db.group_members(gid):
                    db.remove_group_member(gid, m["id"])
                db.add_group_members(gid, ids)
            elif action == "remove":
                for m in db.group_members(gid):
                    db.remove_group_member(gid, m["id"])
        elif path.lower().startswith("members["):
            # e.g. members[value eq "<uid>"]
            m = re.search(r'value eq "(.*?)"', path)
            if m and action == "remove":
                db.remove_group_member(gid, m.group(1))
    row = db.get_group(gid)
    return scim_response(scim.group_to_scim(row, db.group_members(gid), _group_loc(gid)))


@app.route("/scim/v2/Groups/<gid>", methods=["DELETE"])
@require_token
def delete_group(gid):
    if not db.delete_group(gid):
        raise scim.ScimError(404, f"Group {gid} not found")
    return app.response_class("", 204)


# --- discovery (unauthenticated is common; we require the token) ------------

@app.route("/scim/v2/ServiceProviderConfig")
@require_token
def service_provider_config():
    return scim_response({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": 200},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": True},
        "authenticationSchemes": [{"type": "oauthbearertoken", "name": "OAuth Bearer Token",
                                   "description": "Authentication via bearer token"}],
    })


@app.route("/scim/v2/ResourceTypes")
@require_token
def resource_types():
    base = _root()
    return scim_response([
        {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
         "id": "User", "name": "User", "endpoint": "/Users", "schema": scim.USER_SCHEMA,
         "meta": {"resourceType": "ResourceType", "location": f"{base}/ResourceTypes/User"}},
        {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
         "id": "Group", "name": "Group", "endpoint": "/Groups", "schema": scim.GROUP_SCHEMA,
         "meta": {"resourceType": "ResourceType", "location": f"{base}/ResourceTypes/Group"}},
    ])


@app.route("/scim/v2/Schemas")
@require_token
def schemas():
    return scim_response({"schemas": [scim.LIST_SCHEMA], "totalResults": 2, "startIndex": 1,
                          "itemsPerPage": 2,
                          "Resources": [{"id": scim.USER_SCHEMA, "name": "User"},
                                        {"id": scim.GROUP_SCHEMA, "name": "Group"}]})


if __name__ == "__main__":
    db.init_schema()
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=os.environ.get("FLASK_DEBUG") == "1")
