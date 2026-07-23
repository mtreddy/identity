"""
scim.py — SCIM 2.0 schema + protocol helpers (RFC 7643 / RFC 7644).

SCIM is how an Identity Provider (Okta, Entra ID, …) **provisions** accounts
into an application: a standard REST+JSON API to create, update, deactivate, and
delete Users and Groups, so the app's directory stays in sync with the IdP as
people join, change roles, and leave. This module maps between our database rows
and SCIM's JSON representation, applies PATCH operations, and parses filters.
"""

import hashlib
import json
import re
from datetime import datetime, timezone

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
PATCHOP_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"


class ScimError(Exception):
    def __init__(self, status: int, detail: str, scim_type: str | None = None):
        super().__init__(detail)
        self.status = status
        self.detail = detail
        self.scim_type = scim_type

    def to_json(self) -> dict:
        body = {"schemas": [ERROR_SCHEMA], "detail": self.detail, "status": str(self.status)}
        if self.scim_type:
            body["scimType"] = self.scim_type
        return body


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def version_of(*parts) -> str:
    """A weak ETag over the mutable fields (SCIM `meta.version`)."""
    h = hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:16]
    return f'W/"{h}"'


# --- User: DB row <-> SCIM JSON ---------------------------------------------

def user_fields_from_scim(payload: dict) -> dict:
    """Validate an incoming User and return DB field values."""
    if USER_SCHEMA not in payload.get("schemas", []):
        raise ScimError(400, "Payload must include the User schema", "invalidSyntax")
    user_name = payload.get("userName")
    if not user_name:
        raise ScimError(400, "userName is required", "invalidValue")
    name = payload.get("name") or {}
    return {
        "user_name": user_name,
        "external_id": payload.get("externalId"),
        "given_name": name.get("givenName"),
        "family_name": name.get("familyName"),
        "display_name": payload.get("displayName"),
        "active": 1 if payload.get("active", True) else 0,
        "emails": json.dumps(payload.get("emails") or []),
    }


def user_to_scim(row, location: str) -> dict:
    out = {
        "schemas": [USER_SCHEMA],
        "id": row["id"],
        "userName": row["user_name"],
        "active": bool(row["active"]),
        "meta": {
            "resourceType": "User",
            "created": row["created"],
            "lastModified": row["last_modified"],
            "location": location,
            "version": row["version"],
        },
    }
    if row["external_id"]:
        out["externalId"] = row["external_id"]
    if row["given_name"] or row["family_name"]:
        out["name"] = {k: v for k, v in
                       (("givenName", row["given_name"]), ("familyName", row["family_name"])) if v}
    if row["display_name"]:
        out["displayName"] = row["display_name"]
    emails = json.loads(row["emails"] or "[]")
    if emails:
        out["emails"] = emails
    return out


# --- PATCH ------------------------------------------------------------------

# SCIM path (lowercased) -> DB field
_PATCH_PATHS = {
    "username": "user_name",
    "externalid": "external_id",
    "displayname": "display_name",
    "name.givenname": "given_name",
    "name.familyname": "family_name",
    "active": "active",
    "emails": "emails",
}


def _set_field(fields: dict, key: str, value):
    if key == "active":
        fields[key] = 1 if value in (True, "true", "True", 1) else 0
    elif key == "emails":
        fields[key] = json.dumps(value or [])
    else:
        fields[key] = value


def apply_user_patch(fields: dict, payload: dict) -> dict:
    """Apply a PatchOp (add/replace/remove) to a dict of User DB fields."""
    if PATCHOP_SCHEMA not in payload.get("schemas", []):
        raise ScimError(400, "PATCH must use the PatchOp schema", "invalidSyntax")
    for op in payload.get("Operations", []):
        action = (op.get("op") or "").lower()
        path = op.get("path")
        value = op.get("value")
        if not path:
            # No path: value is a partial resource object (Entra ID style).
            if action in ("add", "replace") and isinstance(value, dict):
                for k, v in value.items():
                    key = _PATCH_PATHS.get(k.lower())
                    if key:
                        _set_field(fields, key, v)
            continue
        key = _PATCH_PATHS.get(path.lower())
        if key is None:
            continue  # ignore attributes we don't model (lenient, per common practice)
        if action == "remove":
            fields[key] = 0 if key == "active" else (json.dumps([]) if key == "emails" else None)
        elif action in ("add", "replace"):
            _set_field(fields, key, value)
        else:
            raise ScimError(400, f"unsupported op: {action}", "invalidSyntax")
    return fields


# --- filter -----------------------------------------------------------------

def parse_filter(f: str):
    """Minimal SCIM filter support: `attr eq "value"` (or eq true/false).
    Returns (attr, value) or None. Enough for the IdP's dedup lookups."""
    if not f:
        return None
    m = re.match(r'\s*(\w+)\s+eq\s+"(.*)"\s*$', f)
    if m:
        return m.group(1), m.group(2)
    m = re.match(r"\s*(\w+)\s+eq\s+(true|false)\s*$", f, re.I)
    if m:
        return m.group(1), m.group(2).lower() == "true"
    raise ScimError(400, f"unsupported filter: {f}", "invalidFilter")


# --- list + group -----------------------------------------------------------

def list_response(resources, total, start_index, per_page) -> dict:
    return {
        "schemas": [LIST_SCHEMA],
        "totalResults": total,
        "startIndex": start_index,
        "itemsPerPage": per_page,
        "Resources": resources,
    }


def group_to_scim(row, members, location) -> dict:
    out = {
        "schemas": [GROUP_SCHEMA],
        "id": row["id"],
        "displayName": row["display_name"],
        "members": [{"value": m["id"], "display": m["user_name"]} for m in members],
        "meta": {"resourceType": "Group", "created": row["created"],
                 "lastModified": row["last_modified"], "location": location,
                 "version": row["version"]},
    }
    if row["external_id"]:
        out["externalId"] = row["external_id"]
    return out
