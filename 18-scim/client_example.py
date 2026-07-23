"""
client_example.py — simulate an Identity Provider provisioning the full user
lifecycle over SCIM: create -> read -> filter -> deactivate (PATCH) -> replace
(PUT) -> group membership -> delete (deprovision).

    SCIM_TOKEN=<from seed.py> python client_example.py
"""

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get("API_BASE", "http://127.0.0.1:5000").rstrip("/") + "/scim/v2"
TOKEN = os.environ.get("SCIM_TOKEN")
USER = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"
PATCHOP = "urn:ietf:params:scim:api:messages:2.0:PatchOp"


def call(method, path, body=None, token=TOKEN):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/scim+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        return e.code, (json.loads(raw) if raw else {})


def main():
    if not TOKEN:
        print("Set SCIM_TOKEN (printed by seed.py)."); sys.exit(2)

    print("0. no token -> " + str(call("GET", "/Users", token=None)[0]) + " (auth required)")

    # 1. provision (create) a user
    st, u = call("POST", "/Users", {
        "schemas": [USER], "userName": "bjensen@example.com", "externalId": "ext-42",
        "name": {"givenName": "Barbara", "familyName": "Jensen"},
        "emails": [{"value": "bjensen@example.com", "type": "work", "primary": True}],
        "active": True})
    uid = u["id"]
    print(f"1. POST /Users               -> {st} id={uid[:8]}… active={u['active']}")

    # 2. read it back
    print(f"2. GET /Users/{{id}}           -> {call('GET', f'/Users/{uid}')[0]}")

    # 3. IdP dedup lookup by userName filter (query string must be URL-encoded)
    q = urllib.parse.urlencode({"filter": 'userName eq "bjensen@example.com"'})
    st, lst = call("GET", "/Users?" + q)
    print(f"3. GET /Users?filter=…       -> {st} totalResults={lst['totalResults']}")

    # 4. deactivate on leave (PATCH replace active=false)
    st, u = call("PATCH", f"/Users/{uid}", {
        "schemas": [PATCHOP], "Operations": [{"op": "replace", "path": "active", "value": False}]})
    print(f"4. PATCH active=false        -> {st} active={u['active']}  (deactivate)")

    # 5. attribute change (PUT full replace: new familyName, re-activate)
    st, u = call("PUT", f"/Users/{uid}", {
        "schemas": [USER], "userName": "bjensen@example.com",
        "name": {"givenName": "Barbara", "familyName": "Smith"}, "active": True})
    print(f"5. PUT /Users/{{id}}           -> {st} familyName={u['name']['familyName']} active={u['active']}")

    # 6. duplicate userName is a conflict
    st, err = call("POST", "/Users", {"schemas": [USER], "userName": "bjensen@example.com"})
    print(f"6. POST duplicate userName   -> {st} {err.get('scimType')}")

    # 7. group + membership
    st, g = call("POST", "/Groups", {"schemas": [GROUP], "displayName": "Engineering"})
    gid = g["id"]
    st, g = call("PATCH", f"/Groups/{gid}", {
        "schemas": [PATCHOP],
        "Operations": [{"op": "add", "path": "members", "value": [{"value": uid}]}]})
    print(f"7. Group + add member        -> {st} members={[m['display'] for m in g['members']]}")
    st, g = call("PATCH", f"/Groups/{gid}", {
        "schemas": [PATCHOP],
        "Operations": [{"op": "remove", "path": f'members[value eq "{uid}"]'}]})
    print(f"   remove member             -> {st} members={g['members']}")

    # 8. deprovision (delete)
    print(f"8. DELETE /Users/{{id}}        -> {call('DELETE', f'/Users/{uid}')[0]} (deprovision)")
    print(f"   GET after delete          -> {call('GET', f'/Users/{uid}')[0]} (404)")


if __name__ == "__main__":
    main()
