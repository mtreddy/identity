"""test.py — checks for 18-scim. Exits nonzero on failure."""
import os
import re
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import testlib as T  # noqa: E402

USER = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"
PATCHOP = "urn:ietf:params:scim:api:messages:2.0:PatchOp"


def main():
    T.clean(HERE)
    seed = T.run(HERE, ["seed.py"])
    token = re.search(r"(scim_\S+)", seed.stdout).group(1)
    proc, base = T.start_server(HERE)
    root = base + "/scim/v2"
    H = {"Authorization": f"Bearer {token}", "Content-Type": "application/scim+json"}

    def call(method, path, body=None, headers=H):
        import json
        st, hdr, text = T.http(method, root + path, json_body=body, headers=headers)
        return st, hdr, (json.loads(text) if text else {})

    T.check("no token -> 401", call("GET", "/Users", headers={})[0] == 401)

    st, hdr, u = call("POST", "/Users", {
        "schemas": [USER], "userName": "bjensen@example.com", "externalId": "ext-42",
        "name": {"givenName": "Barbara", "familyName": "Jensen"}, "active": True})
    uid = u.get("id")
    T.check("create user -> 201 with id", st == 201 and uid and hdr.get("Content-Type", "").startswith("application/scim+json"))

    T.check("get user -> 200", call("GET", f"/Users/{uid}")[0] == 200)

    q = urllib.parse.urlencode({"filter": 'userName eq "bjensen@example.com"'})
    st, _, lst = call("GET", "/Users?" + q)
    T.check("filter userName eq -> 1 result", st == 200 and lst["totalResults"] == 1)

    st, _, u = call("PATCH", f"/Users/{uid}", {
        "schemas": [PATCHOP], "Operations": [{"op": "replace", "path": "active", "value": False}]})
    T.check("PATCH deactivate -> active false", st == 200 and u["active"] is False)

    st, _, u = call("PUT", f"/Users/{uid}", {
        "schemas": [USER], "userName": "bjensen@example.com",
        "name": {"givenName": "Barbara", "familyName": "Smith"}, "active": True})
    T.check("PUT replace -> updated + reactivated",
            st == 200 and u["name"]["familyName"] == "Smith" and u["active"] is True)

    st, _, err = call("POST", "/Users", {"schemas": [USER], "userName": "bjensen@example.com"})
    T.check("duplicate userName -> 409 uniqueness", st == 409 and err.get("scimType") == "uniqueness")

    st, _, g = call("POST", "/Groups", {"schemas": [GROUP], "displayName": "Engineering"})
    gid = g["id"]
    st, _, g = call("PATCH", f"/Groups/{gid}", {
        "schemas": [PATCHOP], "Operations": [{"op": "add", "path": "members", "value": [{"value": uid}]}]})
    T.check("group add member", st == 200 and len(g["members"]) == 1)
    st, _, g = call("PATCH", f"/Groups/{gid}", {
        "schemas": [PATCHOP], "Operations": [{"op": "remove", "path": f'members[value eq "{uid}"]'}]})
    T.check("group remove member", st == 200 and len(g["members"]) == 0)

    T.check("delete user (deprovision) -> 204", call("DELETE", f"/Users/{uid}")[0] == 204)
    T.check("get after delete -> 404", call("GET", f"/Users/{uid}")[0] == 404)

    T.finish(proc)


if __name__ == "__main__":
    main()
