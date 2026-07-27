"""test.py — checks for 27-rest-api-authz. Exits nonzero on failure.

Asserts the security negatives for all four bugs: the /vuln endpoint leaks or
escalates, the /safe endpoint holds, and normal authorized use still works.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import testlib as T  # noqa: E402


def main():
    T.clean(HERE)
    proc, base = T.start_server(HERE)   # app.py seeds on startup

    import json

    def login(username, password):
        st, _, text = T.http("POST", base + "/login",
                             json_body={"username": username, "password": password})
        return st, (json.loads(text) if text else {})

    def call(method, path, token=None, body=None):
        headers = {"Authorization": f"Bearer {token}"} if token else None
        st, _, text = T.http(method, base + path, headers=headers, json_body=body)
        return st, (json.loads(text) if text else {})

    # --- authentication (the ordinary part) ---------------------------------
    st, body = login("alice@example.com", "correct-horse-battery-staple")
    alice = body.get("token")
    T.check("login issues a token", st == 200 and bool(alice))
    T.check("wrong password -> 401", login("alice@example.com", "nope")[0] == 401)
    T.check("no token -> 401", call("GET", "/safe/me")[0] == 401)

    bob = login("bob@example.com", "hunter2")[1]["token"]
    admin = login("admin@example.com", "admin-pw-do-not-ship")[1]["token"]

    # --- BOLA / IDOR (note id 2 belongs to bob) -----------------------------
    T.check("BOLA falls on /vuln (alice reads bob's note)",
            call("GET", "/vuln/notes/2", alice) == (200, {"note": {
                "id": 2, "owner_id": 2, "title": "Bob's passwords",
                "body": "bob's private secrets"}}))
    T.check("BOLA blocked on /safe (404, no existence oracle)",
            call("GET", "/safe/notes/2", alice)[0] == 404)
    T.check("owner can read own note on /safe",
            call("GET", "/safe/notes/1", alice)[0] == 200)

    # --- excessive data exposure --------------------------------------------
    vuln_fields = set(call("GET", "/vuln/me", alice)[1]["user"])
    safe_fields = set(call("GET", "/safe/me", alice)[1]["user"])
    T.check("sensitive fields exposed on /vuln/me",
            {"password_hash", "recovery_code", "is_admin"} <= vuln_fields)
    T.check("sensitive fields withheld on /safe/me",
            not ({"password_hash", "recovery_code", "is_admin"} & safe_fields))

    # --- BFLA (admin-only listing function) ---------------------------------
    T.check("BFLA falls on /vuln (non-admin lists users)",
            call("GET", "/vuln/admin/users", alice)[0] == 200)
    T.check("BFLA blocked on /safe (non-admin -> 403)",
            call("GET", "/safe/admin/users", alice)[0] == 403)
    T.check("admin allowed on /safe/admin/users",
            call("GET", "/safe/admin/users", admin)[0] == 200)

    # --- mass assignment (bob tries to grant himself admin) -----------------
    call("PATCH", "/safe/me", bob, {"full_name": "Bob B", "is_admin": True})
    T.check("mass assignment blocked on /safe (is_admin unchanged)",
            call("GET", "/vuln/me", bob)[1]["user"]["is_admin"] == 0)
    T.check("allowed field still updated on /safe",
            call("GET", "/safe/me", bob)[1]["user"]["full_name"] == "Bob B")
    call("PATCH", "/vuln/me", bob, {"is_admin": True})
    T.check("mass assignment escalates on /vuln (is_admin -> 1)",
            call("GET", "/vuln/me", bob)[1]["user"]["is_admin"] == 1)

    T.finish(proc)


if __name__ == "__main__":
    main()
