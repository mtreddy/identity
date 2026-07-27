"""
client_example.py — drive all four attacks against /vuln and /safe and print
what falls vs. what holds. A non-browser API client (like an attacker's script
or a curl loop); no cookies or CSRF in play — just bearer tokens.

    python app.py                 # in one shell (seeds + serves)
    python client_example.py      # in another
"""

import json
import os
import urllib.error
import urllib.request

BASE = os.environ.get("BASE_URL", "http://127.0.0.1:5000")


def call(method, path, token=None, body=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=headers)
    try:
        r = urllib.request.urlopen(req)
        return r.status, json.loads(r.read() or "{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or "{}")


def login(username, password):
    _, body = call("POST", "/login", body={"username": username, "password": password})
    return body["token"]


def main():
    alice = login("alice@example.com", "correct-horse-battery-staple")
    bob = login("bob@example.com", "hunter2")
    admin = login("admin@example.com", "admin-pw-do-not-ship")
    print("logged in alice, bob, admin\n")

    print("== BOLA / IDOR: alice reads bob's note (id 2) ==")
    print("  /vuln:", call("GET", "/vuln/notes/2", alice))       # leaks bob's note
    print("  /safe:", call("GET", "/safe/notes/2", alice))       # 404
    print("  /safe alice's own note (id 1):", call("GET", "/safe/notes/1", alice)[0])

    print("\n== Excessive data exposure: alice reads her own profile ==")
    print("  /vuln fields:", sorted(call("GET", "/vuln/me", alice)[1]["user"]))
    print("  /safe fields:", sorted(call("GET", "/safe/me", alice)[1]["user"]))

    print("\n== BFLA: alice (not admin) lists all users ==")
    print("  /vuln:", call("GET", "/vuln/admin/users", alice)[0], "(leaked list)")
    print("  /safe:", call("GET", "/safe/admin/users", alice)[0], "(forbidden)")
    print("  /safe as admin:", call("GET", "/safe/admin/users", admin)[0])

    print("\n== Mass assignment: bob sets is_admin via a profile update ==")
    call("PATCH", "/safe/me", bob, {"full_name": "Bob B", "is_admin": True})
    print("  after /safe is_admin=?:", call("GET", "/vuln/me", bob)[1]["user"]["is_admin"])
    call("PATCH", "/vuln/me", bob, {"is_admin": True})
    print("  after /vuln is_admin=?:", call("GET", "/vuln/me", bob)[1]["user"]["is_admin"])


if __name__ == "__main__":
    main()
