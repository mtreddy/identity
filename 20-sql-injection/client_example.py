"""
client_example.py — fire the same SQL-injection attacks at the VULNERABLE and
SAFE endpoints and show that only the vulnerable one falls.

    python client_example.py     (server must be running)
"""

import json
import os
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get("API_BASE", "http://127.0.0.1:5000").rstrip("/")


def get(path, **params):
    url = BASE + path + "?" + urllib.parse.urlencode(params)
    try:
        with urllib.request.urlopen(url) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def main():
    print("=" * 72)
    print("1) AUTH BYPASS — payload:  username = \"admin' -- \"  (no password)")
    print("=" * 72)
    payload = {"username": "admin' -- ", "password": "wrong"}
    for kind in ("vuln", "safe"):
        _, r = get(f"/{kind}/login", **payload)
        who = r["user"][0]["username"] if r["authenticated"] else "-"
        print(f"  /{kind}/login -> authenticated={r['authenticated']!s:<5} as={who}")
        print(f"     sql: {r['sql']}")

    print("\n" + "=" * 72)
    print("2) TAUTOLOGY BYPASS — payload:  username = \"x' OR '1'='1' -- \"")
    print("=" * 72)
    payload = {"username": "x' OR '1'='1' -- ", "password": "x"}
    for kind in ("vuln", "safe"):
        _, r = get(f"/{kind}/login", **payload)
        who = r["user"][0]["username"] if r["authenticated"] else "-"
        print(f"  /{kind}/login -> authenticated={r['authenticated']!s:<5} as={who}")

    print("\n" + "=" * 72)
    print("3) UNION EXFILTRATION — steal user secrets through product search")
    print("   payload:  category = \"none' UNION SELECT username, secret_note FROM users -- \"")
    print("=" * 72)
    payload = {"category": "none' UNION SELECT username, secret_note FROM users -- "}
    for kind in ("vuln", "safe"):
        _, r = get(f"/{kind}/search", **payload)
        leaked = [f"{row['name']}={row['category']}" for row in r["results"]]
        print(f"  /{kind}/search -> {len(r['results'])} rows: {leaked or '(none)'}")

    print("\n" + "=" * 72)
    print("4) ORDER BY / IDENTIFIER INJECTION — payload:  sort = injected expression")
    print("   (values can't fix this — identifiers need an ALLOW-LIST)")
    print("=" * 72)
    inj = "(SELECT CASE WHEN 1=1 THEN name ELSE price END)"
    _, r = get("/vuln/list", sort=inj)
    print(f"  /vuln/list?sort=<injected expr> -> {r.get('error') or 'executed: ' + str(len(r['results'])) + ' rows'}")
    st, r = get("/safe/list", sort=inj)
    print(f"  /safe/list?sort=<injected expr> -> {st} {r.get('error')}")
    _, r = get("/safe/list", sort="price")
    print(f"  /safe/list?sort=price (allow-listed) -> {[x['name'] for x in r['results']]}")

    print("\n" + "=" * 72)
    print("SANITY — normal usage still works on the safe endpoints")
    print("=" * 72)
    _, r = get("/safe/login", username="admin", password="s3cr3t-admin-pw")
    print(f"  correct admin login -> authenticated={r['authenticated']}")
    _, r = get("/safe/login", username="admin", password="wrong")
    print(f"  wrong password      -> authenticated={r['authenticated']}")
    _, r = get("/safe/search", category="hardware")
    print(f"  search 'hardware'   -> {[x['name'] for x in r['results']]}")


if __name__ == "__main__":
    main()
