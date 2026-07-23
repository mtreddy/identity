"""test.py — checks for 20-sql-injection. Exits nonzero on failure."""
import os
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import testlib as T  # noqa: E402


def main():
    T.clean(HERE)
    proc, base = T.start_server(HERE)   # app.py seeds on startup

    def g(path, **params):
        return T.get_json(base + path + "?" + urllib.parse.urlencode(params))

    # 1. auth bypass — payload comments out the password check
    payload = {"username": "admin' -- ", "password": "wrong"}
    T.check("auth bypass falls on /vuln", g("/vuln/login", **payload)[1]["authenticated"] is True)
    T.check("auth bypass blocked on /safe", g("/safe/login", **payload)[1]["authenticated"] is False)

    # 2. tautology bypass
    taut = {"username": "x' OR '1'='1' -- ", "password": "x"}
    T.check("tautology falls on /vuln", g("/vuln/login", **taut)[1]["authenticated"] is True)
    T.check("tautology blocked on /safe", g("/safe/login", **taut)[1]["authenticated"] is False)

    # 3. UNION exfiltration through product search
    union = {"category": "none' UNION SELECT username, secret_note FROM users -- "}
    T.check("UNION exfiltration falls on /vuln", len(g("/vuln/search", **union)[1]["results"]) == 3)
    T.check("UNION exfiltration blocked on /safe", len(g("/safe/search", **union)[1]["results"]) == 0)

    # 4. ORDER BY / identifier injection — allow-list defense
    inj = "(SELECT CASE WHEN 1=1 THEN name ELSE price END)"
    T.check("identifier injection executes on /vuln", g("/vuln/list", sort=inj)[0] == 200)
    T.check("identifier allow-list rejects on /safe (400)", g("/safe/list", sort=inj)[0] == 400)

    # sanity: normal usage still works on safe endpoints
    T.check("correct login works",
            g("/safe/login", username="admin", password="s3cr3t-admin-pw")[1]["authenticated"] is True)
    T.check("wrong password fails",
            g("/safe/login", username="admin", password="nope")[1]["authenticated"] is False)
    T.check("normal search works", len(g("/safe/search", category="hardware")[1]["results"]) == 2)

    T.finish(proc)


if __name__ == "__main__":
    main()
