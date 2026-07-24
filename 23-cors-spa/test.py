"""test.py — checks for 23-cors-spa. Exits nonzero on failure.

CORS is enforced by the browser, so we assert the SERVER emits the correct
headers per origin (what the browser bases its allow/block decision on)."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import testlib as T  # noqa: E402

SPA = "http://spa.example"        # the one allow-listed origin for this test
EVIL = "http://evil.example"
TOKEN = "demo-spa-token"
ENV = {"ALLOWED_ORIGINS": SPA, "API_TOKEN": TOKEN}


def main():
    T.clean(HERE)
    proc, base = T.start_server(HERE, env_extra=ENV)

    def call(method, path, origin, preflight=False, token=True):
        h = {"Origin": origin}
        if preflight:
            h["Access-Control-Request-Method"] = "GET"
            h["Access-Control-Request-Headers"] = "authorization"
        elif token:
            h["Authorization"] = f"Bearer {TOKEN}"
        st, hdr, _ = T.http(method, base + path, headers=h)
        return st, hdr

    # preflight from an allowed origin
    st, hdr = call("OPTIONS", "/api/data", SPA, preflight=True)
    T.check("preflight -> 204", st == 204)
    T.check("preflight allows the origin", hdr.get("Access-Control-Allow-Origin") == SPA)
    T.check("preflight advertises methods", "GET" in (hdr.get("Access-Control-Allow-Methods") or ""))
    T.check("preflight advertises headers", "Authorization" in (hdr.get("Access-Control-Allow-Headers") or ""))
    T.check("preflight allows credentials", hdr.get("Access-Control-Allow-Credentials") == "true")

    # actual GET from an allowed origin
    st, hdr = call("GET", "/api/data", SPA)
    T.check("allowed origin: ACAO echoes the origin (not *)",
            hdr.get("Access-Control-Allow-Origin") == SPA)
    T.check("allowed origin: Vary: Origin set", "Origin" in (hdr.get("Vary") or ""))

    # GET from a DISALLOWED origin: server still responds, but NO ACAO ->
    # the browser blocks the page from reading it.
    st, hdr = call("GET", "/api/data", EVIL)
    T.check("disallowed origin: no ACAO header (browser blocks)",
            hdr.get("Access-Control-Allow-Origin") is None, f"acao={hdr.get('Access-Control-Allow-Origin')}")

    # never '*' with credentials on the safe endpoint
    T.check("safe endpoint never uses '*'",
            call("GET", "/api/data", SPA)[1].get("Access-Control-Allow-Origin") != "*")

    # the MISCONFIG: /vuln reflects any origin WITH credentials
    st, hdr = call("GET", "/vuln/data", EVIL)
    T.check("vuln reflects the attacker origin", hdr.get("Access-Control-Allow-Origin") == EVIL)
    T.check("vuln allows credentials (the dangerous combo)",
            hdr.get("Access-Control-Allow-Credentials") == "true")

    # same-origin / non-browser request (no Origin) works, no CORS headers needed
    st, hdr, _ = T.http("GET", base + "/api/data", headers={"Authorization": f"Bearer {TOKEN}"})
    T.check("no-Origin request works without CORS headers",
            st == 200 and hdr.get("Access-Control-Allow-Origin") is None)

    T.finish(proc)


if __name__ == "__main__":
    main()
