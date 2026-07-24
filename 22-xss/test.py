"""test.py — checks for 22-xss. Exits nonzero on failure."""
import os
import secrets
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import testlib as T  # noqa: E402

ENV = {"SECRET_KEY": secrets.token_hex(32)}
PAYLOAD = "<script>__XSS__</script>"
ENCODED = "&lt;script&gt;__XSS__&lt;/script&gt;"


def main():
    T.clean(HERE)
    proc, base = T.start_server(HERE, env_extra=ENV)

    q = "?q=" + urllib.parse.quote(PAYLOAD)

    # reflected: vuln reflects raw payload; safe encodes it
    _, _, vbody = T.http("GET", base + "/vuln/search" + q)
    T.check("reflected XSS: raw <script> present on /vuln", PAYLOAD in vbody)
    _, shdr, sbody = T.http("GET", base + "/safe/search" + q)
    T.check("reflected XSS: encoded (inert) on /safe", ENCODED in sbody and PAYLOAD not in sbody)
    T.check("/safe sends a Content-Security-Policy",
            "script-src 'self'" in (shdr.get("Content-Security-Policy") or ""))
    T.check("/vuln has NO CSP (shows the missing layer)",
            not T.http("GET", base + "/vuln/search" + q)[1].get("Content-Security-Policy"))

    # stored: post the payload, then read it back
    T.http("POST", base + "/vuln/comments", data={"comment": PAYLOAD})
    _, _, vbody = T.http("GET", base + "/vuln/comments")
    T.check("stored XSS: raw <script> persisted+served on /vuln", PAYLOAD in vbody)
    T.http("POST", base + "/safe/comments", data={"comment": PAYLOAD})
    _, _, sbody = T.http("GET", base + "/safe/comments")
    T.check("stored XSS: encoded (inert) on /safe", ENCODED in sbody and PAYLOAD not in sbody)

    # HttpOnly session cookie -> a working XSS still can't read it
    _, hdr, _ = T.http("GET", base + "/", allow_redirects=False)
    T.check("session cookie is HttpOnly", "HttpOnly" in hdr.get("Set-Cookie", ""))

    T.finish(proc)


if __name__ == "__main__":
    main()
