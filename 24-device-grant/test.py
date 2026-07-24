"""test.py — checks for 24-device-grant. Exits nonzero on failure."""
import os
import secrets
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import testlib as T  # noqa: E402

PORT = os.environ.get("TEST_PORT", "5724")
BASE = f"http://127.0.0.1:{PORT}"
ENV = {"SECRET_KEY": secrets.token_hex(32), "JWT_SECRET": secrets.token_hex(32),
       "DEVICE_INTERVAL": "1"}   # 1s interval keeps the test fast


def main():
    T.clean(HERE)
    T.run(HERE, ["seed.py"], env_extra=ENV)
    proc, base = T.start_server(HERE, env_extra=ENV, port=PORT)

    os.environ["API_BASE"] = BASE
    sys.path.insert(0, HERE)
    import client_example as ce  # noqa: E402
    import db  # noqa: E402

    # 1. device_authorization returns the RFC 8628 fields
    dev = ce.authorize()
    T.check("device_authorization returns user_code + device_code + verification_uri",
            all(k in dev for k in ("user_code", "device_code", "verification_uri",
                                   "verification_uri_complete", "interval", "expires_in")))
    T.check("user_code is human-friendly (XXXX-XXXX)",
            len(dev["user_code"]) == 9 and dev["user_code"][4] == "-")

    # 2. polling before approval -> authorization_pending
    st, body = ce.poll(dev["device_code"])
    T.check("poll before approval -> authorization_pending",
            st == 400 and body.get("error") == "authorization_pending")

    # 3. polling too fast -> slow_down
    st, body = ce.poll(dev["device_code"])
    T.check("polling faster than interval -> slow_down",
            st == 400 and body.get("error") == "slow_down")

    # 4. wrong user_code entered in the browser -> rejected (stays pending)
    b = ce._browser()
    page = ce._open(b, "GET", "/device")
    page = ce._open(b, "POST", "/device",
                    {"csrf_token": ce._field(page, "csrf_token"), "user_code": "ZZZZ-ZZZZ"})
    T.check("unknown user_code rejected", "not valid" in page)

    # 5. user approves -> device poll returns a token
    T.check("user approves in the browser", ce.user_decides(dev["user_code"], approve=True))
    time.sleep(1.1)
    st, body = ce.poll(dev["device_code"])
    T.check("poll after approval -> access_token", st == 200 and "access_token" in body)
    token = body["access_token"]

    # 6. token works at the resource server
    st, body = ce.api("/api/resources", token)
    T.check("token reads the user's resources", st == 200 and len(body["resources"]) == 2)

    # 7. device_code is one-time (already consumed)
    time.sleep(1.1)
    st, body = ce.poll(dev["device_code"])
    T.check("device_code is one-time (consumed -> invalid_grant)",
            st == 400 and body.get("error") == "invalid_grant")

    # 8. denial path -> access_denied
    dev2 = ce.authorize()
    ce.user_decides(dev2["user_code"], approve=False)
    time.sleep(1.1)
    st, body = ce.poll(dev2["device_code"])
    T.check("denied by user -> access_denied", st == 400 and body.get("error") == "access_denied")

    # 9. expired device_code -> expired_token
    dev3 = ce.authorize()
    db.get_connection().execute(
        "UPDATE device_codes SET expires_at = 1 WHERE user_code = ?", (dev3["user_code"],)
    ).connection.commit()
    st, body = ce.poll(dev3["device_code"])
    T.check("expired device_code -> expired_token",
            st == 400 and body.get("error") == "expired_token", f"{st} {body}")

    T.finish(proc)


if __name__ == "__main__":
    main()
