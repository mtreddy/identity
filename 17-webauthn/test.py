"""test.py — checks for 17-webauthn. Exits nonzero on failure."""
import os
import secrets
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import testlib as T  # noqa: E402

PORT = os.environ.get("TEST_PORT", "5717")
BASE = f"http://127.0.0.1:{PORT}"
ENV = {"SECRET_KEY": secrets.token_hex(32), "RP_ID": "localhost", "ORIGIN": BASE}


def main():
    T.clean(HERE)
    proc, base = T.start_server(HERE, env_extra=ENV, port=PORT)

    os.environ.update(ENV)
    os.environ["API_BASE"] = BASE
    sys.path.insert(0, HERE)
    import client_example as ce  # noqa: E402

    auth = ce.SoftwareAuthenticator()

    _, opt = ce.post("/register/begin", {"email": "user@example.com"})
    st, r = ce.post("/register/finish", auth.create(opt))
    T.check("register a passkey -> 200", st == 200 and r.get("status") == "ok")

    st, r = ce.login(auth)
    T.check("login with passkey -> 200", st == 200 and r.get("email") == "user@example.com")

    st, r = ce.login(auth, bump=False)
    T.check("non-increasing sign counter (clone) -> 401", st == 401, f"{st} {r}")

    st, r = ce.login(auth, origin="http://evil.example")
    T.check("wrong origin (phishing) -> 401", st == 401, f"{st} {r}")

    st, r = ce.login(auth, tamper_sig=True)
    T.check("tampered signature -> 401", st == 401, f"{st} {r}")

    # counter still advances on a legit login after the failures
    T.check("legit login still works (counter advances)", ce.login(auth)[0] == 200)

    T.finish(proc)


if __name__ == "__main__":
    main()
