"""test.py — checks for 25-signup-verification. Exits nonzero on failure.

Covers the happy path (signup -> verify -> login) plus the security negatives
that define this mechanism: the verification gate, single-use + expiring tokens,
and the no-enumeration property of /signup.
"""
import os
import re
import secrets
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import testlib as T  # noqa: E402

PORT = os.environ.get("TEST_PORT", "5725")
BASE = f"http://127.0.0.1:{PORT}"
KEY = secrets.token_hex(32)
ENV = {"SECRET_KEY": KEY, "PUBLIC_BASE_URL": BASE}

SEEDED_EMAIL = "alice@example.com"   # pre-verified by seed.py


def _csrf(page):
    m = re.search(r'name="csrf_token"\s+value="([^"]*)"', page)
    return m.group(1) if m else ""


def main():
    T.clean(HERE)
    try:
        os.remove(os.path.join(HERE, "outbox.log"))
    except OSError:
        pass
    T.run(HERE, ["seed.py"], env_extra=ENV)
    proc, base = T.start_server(HERE, env_extra=ENV, port=PORT)

    # Happy path via the scriptable driver: signup -> gate -> verify ->
    # single-use replay -> login -> dashboard. Raises on any failure.
    os.environ["API_BASE"] = BASE
    sys.path.insert(0, HERE)
    import client_example as ce  # noqa: E402
    try:
        ce.main()
        T.check("signup -> verify -> login flow (with gate + single-use link)", True)
    except Exception as e:  # noqa
        T.check("signup -> verify -> login flow (with gate + single-use link)", False, repr(e))

    # --- verification gate: a fresh unverified account cannot log in ---------
    email = f"gate-{secrets.token_hex(4)}@example.com"
    st, _ = ce.signup(email, "another-Strong-Passphrase-99")
    T.check("signup returns check-email page", st == 200)
    st, _, page = ce.login(email, "another-Strong-Passphrase-99")
    T.check("unverified account is blocked at login (the gate)",
            st == 200 and "verify your email" in page.lower())

    # --- no account-enumeration oracle on /signup ---------------------------
    # Signing up an EXISTING address and a brand-new one must be indistinguishable.
    new_email = f"brand-{secrets.token_hex(4)}@example.com"
    _, _, sp = ce._open("GET", base + "/signup")
    st_exist, _, body_exist = ce._open("POST", base + "/signup",
        {"csrf_token": _csrf(sp), "email": SEEDED_EMAIL, "password": "irrelevant-but-long-1234"})
    _, _, sp2 = ce._open("GET", base + "/signup")
    st_new, _, body_new = ce._open("POST", base + "/signup",
        {"csrf_token": _csrf(sp2), "email": new_email, "password": "irrelevant-but-long-1234"})
    # Identical response (status + body) once the echoed address is normalized:
    # nothing in the page distinguishes "already registered" from "brand new".
    same = (st_exist == st_new == 200
            and "check your email" in body_exist.lower()
            and body_exist.replace(SEEDED_EMAIL, "X") == body_new.replace(new_email, "X"))
    T.check("signup does not reveal whether an email is registered", same)

    # --- weak password rejected at signup, no account created ---------------
    _, _, sp3 = ce._open("GET", base + "/signup")
    _, _, body_weak = ce._open("POST", base + "/signup",
        {"csrf_token": _csrf(sp3), "email": "weakpw@example.com", "password": "short"})
    import db  # noqa: E402
    T.check("weak password rejected and no account created at signup",
            "at least 12" in body_weak and db.get_user_by_email("weakpw@example.com") is None)

    # --- unknown / garbage verification token -> 400 ------------------------
    st_bad, _, _ = ce._open("GET", base + "/verify?token=not-a-real-token")
    T.check("unknown verification token -> 400", st_bad == 400, f"status={st_bad}")

    # --- token expiry (exercised at the db layer, deterministically) --------
    import verify  # noqa: E402
    u = db.get_user_by_email(SEEDED_EMAIL)
    tok = verify.generate_token()
    db.create_verification(tok, u["id"], ttl_seconds=-1)   # already expired
    T.check("expired verification token is rejected",
            db.consume_verification(tok) is None)

    # --- the raw token is never stored in the clear -------------------------
    tok2 = verify.generate_token()
    db.create_verification(tok2, u["id"], ttl_seconds=3600)
    conn = db.get_connection()
    stored = [r[0] for r in conn.execute("SELECT token_hash FROM email_verifications").fetchall()]
    conn.close()
    T.check("verification tokens stored hashed, never in clear",
            tok2 not in stored and verify.hash_token(tok2) in stored)

    # --- auth.log records events but never a password -----------------------
    log = ""
    p = os.path.join(HERE, "auth.log")
    if os.path.exists(p):
        log = open(p).read()
    T.check("auth.log records signup/verify and leaks no password",
            "email verified" in log and "signup created" in log
            and "a-Very-Strong-Passphrase-2026" not in log)

    T.finish(proc)


if __name__ == "__main__":
    main()
