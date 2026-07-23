"""test.py — checks for 19-sso-mailbox. Exits nonzero on failure."""
import os
import secrets
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import testlib as T  # noqa: E402

PORT = os.environ.get("TEST_PORT", "5719")
BASE = f"http://127.0.0.1:{PORT}"
ENV = {"SECRET_KEY": secrets.token_hex(32), "OIDC_ISSUER": BASE, "PUBLIC_BASE_URL": BASE}


def main():
    T.clean(HERE)
    T.run(HERE, ["seed.py"], env_extra=ENV)
    proc, base = T.start_server(HERE, env_extra=ENV, port=PORT)
    os.environ.update(ENV)
    os.environ["API_BASE"] = BASE

    # full SSO -> read mailbox (login/consent/id_token/mailbox). Raises on failure.
    sys.path.insert(0, HERE)
    import client_example as ce  # noqa: E402
    try:
        ce.main()
        T.check("SSO login then read mailbox", True)
    except Exception as e:  # noqa
        T.check("SSO login then read mailbox", False, repr(e))

    # the authorization point: mail:read scope gates the mailbox
    import tokens  # noqa: E402
    full, _ = tokens.issue_access_token(1, "mailviewer-app", "openid profile email mail:read")
    idonly, _ = tokens.issue_access_token(1, "mailviewer-app", "openid")
    T.check("mail:read token -> mailbox 200",
            T.get_json(base + "/api/mailbox", headers={"Authorization": f"Bearer {full}"})[0] == 200)
    st, body = T.get_json(base + "/api/mailbox", headers={"Authorization": f"Bearer {idonly}"})
    T.check("token without mail:read -> 403 insufficient_scope",
            st == 403 and body.get("error") == "insufficient_scope", f"{st} {body}")
    T.check("no token -> 401", T.get_json(base + "/api/mailbox")[0] == 401)

    T.finish(proc)


if __name__ == "__main__":
    main()
