"""test.py — checks for 12-cert-bound-tokens. Exits nonzero on failure."""
import os
import secrets
import sys
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import testlib as T  # noqa: E402

PORT = os.environ.get("TEST_PORT", "5712")
ENV = {"JWT_SECRET": secrets.token_hex(32)}


def main():
    T.clean(HERE)
    T.run(HERE, ["seed.py"], env_extra=ENV)
    proc, base = T.start_server(HERE, env_extra=ENV, port=PORT, scheme="https", ready="tcp")

    os.environ.update(ENV)
    os.environ["PORT"] = PORT
    sys.path.insert(0, HERE)
    import client_example as ce  # noqa: E402
    import jwt  # noqa: E402
    import pki  # noqa: E402
    D = Path(HERE) / "certs"

    # get a cert-bound token for billing; its cnf.jkt matches billing's cert
    st, tok = ce.req("billing-agent", "POST", "/v1/token")
    claims = jwt.decode(tok["access_token"], options={"verify_signature": False})
    cert_thumb = pki.x5t_s256(pki.load_cert(D / "billing-agent.crt"))
    T.check("token bound to cert (cnf.x5t#S256 matches)",
            st == 200 and claims["cnf"]["x5t#S256"] == cert_thumb)
    billing_token = tok["access_token"]

    # same cert that got the token -> works
    T.check("token + its own cert works",
            ce.req("billing-agent", "GET", "/v1/resources", billing_token)[0] == 200)

    # THE property: stolen token replayed with a DIFFERENT client's cert -> 401
    st, body = ce.req("analytics-agent", "GET", "/v1/resources", billing_token)
    T.check("stolen token + different cert -> 401 (not bound)", st == 401, f"{st} {body}")

    # control: analytics uses its own cert-bound token
    _, tok2 = ce.req("analytics-agent", "POST", "/v1/token")
    T.check("analytics token + analytics cert works",
            ce.req("analytics-agent", "GET", "/v1/resources", tok2["access_token"])[0] == 200)

    # revoking the cert also kills its bound token (cert presented every call)
    import db  # noqa: E402
    db.revoke_cert(pki.fingerprint(pki.load_cert(D / "billing-agent.crt")))
    T.check("revoked cert -> bound token 403",
            ce.req("billing-agent", "GET", "/v1/resources", billing_token)[0] == 403)

    T.finish(proc)


if __name__ == "__main__":
    main()
