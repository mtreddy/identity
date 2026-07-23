"""test.py — checks for 15-spiffe. Exits nonzero on failure."""
import os
import ssl
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import testlib as T  # noqa: E402

PORT = os.environ.get("TEST_PORT", "5715")


def main():
    T.clean(HERE)
    T.run(HERE, ["seed.py"])
    proc, base = T.start_server(HERE, port=PORT, scheme="https", ready="tcp")

    os.environ["PORT"] = PORT
    sys.path.insert(0, HERE)
    import client_example as ce  # noqa: E402
    import trust  # noqa: E402

    st, body = ce.call("/x509/whoami", client="billing")
    T.check("X.509-SVID mTLS -> caller identified by SPIFFE ID",
            st == 200 and body["caller"].endswith("/workload/billing"))
    st, body = ce.call("/x509/resources", client="analytics")
    T.check("per-workload isolation", st == 200 and len(body["resources"]) == 1)

    # valid in-domain SVID but no policy grant -> 403
    st, _ = ce.call("/x509/whoami", client="rogue")
    T.check("rogue SVID (no policy grant) -> 403", st == 403, f"status={st}")

    # SVID signed by a CA not in the trust bundle -> handshake refused
    try:
        ce.call("/x509/whoami", client="foreign")
        T.check("foreign-CA SVID -> handshake refused", False, "accepted")
    except (ssl.SSLError, OSError):
        T.check("foreign-CA SVID -> handshake refused", True)

    # JWT-SVID: correct audience works, wrong audience rejected
    billing_id = f"spiffe://{trust.TRUST_DOMAIN}/workload/billing"
    good = trust.issue_jwt_svid(billing_id, audience=ce.SERVER_ID)
    T.check("JWT-SVID correct audience -> 200", ce.call("/jwt/whoami", bearer=good)[0] == 200)
    wrong = trust.issue_jwt_svid(billing_id, audience=f"spiffe://{trust.TRUST_DOMAIN}/other")
    T.check("JWT-SVID wrong audience -> 401", ce.call("/jwt/whoami", bearer=wrong)[0] == 401)

    T.finish(proc)


if __name__ == "__main__":
    main()
