"""test.py — checks for 11-mtls. Exits nonzero on failure."""
import os
import ssl
import sys
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import testlib as T  # noqa: E402

PORT = os.environ.get("TEST_PORT", "5711")


def main():
    T.clean(HERE)
    T.run(HERE, ["seed.py"])
    proc, base = T.start_server(HERE, port=PORT, scheme="https", ready="tcp")

    os.environ["PORT"] = PORT
    os.environ["SERVER_HOST"] = "127.0.0.1"
    sys.path.insert(0, HERE)
    import client_example as ce  # noqa: E402
    import db  # noqa: E402
    import pki  # noqa: E402
    D = Path(HERE) / "certs"

    def cert(agent):
        return D / f"{agent}.crt", D / f"{agent}.key"

    st, body = ce.call("/v1/whoami", *cert("billing-agent"))
    T.check("client cert -> whoami 200", st == 200 and body["name"] == "billing-agent")
    st, body = ce.call("/v1/resources", *cert("analytics-agent"))
    T.check("per-client isolation", st == 200 and len(body["resources"]) == 1)

    # no client certificate -> handshake refused
    try:
        ce.call("/v1/whoami")
        T.check("no client cert -> handshake refused", False, "accepted")
    except (ssl.SSLError, OSError):
        T.check("no client cert -> handshake refused", True)

    # certificate from an untrusted CA -> handshake refused
    rca_c, rca_k = pki.create_ca("rogue CA")
    rc, rk = pki.issue_cert(rca_c, rca_k, "billing-agent", server=False)
    pki.save_cert(D / "rogue.crt", rc)
    pki.save_key(D / "rogue.key", rk)
    try:
        ce.call("/v1/whoami", D / "rogue.crt", D / "rogue.key")
        T.check("untrusted-CA cert -> handshake refused", False, "accepted")
    except (ssl.SSLError, OSError):
        T.check("untrusted-CA cert -> handshake refused", True)

    # revocation: revoke billing's cert fingerprint -> 403; analytics still 200
    fp = pki.fingerprint(pki.load_cert(D / "billing-agent.crt"))
    db.revoke_cert(fp)
    T.check("revoked cert -> 403", ce.call("/v1/whoami", *cert("billing-agent"))[0] == 403)
    T.check("other client unaffected", ce.call("/v1/whoami", *cert("analytics-agent"))[0] == 200)

    T.finish(proc)


if __name__ == "__main__":
    main()
