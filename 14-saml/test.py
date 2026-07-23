"""test.py — checks for 14-saml. Exits nonzero on failure."""
import os
import re
import secrets
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import testlib as T  # noqa: E402

PORT = os.environ.get("TEST_PORT", "5714")
BASE = f"http://127.0.0.1:{PORT}"
ENV = {"SECRET_KEY": secrets.token_hex(32)}


def main():
    T.clean(HERE)
    T.run(HERE, ["seed.py"], env_extra=ENV)
    proc, base = T.start_server(HERE, env_extra=ENV, port=PORT)

    # HTTP happy path via the browser-flow driver
    os.environ["API_BASE"] = BASE
    sys.path.insert(0, HERE)
    import client_example as ce  # noqa: E402
    op = ce._opener()
    acs, resp = ce.run_flow(op)
    st, _, page = ce._open(op, "POST", acs, {"SAMLResponse": resp, "RelayState": "/sp/"})
    who = re.search(r"<strong>(.*?)</strong>", page)
    T.check("SP-initiated SSO signs the user in",
            st == 200 and who and "Ada" in who.group(1), f"status={st}")

    # validator-level security checks (pure functions; no server needed)
    import idp_keys  # noqa: E402
    import saml  # noqa: E402
    common = dict(idp_entity_id="idp", sp_entity_id="sp-A", acs_url="https://sp/acs",
                  user={"email": "user@example.com", "name": "Ada"},
                  key_pem=idp_keys.PRIVATE_PEM, cert_pem=idp_keys.CERT_PEM)

    def make(irt="req-1", validity=300):
        return saml.build_signed_response(in_response_to=irt, validity_seconds=validity, **common)

    def validate(xml, sp="sp-A", acs="https://sp/acs", irt="req-1", seen=None):
        return saml.validate_response(xml=xml, idp_cert_pem=idp_keys.CERT_PEM,
            sp_entity_id=sp, acs_url=acs, expected_in_response_to=irt,
            seen_assertion_ids=seen if seen is not None else set())

    def rejected(fn):
        try:
            fn(); return False
        except saml.SamlError:
            return True

    T.check("valid assertion accepted", validate(make())["nameid"] == "user@example.com")
    T.check("tampered assertion rejected",
            rejected(lambda: validate(make().replace("user@example.com", "attacker@evil.com", 1))))
    T.check("wrong audience rejected", rejected(lambda: validate(make(), sp="sp-B")))
    T.check("InResponseTo mismatch rejected", rejected(lambda: validate(make(), irt="other")))
    T.check("wrong recipient rejected", rejected(lambda: validate(make(), acs="https://evil/acs")))
    T.check("expired assertion rejected", rejected(lambda: validate(make(validity=-30))))
    seen = set()
    x = make(irt="rr")
    validate(x, irt="rr", seen=seen)
    T.check("replayed assertion rejected", rejected(lambda: validate(x, irt="rr", seen=seen)))
    nosig = re.sub(r"<(ds:)?Signature.*?</(ds:)?Signature>", "", make(), flags=re.S)
    T.check("assertion without signature rejected", rejected(lambda: validate(nosig)))

    T.finish(proc)


if __name__ == "__main__":
    main()
