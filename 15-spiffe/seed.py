"""
seed.py — mint X.509-SVIDs for the demo workloads and write the trust bundle.

Run once:  python seed.py

Creates (under svids/):
  * bundle_ca.pem / bundle_jwks.json   the trust bundle relying parties verify against
  * server.pem / server_key.pem        the API server workload's X.509-SVID
  * billing.pem, analytics.pem         authorized caller workloads
  * rogue.pem                          a VALID in-domain SVID that policy doesn't allow
  * foreign.pem                        an SVID from a DIFFERENT (untrusted) CA

The JWT-SVID is short-lived and minted on demand (client_example does this,
standing in for the SPIFFE Workload API).
"""

import json
import os
from pathlib import Path

import spiffe
import trust

DIR = Path(os.environ.get("SVID_DIR", Path(__file__).parent / "svids"))

# SPIFFE path -> local filename stem for the SVID
WORKLOADS = {
    "workload/api-server": "server",
    "workload/billing": "billing",
    "workload/analytics": "analytics",
    "workload/rogue": "rogue",
}


def _save(name, cert, key):
    DIR.joinpath(f"{name}.pem").write_bytes(spiffe.cert_pem(cert))
    DIR.joinpath(f"{name}_key.pem").write_bytes(spiffe.key_pem(key))


def main():
    DIR.mkdir(exist_ok=True)

    # Trust bundle (what verifiers use).
    DIR.joinpath("bundle_ca.pem").write_bytes(trust.bundle_ca_pem())
    DIR.joinpath("bundle_jwks.json").write_text(json.dumps(trust.jwks(), indent=2))

    print(f"trust domain: {trust.TRUST_DOMAIN}\n")
    print("Issued X.509-SVIDs (SPIFFE ID in the URI SAN):")
    for path, filename in WORKLOADS.items():
        sid = trust.spiffe_id(path)
        cert, key = trust.issue_x509_svid(sid)
        _save(filename, cert, key)
        print(f"  {sid}  -> svids/{filename}.pem")

    # A workload whose SVID was signed by a DIFFERENT CA (not in our bundle).
    foreign_ca, foreign_key = spiffe.create_ca("evil.example")
    fsid = trust.spiffe_id("workload/imposter")   # spoofs our domain in the ID…
    fcert, fkey = spiffe.issue_x509_svid(foreign_ca, foreign_key, fsid)
    _save("foreign", fcert, fkey)
    print(f"  {fsid}  (signed by a FOREIGN CA — should be rejected)")

    print("\nStart the server:  python app.py")
    print("Then:  python client_example.py")


if __name__ == "__main__":
    main()
