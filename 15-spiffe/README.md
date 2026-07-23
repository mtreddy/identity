# 15 — SPIFFE / SVID (workload identity)

Identity for **workloads** (services, not humans). Each workload gets a URI
identity — a **SPIFFE ID** — delivered as a verifiable document (**SVID**) and
checked against a **trust bundle**. This is what a service mesh / zero-trust
network uses to let services authenticate each other automatically.

```
SPIFFE ID:  spiffe://example.org/workload/billing
             └─scheme─┘ └trust domain┘ └── path ──┘
```

Two SVID forms (both here):

| SVID | What it is | Used for |
|------|-----------|----------|
| **X.509-SVID** | an X.509 cert with the SPIFFE ID in its **URI SAN** (Subject is empty) | workload **mTLS** |
| **JWT-SVID** | a JWT with `sub` = SPIFFE ID, `aud` = the recipient | calls where mTLS isn't end-to-end |

Relative to mechanism 11 (mTLS by CN), the SPIFFE difference is: identity is a
**SPIFFE ID in the URI SAN** (never the CN or a hostname), verified against a
**trust bundle** and authorized by a **SPIFFE-ID policy**.

## Files

| File | Role |
|------|------|
| `spiffe.py` | SPIFFE primitives: build/read X.509-SVID (URI SAN), issue/verify JWT-SVID, SPIFFE-ID helpers |
| `trust.py` | the trust domain's issuer (a tiny SPIRE-server stand-in): CA + JWT key, issuance, and the **trust bundle** (CA PEM + JWKS) |
| `seed.py` | mints workload SVIDs into `svids/` + writes the bundle (incl. a rogue and a foreign-CA SVID) |
| `app.py` | server workload: X.509-SVID mTLS routes + a JWT-SVID route, authorized by SPIFFE ID |
| `client_example.py` | calls as different workloads; verifies the **server** by its SPIFFE ID |

## Run it

```bash
cd 15-spiffe
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python seed.py           # mints SVIDs + trust bundle into svids/
python app.py            # HTTPS on 127.0.0.1:5000 (mTLS optional)

# in another shell:
python client_example.py
```

## How authentication + authorization work

- **Server identity:** the server holds an X.509-SVID; clients verify its cert
  chains to the bundle CA and then check its **SPIFFE ID** (not the hostname —
  SVIDs carry no DNS/IP SAN).
- **X.509-SVID (mTLS):** the client presents its SVID; the server verifies the
  chain (bundle CA), reads the **SPIFFE ID from the URI SAN**, checks the trust
  domain, and applies a **SPIFFE-ID allow-list** policy.
- **JWT-SVID:** the client sends `Authorization: Bearer <jwt-svid>`; the server
  verifies the signature via the bundle **JWKS** (by `kid`) and requires
  `aud` == the server's own SPIFFE ID, then applies the same policy.

## Threats addressed
| Threat | Defense |
|--------|---------|
| Forged/foreign workload cert | must chain to the **trust bundle** CA (handshake fails otherwise) |
| SPIFFE-ID spoofing via a rogue CA | the ID lives in a **CA-signed** URI SAN — an untrusted CA is rejected |
| Over-broad access | authorization is a **SPIFFE-ID policy**, not "any valid cert" |
| Server impersonation | client verifies the **server's SPIFFE ID** |
| JWT-SVID replay to another service | `aud` must equal the target's SPIFFE ID |

## Notes & further hardening
Real SPIFFE uses **SPIRE** (Server + node/workload **attestation**, the Workload
API, automatic short-TTL SVID rotation) — here `client_example.py` mints its own
JWT-SVID as a stand-in for the Workload API. Production: rotate X.509-SVIDs
frequently, federate trust bundles across domains, and pin selectors/attestation
so a workload can only obtain its own SVID.
