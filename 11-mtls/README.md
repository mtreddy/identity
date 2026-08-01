# 11 — mTLS (mutual TLS client-certificate auth)

The certificate-based counterpart to the bearer-token machine flows (06–08).
Instead of sending a secret on every request, the client authenticates during
the **TLS handshake** with an X.509 **client certificate** signed by a trusted
CA. There is **no `Authorization` header** — identity lives in the transport.

- **Trust root:** a self-contained CA (`pki.py`) issues the server cert and one
  client cert per machine/agent (CN = the identity)
- **Server:** requires a client cert (`ssl.CERT_REQUIRED`); the handshake itself
  gates every request
- **Identity:** derived from the verified client cert (Subject CN + SHA-256
  fingerprint), then authorized against the DB

## Files

| File | Role |
|------|------|
| `pki.py` | Tiny X.509 CA: create CA, issue server/client certs, fingerprints |
| `db.py` | `clients` (name = CN), `client_certs` (fingerprint, revocable), `resources` |
| `app.py` | TLS server requiring client certs; extracts the peer cert → identity |
| `seed.py` | Builds the PKI under `certs/` and registers clients + resources |
| `client_example.py` | Calls the API with a client cert (and shows a no-cert failure) |

## Run it

```bash
cd 11-mtls
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python seed.py           # creates certs/ (CA, server, per-agent client certs)
python app.py            # HTTPS on 127.0.0.1:5000, client cert REQUIRED
```

In another shell — note every call must present a client cert:

```bash
curl --cacert certs/ca.crt \
     --cert certs/billing-agent.crt --key certs/billing-agent.key \
     https://127.0.0.1:5000/v1/whoami

# no client cert -> the handshake is refused:
curl --cacert certs/ca.crt https://127.0.0.1:5000/v1/whoami   # fails

# or drive it:
python client_example.py billing-agent
```

## How mTLS authenticates

1. **Handshake (transport layer).** The server presents its cert (client
   verifies it against the CA + hostname). The server demands a client cert and
   verifies it chains to the **same CA**. No CA-signed client cert → **no
   connection** — the request never reaches the app. This is the "mutual" part:
   both sides prove themselves with certificates.
2. **Identity (application layer).** `app.py` reads the peer certificate off the
   socket, takes its **Subject CN** as the identity and its **SHA-256
   fingerprint** as the exact-cert id, and calls `db.authenticate` to map it to
   an active, non-revoked client.
3. **Authorization.** The route serves only that client's resources.

Two layers of trust: *CA-signed* (handshake) **and** *registered &
not-revoked fingerprint* (DB). A cert we didn't issue for that client, or one
we've revoked, is rejected even though it chains to the CA.

## Flow — how the communication starts and finishes

The defining difference from 06–08: there is **no `Authorization` header**.
Identity is established during the **TLS handshake** — if the client can't
present a CA-signed certificate, the connection is refused and the request never
reaches Flask. The app then reads the *already-verified* peer cert off the
socket and maps its fingerprint to a client. The exchange **finishes** when the
connection closes; there is nothing to log out or expire.

```
 ┌─────────┐                     ┌─────────────────────┐          ┌────────┐
 │ Client  │                     │ mTLS server (app.py)│          │identity│
 │ +cert+key                     │   127.0.0.1:5000    │          │  .db   │
 └────┬────┘                     └──────────┬──────────┘          └───┬────┘
      │                                     │                         │
 ═════╪═ START: MUTUAL TLS HANDSHAKE (auth happens HERE) ═══════════════════
      │                                     │                         │
      │ ClientHello ───────────────────────►│                         │
      │◄─ server cert ─────────────────────│  client verifies server │
      │  (client checks it chains to CA)    │  cert vs CA + hostname  │
      │◄─ CertificateRequest (CERT_REQUIRED)│                         │
      │ client cert + proof-of-private-key ►│ verify chains to SAME CA│
      │                                     │  ✘ no/again-bad cert →  │
      │                                     │    HANDSHAKE FAILS      │
      │                                     │    (never reaches app)  │
      │◄════════ secure channel established ═│                         │
      │                                     │                         │
 ═════╪═ APPLICATION: identity from the verified cert ═════════════════════
      │ GET /v1/whoami  (NO Authorization header) ─────────────────► │
      │                                     │ read peer cert off socket
      │                                     │ CN = identity; SHA-256 fp
      │                                     │ authenticate(fp): registered
      │                                     │  AND revoked=0 AND active=1 ──►│
      │                                     │◄──── client row / None ────────│
      │                                     │  ✘ unknown/revoked fp → 401
      │◄─ 200 {client, resources} ──────────│  ✔ serve only its data
      │                                     │                         │
 ═════╪═ "FINISH": connection close / revocation ══════════════════════════
      │ revoke_cert(fp) ────────────────────────────────────────────►│ revoked=1
      │  → that exact cert fails on its NEXT request (allow-list flip)│
      ▼                                     ▼                         ▼
  no header ever sent          identity lived in the transport, not a token
```

The key property: the client proves possession of a **private key**, not a
copyable string. A leaked request or log holds nothing replayable — the strength
over bearer tokens (06–08). Revocation is an allow-list flip on the fingerprint,
standing in for CRL/OCSP.

## Revocation without CRL/OCSP
Real PKI revocation uses CRLs or OCSP. For a self-contained demo we keep an
allow-list of issued client-cert fingerprints with a `revoked` flag
(`db.revoke_cert`): flip it and that exact certificate stops working on the
next request — immediate, no extra infrastructure.

## mTLS vs. bearer tokens (06–08)

| | Bearer token (API key/JWT) | mTLS client cert |
|--|--|--|
| Secret on every request | yes (token in header) | no (proven in handshake) |
| Bound to the connection | no (token is bearer — stealable/replayable) | yes (needs the private key) |
| Where identity lives | app layer | transport layer |
| Infra cost | low | PKI: issuance, rotation, revocation |
| Great for | public/varied clients, browsers | service-to-service / zero-trust meshes |

Because the client must hold the **private key** (not just a copyable string),
a leaked request or log can't be replayed — a key strength over bearer tokens.

## Threats addressed
- **Credential theft/replay:** possession of a private key is required; nothing
  reusable is transmitted.
- **Unknown/forged clients:** only certs signed by our CA complete the handshake.
- **Compromised cert:** revoke its fingerprint → immediate rejection.
- **Server impersonation:** the client verifies the server cert too (mutual).

## Limitations / further hardening
Automated issuance & short-lived certs (SPIFFE/SPIRE, service mesh sidecars);
real revocation (CRL/OCSP stapling); cert rotation without downtime; constrain
EKU/name constraints on the CA; protect the CA key in an HSM; bind app-layer
tokens to the client cert (RFC 8705 certificate-bound access tokens) to combine
mTLS with 07/08.
