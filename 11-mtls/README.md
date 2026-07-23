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
