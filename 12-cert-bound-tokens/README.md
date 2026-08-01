# 12 — Certificate-bound access tokens (RFC 8705)

The capstone: **mTLS (11) + JWT (07)**. It fixes the biggest weakness of a
bearer token — that *anyone* who holds it can use it. Here the token is
**sender-constrained**: it only works for the client whose certificate it was
issued to.

```bash
diff -ru ../11-mtls ./ | less
```

- The client authenticates to the token endpoint over **mTLS** and receives a
  JWT carrying `cnf: {"x5t#S256": <its cert thumbprint>}`.
- On every resource call the client presents the token **and** (over mTLS) its
  certificate; the server checks the presented cert's thumbprint equals the
  token's `cnf`.
- A token stolen from a log, proxy, or SSRF is useless without the matching
  **private key** — which never leaves the legitimate client.

## Files (vs 11)

| File | Change |
|------|--------|
| `tokens.py` | **new** — issue/verify JWT with the `cnf.x5t#S256` binding claim |
| `pki.py` | adds `x5t_s256` (base64url SHA-256 of the DER cert) |
| `db.py` | `clients` gains `scopes` + `get_client_scopes` |
| `app.py` | `/v1/token` (mTLS-authenticated, cert-bound) + binding check on resource routes |
| `client_example.py` | full demo incl. a **stolen-token replay** that gets rejected |

## Run it

```bash
cd 12-cert-bound-tokens
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export JWT_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python seed.py           # builds certs/ (CA, server, per-agent client certs)
python app.py            # HTTPS on 127.0.0.1:5000, client cert REQUIRED

# in another shell:
python client_example.py
```

By hand (note every call is mTLS):

```bash
D=certs; C="--cacert $D/ca.crt --cert $D/billing-agent.crt --key $D/billing-agent.key"
TOKEN=$(curl -s $C -X POST https://127.0.0.1:5000/v1/token | python -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

# same cert that got the token -> works
curl -s $C -H "Authorization: Bearer $TOKEN" https://127.0.0.1:5000/v1/resources

# a DIFFERENT client cert with the stolen token -> 401 (not bound to this cert)
curl -s --cacert $D/ca.crt --cert $D/analytics-agent.crt --key $D/analytics-agent.key \
     -H "Authorization: Bearer $TOKEN" https://127.0.0.1:5000/v1/resources
```

## How the binding works

1. **Issue** (`/v1/token`): the client authenticates with its cert (mTLS). We
   compute `x5t#S256 = base64url(SHA-256(client cert DER))` and embed it in the
   token's `cnf` (confirmation) claim (RFC 7800 / 8705).
2. **Use** (`require_bound_token`): after verifying the JWT signature/`exp`, we
   compute the thumbprint of the certificate presented on *this* connection and
   require it to equal the token's `cnf.x5t#S256`. Mismatch → `401`.
3. **Revocation still applies**: because the cert is presented on every call,
   revoking it (mechanism 11's fingerprint allow-list) also kills every token
   bound to it — checked as defense in depth.

## Flow — how the communication starts and finishes

This fuses `../11-mtls` and `../07-jwt`: **every** connection is mTLS (as in 11),
but now the client first swaps its cert-authenticated session for a JWT that is
**bound to that cert**. The token carries `cnf.x5t#S256` = the SHA-256 thumbprint
of the client's certificate. On each resource call the server recomputes the
thumbprint of the cert on *this* connection and requires it to equal the token's
`cnf` — so a stolen token is inert without the matching private key.

```
 ┌─────────┐                    ┌──────────────────────┐          ┌────────┐
 │ Client  │                    │ mTLS API (app.py)    │          │identity│
 │ +cert+key                    │  127.0.0.1:5000      │          │  .db   │
 └────┬────┘                    └──────────┬───────────┘          └───┬────┘
      │                                    │                          │
 ═════╪═ ISSUE: mTLS → cert-bound JWT ═════════════════════════════════════
      │ mTLS handshake (client cert verified vs CA) ◄══════════════►│
      │ POST /v1/token  (NO header — authed by the cert) ─────────► │
      │                                    │ read peer cert; fp check ►│ active?
      │                                    │ x5t#S256 = base64url(
      │                                    │   SHA-256(cert DER))
      │                                    │ issue_token(): JWT with
      │                                    │   cnf={"x5t#S256": <fp>}, scope, exp
      │◄─ 200 {access_token: eyJ…(cnf=fpA), token_type:"Bearer"} ──│

 ═════╪═ USE: token + SAME cert (proof of possession) ═══════════════════════
      │ mTLS handshake (cert A again) ◄════════════════════════════►│
      │ GET /v1/resources                  │                        │
      │ Authorization: Bearer eyJ…(cnf=fpA) ─────────────────────► │
      │                                    │ verify JWT sig + exp    │
      │                                    │ thumbprint(THIS conn's cert)
      │                                    │   == token cnf.x5t#S256 ?
      │                                    │   ✔ match (fpA==fpA) ↓  │
      │                                    │ (fp still registered/not revoked?)►│
      │◄─ 200 {resources:[…]} ─────────────│                        │

 ═════╪═ ATTACK: stolen token replayed from another client ════════════════
      │ (attacker holds eyJ…(cnf=fpA) but only cert B + its key)    │
      │ mTLS handshake (cert B) ◄══════════════════════════════════►│
      │ GET /v1/resources  Bearer eyJ…(cnf=fpA) ─────────────────► │
      │                                    │ thumbprint(cert B)=fpB  │
      │                                    │   fpB ≠ cnf fpA →        │
      │◄─ 401 (token not bound to this cert)│  proof-of-possession fails
      │                                    │                          │
      ▼                                    ▼                          ▼
  useless without cert A's       "finish": token expires (exp), OR revoke the
  private key                     cert → every token bound to it dies too
```

The takeaway over plain bearer tokens (07/08): presenting the token is **not
enough** — the caller must *also* prove possession of the private key behind the
bound cert on the very same connection. A token exported from a log, proxy, or
SSRF is dead on arrival from any other client. DPoP (`../13-dpop`) achieves the
same proof-of-possession without needing mTLS end-to-end.

## Why this matters

| | Plain bearer token (07/08) | Certificate-bound token (here) |
|--|--|--|
| Stolen from a log / proxy | fully usable by the thief | **useless** without the private key |
| Bound to the caller | no | yes (`cnf` = client cert) |
| Extra requirement | — | client must use mTLS on each call |

This is "proof-of-possession": presenting the token isn't enough; the caller
must also prove possession of the key behind the bound certificate. DPoP
(RFC 9449) achieves the same goal without mTLS, using a per-request signature.

## Threats addressed (beyond 07/08 and 11)
- **Token export / replay:** a leaked access token can't be used from any other
  client — the `cnf`/cert check fails.
- **Token injection via a compromised proxy/SSRF:** same — the attacker lacks
  the bound cert's key.
- **(from 11) unknown/forged clients & server impersonation:** mutual TLS.
- **(from 11) compromised cert:** revoke the fingerprint → bound tokens die too.

## Limitations / further hardening
RS256/JWKS signing (mechanism 10) so verifiers hold no secret; short token TTL +
refresh (mechanism 08) with the binding preserved across refresh; standard
`WWW-Authenticate` challenges; automated cert issuance/rotation (SPIFFE/SPIRE);
consider DPoP where mTLS isn't available end-to-end.
