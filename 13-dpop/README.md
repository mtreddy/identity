# 13 — DPoP: sender-constrained tokens without mTLS (RFC 9449)

The application-layer sibling of mechanism 12. Both make an access token
**sender-constrained** — bound to a key so a stolen token can't be replayed —
but DPoP needs **no client certificates and no mTLS**. The client holds its own
keypair and signs a fresh **DPoP proof** on every request.

- **Client key:** the client generates an EC (P-256/ES256) keypair.
- **DPoP proof:** a short-lived JWT in the `DPoP:` header, signed by the client,
  naming the HTTP method (`htm`), URL (`htu`), a unique `jti`, `iat`, and (on API
  calls) `ath` = a hash of the access token. Its header carries the public `jwk`.
- **Binding:** the access token carries `cnf: {"jkt": <RFC 7638 thumbprint>}`.
- **Check:** the resource server validates the proof and requires
  `token.cnf.jkt == thumbprint(proof.jwk)`.

## Files

| File | Role |
|------|------|
| `dpop.py` | DPoP proof create/verify + RFC 7638 JWK thumbprint + `jti` replay cache |
| `tokens.py` | HS256 access token with `cnf.jkt` binding |
| `keys.py`, `db.py` | API-key auth for the token endpoint (reused from 06/07) |
| `app.py` | `/v1/token` (API key + proof → bound token); resource routes verify proof + binding |
| `seed.py` | sample clients, API keys (printed once), resources |
| `client_example.py` | client keypair + proofs; full flow and the replay/theft demos |

## Run it

```bash
cd 13-dpop
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export JWT_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python seed.py           # prints API keys once — copy one
python app.py            # http://127.0.0.1:5000

# in another shell:
API_KEY=sk_live_... python client_example.py
```

## How a request is authorized

1. **Get a token** (`POST /v1/token`): the client authenticates with its API key
   (`X-API-Key`) and sends a DPoP proof (`htm=POST`, `htu` = the token URL). The
   server verifies the proof, computes the key thumbprint `jkt`, and issues a
   token with `cnf.jkt`.
2. **Call the API** (`Authorization: DPoP <token>` + a fresh `DPoP` proof): the
   server verifies the token, then the proof — signature (via the embedded
   `jwk`), `htm`/`htu` match this request, `iat` is fresh, `jti` is unseen, and
   `ath` matches the token. Finally it requires `cnf.jkt == thumbprint(jwk)`.

The proof key is validated against itself (the `jwk` in its header) — which is
safe because we then require that key to be the one the token was *issued* to.

## Flow — how the communication starts and finishes

Same sender-constrained goal as `../12-cert-bound-tokens`, but with **no mTLS and
no certificates**. The client owns an EC keypair and signs a fresh **DPoP proof**
(a tiny JWT in the `DPoP:` header) on *every* request. The access token is bound
to that key via `cnf.jkt` (the RFC 7638 thumbprint of the public JWK). The server
requires `cnf.jkt == thumbprint(proof.jwk)` — so the token is useless to anyone
who can't sign a matching proof.

```
 ┌─────────┐                    ┌──────────────────────┐          ┌────────┐
 │ Client  │                    │  Flask API (app.py)  │          │identity│
 │ +EC key │                    │   127.0.0.1:5000     │          │  .db   │
 └────┬────┘                    └──────────┬───────────┘          └───┬────┘
      │  (deploy behind TLS; DPoP stops export/replay, not eavesdropping)
 ═════╪═ ISSUE: API key + DPoP proof → key-bound token ══════════════════════
      │ POST /v1/token                     │                          │
      │ X-API-Key: sk_live_…               │                          │
      │ DPoP: proof{htm:POST, htu:/v1/token, jti, iat, jwk:PUB} ────► │
      │                                    │ authenticate(api key) ──►│
      │                                    │ verify proof: sig via jwk,
      │                                    │  htm/htu match, iat fresh,
      │                                    │  jti unseen
      │                                    │ jkt = thumbprint(jwk)     │
      │                                    │ issue_token(): cnf={"jkt":jktA}
      │◄─ 200 {access_token: eyJ…(cnf=jktA), token_type:"DPoP"} ─────│

 ═════╪═ USE: token + a FRESH proof per call ═════════════════════════════════
      │ GET /v1/resources                  │                          │
      │ Authorization: DPoP eyJ…(cnf=jktA) │                          │
      │ DPoP: proof{htm:GET, htu:/v1/resources, jti', iat',           │
      │            ath:hash(access_token), jwk:PUB} ───────────────► │
      │                                    │ verify token (sig+exp)   │
      │                                    │ verify proof: sig, htm/htu,
      │                                    │  iat fresh, jti' unseen,  │
      │                                    │  ath == hash(token)       │
      │                                    │ REQUIRE cnf.jkt==thumbprint(jwk)?
      │                                    │  ✔ jktA==jktA ↓          │
      │◄─ 200 {resources:[…]} ─────────────│                          │

 ═════╪═ ATTACKS (all → 401) ══════════════════════════════════════════════
      │ stolen token + attacker's OWN key → proof jkt=jktB ≠ cnf jktA → 401
      │ replayed proof (same jti already seen)               → 401
      │ proof aimed at a different URL (htu mismatch)         → 401
      │ token with no proof at all                           → 401
      ▼                                    ▼                          ▼
  can't forge a proof for       "finish": token expires (exp); no logout —
  a key it doesn't hold          each request re-proves possession afresh
```

Versus 12: the binding is to a **key the client generated**, not a CA-issued
cert, so there's no PKI and it works even over plain HTTP\* — the trade is a
signed proof JWT on every single request instead of a TLS handshake carrying the
cert. \*Still run TLS in production to protect the token/proofs on the wire.

## Threats addressed
- **Token theft / replay:** a leaked access token is useless — the attacker
  can't produce a proof signed by the bound key (they lack the private key), and
  their own key yields a different `jkt` → `401`.
- **Proof replay:** each proof has a unique `jti`; the server rejects reuse
  (in-memory cache here; a shared TTL store in production).
- **Proof relay to another endpoint:** `htm`/`htu` pin the proof to one
  method+URL; `ath` pins it to one access token.
- **Stale proofs:** `iat` must be within a short window.

## DPoP (13) vs. mTLS cert-binding (12)

| | Certificate-bound (12) | DPoP (13) |
|--|--|--|
| Binds token to | client **certificate** | client **key** (any keypair) |
| Requires mTLS | yes (client certs, a CA) | **no** (works over plain HTTP*) |
| Per-request cost | TLS handshake presents the cert | sign + verify a small JWT |
| Proof of possession | TLS handshake | a signed proof JWT per request |
| Good when | you already run mTLS / a service mesh | public clients, SPAs, no client-cert infra |

\* Still deploy behind TLS in production to protect the token and proofs on the
wire — DPoP defends against token *export/replay*, not eavesdropping.

## Limitations / further hardening
RS256/JWKS for the access token (mechanism 10); refresh tokens (08) with the
binding carried across refresh; a shared `jti` store with TTL; server-provided
DPoP nonce (`DPoP-Nonce`) to bound proof pre-generation; accept a small set of
`htu` forms behind proxies.
