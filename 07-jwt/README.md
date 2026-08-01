# 07 — JWT access tokens (machine / agent authentication)

Builds on [`../06-api-keys`](../06-api-keys/). Instead of sending a long-lived
API key on every request, the client uses its key **once** to obtain a
**short-lived, signed JWT** and sends that token thereafter. The API verifies
the token **statelessly** — signature + expiry + audience + issuer + scope — with
no database lookup per request. This is the OAuth2 *client-credentials* pattern.

```bash
diff -ru ../06-api-keys ./ | less
```

- **Credential exchange:** `POST /v1/token` with `Authorization: Bearer <api_key>`
- **Access token:** a JWT (HS256) with `sub`, `scope`, `exp`, `aud`, `iss`
- **Signing:** shared secret from `JWT_SECRET` (env)

## Files (vs. 06)

| File | Change |
|------|--------|
| `tokens.py` | **new** — `issue_token` / `verify_token` (PyJWT), algorithm pinned |
| `db.py` | `clients` gains a `scopes` column + `get_client_scopes` |
| `app.py` | `/v1/token` (API-key gated) issues JWTs; resources now JWT+scope gated |
| `seed.py` | clients get scopes (billing: `resources:read admin`, analytics: `resources:read`) |
| `client_example.py` | full flow: key → token → calls → scope 403 → bad-token 401 |
| `requirements.txt` | adds `PyJWT` |

## Run it

```bash
cd 07-jwt
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export JWT_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python seed.py            # prints API keys once — copy one
python app.py            # http://127.0.0.1:5000
```

In another shell:

```bash
KEY=sk_live_...          # a key from seed.py

# 1) exchange the API key for a JWT
TOKEN=$(curl -s -X POST -H "Authorization: Bearer $KEY" \
        http://127.0.0.1:5000/v1/token \
        | python -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

# 2) call the API with the JWT
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:5000/v1/whoami
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:5000/v1/resources

# or drive the whole flow:
API_KEY=$KEY python client_example.py
```

## How verification works (and why it's safe)

`tokens.verify_token` calls `jwt.decode(..., algorithms=["HS256"], audience=…,
issuer=…)`:

- **Signature** proves the token was minted by us and not modified.
- **Algorithm is pinned** to `HS256` — this blocks the classic `alg: none`
  forgery and HS/RS confusion attacks (never trust the algorithm named in the
  token header).
- **`aud` / `iss`** are checked so a token minted for a different service or
  purpose can't be replayed here.
- **`exp`** bounds the token's lifetime (15 min by default; set `TOKEN_TTL`).
- **`scope`** is enforced per route (`@require_jwt(scope="…")`) for least
  privilege — `analytics-agent` gets **403** on `/v1/admin/stats`.

## Flow — how the communication starts and finishes

The shift from `../06-api-keys` is a **two-phase** exchange. The long-lived API
key is presented **once** to a token endpoint (`/v1/token`) — the only DB-backed
step — and swapped for a **short-lived signed JWT**. Every subsequent call
carries that JWT, and the API verifies it **statelessly**: signature + `alg`
pin + `aud`/`iss` + `exp` + `scope`, with **no database lookup**. It all rides
over TLS because both the key and the token are bearer secrets.

```
 ┌─────────┐              ┌─────────────────────┐            ┌────────┐
 │ Client  │              │  Flask API (app.py) │            │identity│
 │(has key)│              │   127.0.0.1:5000    │            │  .db   │
 └────┬────┘              └──────────┬──────────┘            └───┬────┘
      │                              │                           │
 ═════╪═ PHASE 1: EXCHANGE key → token (once per ~15 min, DB-backed) ═════════
      │                              │                           │
      │ TLS handshake ◄═════════════►│  ← key + token are bearer secrets
      │                              │                           │
      │ POST /v1/token               │                           │
      │ Authorization: Bearer sk_live_Xw9a… ───────────────────► │
      │                              │ require_api_key:          │
      │                              │  authenticate(key): SHA-256 lookup ──► │
      │                              │◄──── client row (or None → 401) ────── │
      │                              │ get_client_scopes ──────────────────►  │
      │                              │ issue_token(): HS256-sign a JWT with
      │                              │  {iss,aud,sub,name,scope,iat,exp=+900s}
      │                              │ log "token issued" → auth.log
      │◄─ 200 {access_token: eyJ… , token_type:"Bearer",         │
      │        expires_in:900, scope:"resources:read admin"} ────│
      │  (client caches the JWT; the API key goes back in the vault)

 ═════╪═ PHASE 2: CALL the API with the JWT (every request, STATELESS) ═══════
      │                              │                           │
      │ GET /v1/resources            │                           │
      │ Authorization: Bearer eyJ…(JWT) ───────────────────────► │
      │                              │ require_jwt("resources:read"):
      │                              │  verify_token(): jwt.decode(
      │                              │   algorithms=["HS256"]  ← pin (no alg:none)
      │                              │   audience=identity-api, issuer=…,
      │                              │   checks signature + exp)   NO DB LOOKUP
      │                              │  scope "resources:read" ∈ claims? ✔
      │◄─ 200 {resources:[…]} ───────│                           │
      │                              │                           │
      │ GET /v1/admin/stats  (JWT lacks 'admin') ──────────────► │
      │◄─ 403 {error:"insufficient_scope", required:"admin"} ────│  ← least privilege

 ═════╪═ FAILURE PATHS (all stateless — decided by the token itself) ═════════
      │ tampered / alg:none / wrong aud|iss → 401 invalid_token   │
      │ expired (exp passed)                → 401 token_expired   │
      │ no token                            → 401 unauthorized    │
      │                              │       (WWW-Authenticate: Bearer)

 ═════╪═ "FINISH": the token just EXPIRES ═══════════════════════════════════
      │                              │                           │
      │ after exp (~15 min) the JWT is dead; go back to PHASE 1.  │
      ▼                              ▼                           ▼
  no logout, no revoke      (short TTL IS the revocation story — a leaked
                             token is only useful until it expires)
```

Note the asymmetry with 06: **Phase 1 touches the DB** (the key is looked up and
its scopes read), but **Phase 2 never does** — that statelessness is the whole
point. The lifecycle **finishes** not with a logout or a revocation call but
when `exp` passes; because a JWT can't be revoked mid-life, the short TTL *is*
the containment. (For pre-expiry revocation you'd add a `jti` deny-list — see
*Further hardening*.)

## Trade-offs vs. API keys (06)

| | API key (06) | JWT (07) |
|--|--|--|
| Per-request cost | DB lookup | none (verify signature) |
| Lifetime | until revoked | minutes (short) |
| Revocation | immediate (per key) | **not before expiry** (mitigated by short TTL) |
| Carries claims/scopes | no | yes (`scope`, `sub`, …) |

The API key is the durable, revocable root credential; the JWT is the
disposable, self-describing working credential minted from it. Keep tokens
short-lived precisely because they can't be revoked mid-life.

## Threats addressed / notes

- **Token forgery / tampering:** rejected by signature + pinned algorithm.
- **Token replay to another service:** blocked by `aud`/`iss` checks.
- **Over-privilege:** scopes enforce least privilege per endpoint.
- **Interception:** the token is still a bearer secret — **run over TLS**
  (`USE_ADHOC_TLS=1`, or `TLS_CERT`/`TLS_KEY`).
- **Config safety:** the server refuses to start without `JWT_SECRET`.

## Further hardening (production)
Prefer an **asymmetric** algorithm (RS256/EdDSA) so resource servers verify
with a public key and never hold a token-minting secret; publish keys via JWKS
and support key rotation (`kid`); add a `jti` + short deny-list if you need
pre-expiry revocation; rate-limit the token endpoint.
