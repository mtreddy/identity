# 08 — Token lifecycle (refresh, revocation, introspection)

Builds on [`../07-jwt`](../07-jwt/). Mechanism 07's JWTs are stateless and fast
but have one big gap: **they can't be revoked before they expire.** This step
adds the machinery a real token service needs, all centered on revocation:

- **Refresh tokens** — long-lived, opaque, hashed-at-rest, **revocable** handles
  that mint fresh short access tokens; **rotated on every use** with **reuse
  detection**.
- **Access-token revocation** — every access JWT carries a `jti`; revoking one
  adds it to a **deny-list** checked on each request.
- **Introspection** — an RFC 7662 `/v1/introspect` endpoint reports whether a
  token is currently active.

```bash
diff -ru ../07-jwt ./ | less
```

## Endpoints (new/changed vs 07)

| Endpoint | Auth | Purpose |
|----------|------|---------|
| `POST /v1/token` | API key | Issue **access JWT + refresh token** (was: access only) |
| `POST /v1/token/refresh` | refresh token | Rotate → new access + new refresh; **detects reuse** |
| `POST /v1/token/revoke` | none / the token | Revoke a refresh token and/or an access token (`jti`) |
| `POST /v1/introspect` | API key | RFC 7662 — `{active: true/false, ...}` |
| `GET /v1/resources` etc. | access JWT | now also reject tokens whose `jti` is revoked |

## Files (vs 07)

| File | Change |
|------|--------|
| `keys.py` | `generate_refresh_token()` + generic `hash_token()` |
| `tokens.py` | access JWTs now carry a unique `jti` |
| `db.py` | `refresh_tokens` + `revoked_jti` tables; rotate/revoke/deny-list ops |
| `app.py` | `/v1/token/refresh`, `/v1/token/revoke`, `/v1/introspect`; jti check |
| `client_example.py` | full lifecycle demo incl. reuse detection |

## Run it

```bash
cd 08-token-lifecycle
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export JWT_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python seed.py            # prints API keys once — copy one
python app.py            # http://127.0.0.1:5000
```

Full lifecycle in one go:

```bash
API_KEY=sk_live_...  python client_example.py
```

Or by hand:

```bash
KEY=sk_live_...
# get an access + refresh pair
curl -s -X POST -H "Authorization: Bearer $KEY" http://127.0.0.1:5000/v1/token
# rotate
curl -s -X POST -d "refresh_token=<REFRESH>" http://127.0.0.1:5000/v1/token/refresh
# revoke an access token before it expires
curl -s -X POST -d "access_token=<JWT>" http://127.0.0.1:5000/v1/token/revoke
# introspect (needs the API key)
curl -s -X POST -H "Authorization: Bearer $KEY" -d "token=<JWT>" http://127.0.0.1:5000/v1/introspect
```

## Key ideas

### Refresh-token rotation + reuse detection
Each refresh token is single-use: exchanging it **revokes it and issues a new
one**. If a *revoked* refresh token is presented again, the legitimate client
already rotated past it — so a second copy means it was **stolen**. The server
responds by revoking **every** refresh token for that client (the "family"),
forcing re-authentication with the API key. This is the OAuth2 best-practice
defense for public/mobile-style clients (RFC 6819 / OAuth Security BCP).

### Why refresh + access, not just one token
| | Access JWT | Refresh token |
|--|--|--|
| Format | signed JWT (claims) | opaque random secret |
| Lifetime | minutes | days |
| Verified by | signature (+ jti deny-list) | DB lookup of its hash |
| Sent to | every resource request | only the token endpoint |
| Revocable | via jti deny-list | directly (it's in the DB) |

Short access tokens limit the damage window; the refresh token is exposed
rarely (only at `/v1/token/refresh`) and is fully revocable.

### Revocation's cost
Checking the `jti` deny-list means resource requests now do a small indexed DB
lookup — we trade a little of 07's pure statelessness for the ability to kill a
token immediately. Deny-list rows store the token's `exp`, so they can be
pruned once the token would have expired anyway (the list stays small).

## Flow — how the communication starts and finishes

Builds on `../07-jwt`'s key→token exchange, but now `/v1/token` returns a
**pair**: a short access JWT (with a `jti`) *and* a long-lived, opaque **refresh
token** stored hashed. The access JWT is spent on resource calls (now also
checked against a `jti` deny-list); the refresh token is spent only at
`/v1/token/refresh`, which **rotates** it every time and **detects reuse**. The
lifecycle **finishes** the moment you want it to — via revocation — not only at
`exp`.

```
 ┌─────────┐              ┌─────────────────────┐            ┌────────┐
 │ Client  │              │  Flask API (app.py) │            │identity│
 │(has key)│              │   127.0.0.1:5000    │            │  .db   │
 └────┬────┘              └──────────┬──────────┘            └───┬────┘
      │                              │  (all over TLS)           │
 ═════╪═ ISSUE: key → access JWT + refresh token ═══════════════════════════
      │ POST /v1/token               │                           │
      │ Authorization: Bearer sk_live_…► authenticate(key) ─────► │
      │                              │ issue_token(): JWT w/ jti  │
      │                              │ create_refresh_token(): store SHA-256 ►│
      │◄─ 200 {access_token: eyJ…(jti=A), refresh_token: rt_1(opaque),│
      │        expires_in:900, refresh_expires_in:30d} ───────────│

 ═════╪═ USE: call resources with the access JWT (stateless + deny-list) ════
      │ GET /v1/resources  Bearer eyJ…► verify_token() (sig/exp/aud/iss)
      │                              │ is_jti_revoked(A)? ──────► │  ← small
      │                              │  ✘ revoked → 401 token_revoked  indexed
      │                              │  ✔ live + scope ok ↓        lookup
      │◄─ 200 {resources:[…]} ───────│                           │

 ═════╪═ REFRESH: rotate the refresh token (single-use) ════════════════════
      │ POST /v1/token/refresh       │                           │
      │ refresh_token=rt_1 ─────────►│ get_refresh_record(rt_1) ►│
      │                              │  revoked? ──┐             │
      │                              │   NO → revoke rt_1, issue │
      │                              │   fresh access(jti=B)+rt_2 ►│
      │◄─ 200 {access_token:eyJ…(B), refresh_token: rt_2} ────────│
      │                              │             │             │
      │  ── REUSE DETECTION ──       │             ▼             │
      │ POST /v1/token/refresh       │  revoked? YES (rt_1 already
      │ refresh_token=rt_1 (replay) ►│  rotated) → someone has a copy:
      │                              │  revoke_all_refresh_for_client() ►│
      │◄─ 401 invalid_grant ─────────│  (whole family killed → must
      │                              │   re-auth with the API key)

 ═════╪═ REVOKE + INTROSPECT ═══════════════════════════════════════════════
      │ POST /v1/token/revoke        │                           │
      │ access_token=eyJ…(B) ───────►│ revoke_jti(B, exp) ──────►│ deny-list
      │◄─ 200 {revoked:["access_token"]}  (RFC 7009: 200 even if
      │                              │   already invalid)        │
      │ POST /v1/introspect (API key)│                           │
      │ token=eyJ…  ────────────────►│ verify + jti check / DB lookup
      │◄─ 200 {active:true|false, sub, scope, exp, …}  (RFC 7662; bare
      │                              │   {active:false} for anything invalid)
      ▼                              ▼                           ▼
  next access token           "finish" = revoke a jti or a refresh token,
  when B expires or is revoked  OR let exp lapse — revocation is the new power
```

The trade with 07: resource calls now do **one small indexed `jti` lookup**, so
they're no longer purely stateless — that's the price of being able to kill a
token before `exp`. Refresh-token **rotation + reuse detection** is the headline:
a stolen refresh token is only useful until the real client next rotates, and
the replay that follows burns the whole family.

## Threats addressed

- **Stolen refresh token:** reuse detection revokes the whole family on the
  first replay.
- **Compromised access token:** revoke its `jti` to stop it before `exp`.
- **Leaked DB:** refresh tokens (and API keys) are stored only as SHA-256
  hashes.
- **Over-privilege:** scopes still enforced per route.
- **Interception:** everything is a bearer secret — **run over TLS**.
- **Introspection abuse:** `/v1/introspect` requires the API key, and returns a
  bare `{active:false}` for anything invalid (no detail leakage).

## Further hardening (production)
Asymmetric signing (RS256/EdDSA) + JWKS so verifiers hold no minting secret;
bind refresh tokens to the client (sender-constrained / DPoP); rate-limit the
token and introspect endpoints; periodically prune expired `revoked_jti` rows.
