# 06 — API keys (machine / agent authentication)

The first **machine-to-machine** identity mechanism. Instead of a human logging
in with a password, a *client* — a script, service, or autonomous agent —
authenticates every request with a long-lived **API key**. No browser, no
cookie, no session.

- **Web server / API:** Flask (Python), returns JSON
- **Backend / DB:** SQLite (`identity.db`)
- **Credential:** a 256-bit random key, sent as `Authorization: Bearer <key>`,
  stored **only as a SHA-256 hash**

## Files

| File                | Role                                                          |
|---------------------|--------------------------------------------------------------|
| `keys.py`           | Key generation + hashing (and *why* SHA-256, not bcrypt)     |
| `db.py`             | `clients`, `api_keys` (hashed, revocable), `resources`       |
| `app.py`            | JSON API: `/healthz`, `/v1/whoami`, `/v1/resources`          |
| `seed.py`           | Creates sample clients, mints one key each (printed once)    |
| `client_example.py` | Standalone caller showing an authenticated request + a 401   |

## Run it

```bash
cd 06-api-keys
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python seed.py          # prints the API keys ONCE — copy one
python app.py           # serves http://127.0.0.1:5000
```

In another shell:

```bash
KEY=sk_live_...        # a key printed by seed.py

curl -H "Authorization: Bearer $KEY" http://127.0.0.1:5000/v1/whoami
curl -H "Authorization: Bearer $KEY" http://127.0.0.1:5000/v1/resources
curl http://127.0.0.1:5000/v1/whoami          # 401 unauthorized (no key)

# or drive it with the sample client:
API_KEY=$KEY python client_example.py
```

## How the mechanism works

1. **Issue** (`db.create_api_key`) — generate `sk_live_` + 256 bits of
   randomness. Return the full key to the owner *once*; persist only its
   SHA-256 hash plus a non-secret display prefix.
2. **Present** — the client sends `Authorization: Bearer <key>` on every call.
3. **Verify** (`db.authenticate`) — hash the presented key, look up a matching
   non-revoked key whose client is active, stamp `last_used_at`, and resolve
   the owning client.
4. **Authorize** — the route (`@require_api_key`) serves only that client's
   resources; anything else returns a generic `401`.

## Flow — how the communication starts and finishes

Unlike 01–05 there is **no browser, no login form, no cookie, no session**. The
credential is issued **once** at provisioning time (the only moment the full key
exists in the clear), and from then on the client presents it as a bearer token
on **every** request. The server never stores the key — only its SHA-256 hash —
so verification is a hash-and-lookup, and the key is individually **revocable**.
Because the key rides on every call, the whole exchange **must** be over TLS.

```
 ┌─────────┐          ┌──────────────────┐   ┌──────────────────┐  ┌────────┐
 │ Operator│          │ seed.py / issuer │   │ Flask API (app.py)│  │identity│
 │         │          │  (keys.py)       │   │  127.0.0.1:5000   │  │  .db   │
 └────┬────┘          └────────┬─────────┘   └─────────┬────────┘  └───┬────┘
      │                        │                       │               │
 ═════╪═ ISSUE (once, at provisioning) ════════════════╪═══════════════╪══════
      │                        │                       │               │
      │ python seed.py ───────►│ generate_api_key():   │               │
      │                        │  "sk_live_" + 256 bits (secrets)      │
      │                        │ store SHA-256(key) + display_prefix ─►│
      │◄─ full key printed ONCE─│ (raw key never persisted)            │
      │  sk_live_Xw9a…          │                       │               │
      │  (copy it now — it's                            │               │
      │   unrecoverable later)  │                       │               │

 ┌─────────┐                                            │               │
 │ Client  │  (script / service / agent — holds the key)│               │
 └────┬────┘                                            │               │
      │                                                 │               │
 ═════╪═ START: AUTHENTICATED REQUEST (every call, over TLS) ═══════════════
      │                                                 │               │
      │  TLS handshake ◄═══════════════════════════════►│  ← key is a bearer
      │                                                 │     secret; TLS is
      │  GET /v1/whoami                                 │     mandatory
      │  Authorization: Bearer sk_live_Xw9a… ──────────►│               │
      │                                                 │ _extract_key()│
      │                                                 │ authenticate():
      │                                                 │  SHA-256(key) ─────►│
      │                                                 │  WHERE key_hash=? AND
      │                                                 │  revoked=0 AND active=1
      │                                                 │◄── client row / None │
      │                                                 │  ✔ stamp last_used_at ►│
      │                                                 │    g.client = client
      │                                                 │    log "auth ok" → auth.log
      │◄─ 200 {client_id, name} ────────────────────────│               │
      │                                                 │               │
      │  GET /v1/resources (same header) ──────────────►│ get_resources_for_client
      │◄─ 200 {resources:[…only this client's…]} ───────│───────────────►│

 ═════╪═ FAILURE PATH (missing / malformed / revoked / unknown key) ═════════
      │                                                 │               │
      │  GET /v1/whoami   (no or bad key) ─────────────►│ authenticate → None
      │                                                 │ log "auth failure"
      │◄─ 401 {error:"unauthorized"}                    │  (ONE generic error —
      │   WWW-Authenticate: Bearer ─────────────────────│   no case enumeration)

 ═════╪═ "FINISH": REVOCATION (no logout — keys are long-lived) ═════════════
      │                        │                        │               │
      │ revoke_api_key(id) ────────────────────────────────────────────►│ revoked=1
      │                        │                        │  next request with that
      │                        │                        │  key → 401 (lookup misses)
      ▼                        ▼                        ▼               ▼
  key retired            (rotate: issue new key, migrate, revoke old — zero downtime)
```

There is no "logout": a machine credential has no session to end. The lifecycle
**finishes** when the key is **revoked** (`revoked=1`), after which the
hash-lookup misses and every request with it returns `401`. Issuing a second key
before revoking the first is how you **rotate** without downtime.

### Why SHA-256 here, not bcrypt
Passwords are low-entropy and human-chosen, so we hash them *slowly* (bcrypt)
to resist brute force. An API key is 256 bits of true randomness — it can't be
brute-forced at any hash speed — so a **fast** hash is correct and keeps
per-request auth cheap. We still hash (not store raw) so a DB leak yields no
usable keys.

## Threats addressed

- **DB leak → credential theft:** keys are stored hashed; a dump reveals no
  usable keys.
- **Leaked/compromised key:** keys are individually **revocable**
  (`db.revoke_api_key`), and multiple keys per client enable zero-downtime
  **rotation** (issue new → migrate → revoke old).
- **Case enumeration:** one generic `401` for missing/malformed/revoked/unknown
  keys; a `WWW-Authenticate: Bearer` header is returned per spec.
- **Undetected abuse:** every auth success/failure is logged (client, path,
  IP) to `auth.log`; `last_used_at` surfaces stale or suspicious keys.
- **Interception:** the key is a bearer secret sent every request, so this
  **must** run over TLS (`USE_ADHOC_TLS=1` locally, or `TLS_CERT`/`TLS_KEY`).

## Limitations (motivating the next step)

- **No expiry / statefulness:** a key is valid until explicitly revoked, and
  every request needs a DB lookup.
- **No scopes / least privilege:** a key grants all of its client's access.

→ **`07-jwt`** addresses the first: the client exchanges its API key at a token
endpoint for a **short-lived, signed JWT** carrying scoped claims that the API
verifies statelessly (the OAuth2 *client-credentials* pattern).

## Further hardening (same lessons as mechanism 01)
Rate-limit the auth path (brute-force/abuse), add per-key scopes and
expiry/rotation policies, and ship auth logs to alerting.
