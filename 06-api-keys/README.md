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
