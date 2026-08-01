# 26 — OAuth2 Dynamic Client Registration (RFC 7591 / 7592)

In `09` the one OAuth client is a row `seed.py` writes by hand. Real deployments
can't hand-register every app, device, or SPA — so clients **register
themselves** at a protocol endpoint. This mechanism adds that endpoint and its
management API, and rewires the demo so the client that drives the flow is one
that *provisioned itself*, not a hardcoded row.

Builds on `../09-oauth2-auth-code-pkce`:

```bash
diff -ru ../09-oauth2-auth-code-pkce . 
```

This is the **Applications / clients** half of the cross-cutting provisioning
story (see `../PROVISIONING.md`); `25-signup-verification` provisions *users*.

## Files

| File | Role |
|------|------|
| `registration.py` | DCR primitives: id/secret/RAT generation + hashing, and the **metadata validation** (redirect-URI allow-list, scope clamping, auth method) |
| `app.py` | adds `POST /register` (RFC 7591) and `GET/PUT/DELETE /register/<id>` (RFC 7592); `/token` now also authenticates confidential clients |
| `db.py` | `oauth_clients` gains `client_secret_hash`, `reg_access_token_hash`, `token_endpoint_auth_method` |
| `seed.py` | registers the demo client **through the registration path**, records it in `demo_client.json` |
| `client_example.py` | drives register → read → OAuth flow → update → delete without a browser |
| `test.py` | happy path **plus** the gate, redirect/scope validation, token isolation, and secret-auth negatives |

## Endpoints

| Method + path | RFC | Auth | Purpose |
|---------------|-----|------|---------|
| `POST /register` | 7591 | initial access token | Create a client; returns `client_id`, a `client_secret` (confidential only), and a `registration_access_token` |
| `GET /register/<id>` | 7592 | registration access token | Read current client metadata |
| `PUT /register/<id>` | 7592 | registration access token | Replace client metadata (re-validated) |
| `DELETE /register/<id>` | 7592 | registration access token | Delete the client |

## Flow — how the communication starts and finishes

In `../09-oauth2-auth-code-pkce` the OAuth client is a row `seed.py` writes by
hand. Here the client **provisions itself**: it calls `POST /register` (gated by
an initial access token), the server **validates its metadata** (redirect-URI
allow-list, scope clamped to what's supported, auth method), and returns a fresh
`client_id`, a one-time `client_secret` (confidential clients only), and a
per-client `registration_access_token` (RAT). Only *then* does the normal
Auth-Code + PKCE flow run — with the just-registered client. Its lifecycle
**finishes** at `DELETE /register/<id>`.

```
 ┌─────────┐              ┌──────────────────────┐            ┌────────┐
 │ Client  │              │ OAuth server (app.py)│            │ oauth_ │
 │ (app)   │              │  127.0.0.1:5026      │            │ clients│
 └────┬────┘              └──────────┬───────────┘            └───┬────┘
      │                              │                            │
 ═════╪═ REGISTER (RFC 7591): self-provision a client ═══════════════════════
      │ POST /register               │                            │
      │ Authorization: Bearer <initial access token> ───────────► │ gate:
      │ {client_name, redirect_uris, │  constant-time compare;    │ fail closed
      │  auth_method, scope} ────────►│  validate_metadata:        │ if unset
      │                              │   redirect_uris absolute/https/no-frag;
      │                              │   scope CLAMPED to supported;
      │                              │   auth_method ok
      │                              │  store: client_secret_hash,│
      │                              │   reg_access_token_hash ──►│
      │◄─ 201 {client_id, client_secret (ONCE, confidential),     │
      │        registration_access_token (ONCE)} ─────────────────│

 ═════╪═ USE: the self-registered client runs Auth-Code + PKCE (from 09) ═════
      │ /authorize (client_id, PKCE S256, redirect_uri exact-match,│
      │             scope ⊆ granted) → login + consent → code      │
      │ POST /token  code + code_verifier                          │
      │  (confidential: + client_secret → verified vs hash;        │
      │   public "none": PKCE only, no secret) ──────────────────► │
      │◄─ 200 {access_token} ─────────────────────────────────────│

 ═════╪═ MANAGE (RFC 7592): authed by THIS client's RAT only ═════════════════
      │ GET /register/<id>  Authorization: Bearer <RAT> ────────► │ read metadata
      │ PUT /register/<id>  {new metadata} ─────────────────────► │ re-validated
      │ DELETE /register/<id> ──────────────────────────────────► │ removed
      │◄─ (unknown client OR wrong RAT → 401, no existence oracle) │
      ▼                              ▼                            ▼
  provisioned itself         secret + RAT stored HASHED (raw shown once);
                             "finish" = DELETE, or the RAT is the only key to it
```

Two provisioning controls carry the security: the **initial access token** stops
open-registration abuse (fails closed if unset; `OPEN_REGISTRATION=1` opts into
the risky open mode), and the **per-client RAT** scopes management to that one
client — editing or deleting another client, or presenting a bad RAT, both return
`401` with no existence oracle. This is the *clients* half of provisioning;
`../25-signup-verification` is the *users* half.

| # | Threat | Defense |
|---|--------|---------|
| 1 | **Open-registration abuse** — anyone bulk-creating clients | `POST /register` requires an **initial access token** (`REGISTRATION_TOKEN`), constant-time compared; it fails closed if unset. `OPEN_REGISTRATION=1` opts into the (documented, risky) open mode |
| 2 | **Malicious redirect_uri** — codes/tokens exfiltrated to an attacker | `validate_metadata` requires **absolute** URIs, **no fragment**, and **https** (plain http only for loopback). The allow-list is the primary OAuth control, so it's validated at registration and exact-matched at `/authorize` and `/token` |
| 3 | **Self-granted privilege** — a client asking for scopes it shouldn't have | Requested `scope` is **clamped** to the server-supported set at registration; `/authorize` then refuses any scope beyond what was granted |
| 4 | **Cross-client management** — one client editing/deleting another | Each client gets its own **registration access token**; management authorizes against *that client's* token only. Unknown client and bad token both return `401` (no existence oracle) |
| 5 | **Registration-DB leak → client impersonation** | `client_secret` and the registration access token are high-entropy and stored **hashed** (SHA-256, like API keys in `06`); the raw values are returned exactly once |
| 6 | **Confidential-client impersonation at the token endpoint** | Clients registered with `client_secret_basic`/`client_secret_post` must present the secret at `/token` (verified against the hash); public clients (`none`) rely on **PKCE** and hold no secret |

Carried over from `09`: PKCE (S256) required, one-time hashed authorization
codes, exact redirect-URI + client-id binding on the code, `state` on the
redirect, and the HS256 access-token issuance.

## Run it

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export JWT_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export REGISTRATION_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(24))')"
export PORT=5026
export PUBLIC_BASE_URL="http://127.0.0.1:5026"
python seed.py
python app.py
```

Register a client by hand:

```bash
curl -sX POST http://127.0.0.1:5026/register \
  -H "Authorization: Bearer $REGISTRATION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"client_name":"my-app","redirect_uris":["https://app.example/cb"],
       "token_endpoint_auth_method":"none","scope":"profile resources:read"}'
```

Or drive registration + the full flow headless:

```bash
API_BASE=http://127.0.0.1:5026 REGISTRATION_TOKEN=$REGISTRATION_TOKEN python client_example.py
python test.py          # inside the venv
```

## Limitations / further hardening

- **Software statements** (RFC 7591 §2.3) — a signed JWT of asserted metadata —
  are not implemented; the initial access token is the only gate here.
- **Secret rotation** for confidential clients isn't exposed (a real RFC 7592
  server rotates the secret on `PUT`); this demo keeps the secret stable and
  only rotates via re-registration.
- No **rate limiting** on `/register` — pair the initial-access-token gate with
  per-issuer quotas in production.
- The same "who provisions the identity, and how" question applies to API keys
  (`06`/`07`/`08`), workload certs/SVIDs (`11`/`12`/`15`), and SAML metadata
  (`14`) — see `../PROVISIONING.md`.
