# 30 — Agent → model over OAuth (client_credentials · private_key_jwt · audience + scope)

An **AI agent calls a remote model** the right way: it authenticates to an
authorization server and receives a **short-lived, audience-bound, scoped**
access token, and the **model gateway** (an OAuth 2.1 Resource Server) checks
signature + audience + scope + a per-client model allow-list on every call. A
`/vuln` endpoint shows the anti-pattern it replaces — a static bearer key with
none of those bindings.

This is the first mechanism of the agent↔model series in
[AGENT_MODEL_AUTH.md](../AGENT_MODEL_AUTH.md); DPoP sender-constraint (`31`) and
on-behalf-of delegation (`32`) build on it. It reuses the OIDC RS256/JWKS split
(`10`), scopes (`09`/`19`), and confidential-client auth (`26`), and adds the
two patterns the library lacked: the **client_credentials** grant and
**`private_key_jwt`** (RFC 7523) client authentication.

> Localhost teaching sandbox. The "model" is a deterministic stub — the point is
> the *access control* around it, which is identical whether the model is remote
> or local. The `/vuln` endpoint is intentionally insecure.

## Why not a static API key? (the threat)

Agents are the worst place to put a long-lived bearer key: tokens flow through
prompts, tool output, and logs, so they *leak*, and a leaked static key is
replayable **anywhere, forever, for every model**. The fix is four bindings on
the token — each kills a specific failure:

| Binding | Claim | Kills |
|---------|-------|-------|
| Short-lived | `exp` (5 min) | a leaked token expires fast |
| **Audience-bound** | `aud` = gateway's canonical resource (RFC 8707/9728) | replay/pass-through to a *different* upstream API |
| **Least-privilege scoped** | `scope` = `model:invoke` / `models:read` | a compromised agent doing everything |
| Per-client allow-list | checked at the RS | an agent calling models it was never granted |

Plus the agent proves identity **per token request** (no standing secret to
leak): featured here via **`private_key_jwt`** (nothing secret on the wire) and
`client_secret_basic` (the baseline).

## Files

| File | Role |
|------|------|
| `config.py` | the stable identifiers: `ISSUER` (AS) and `GATEWAY_RESOURCE` (the audience) |
| `crypto_keys.py` | AS RS256 signing key + JWKS (public key verifiers fetch) |
| `tokens.py` | mint/verify the access token; `aud`/`scope`/`exp`/`iss` bindings |
| `clientauth.py` | client auth at the token endpoint: `client_secret` and **`private_key_jwt`** (RFC 7523) with `jti` replay protection |
| `gateway.py` | the deterministic model stub + the model catalog |
| `db.py` | SQLite: clients (auth method, allowed scopes/models), `/vuln` api-keys, jti replay cache |
| `app.py` | the AS (`/oauth/token`, metadata, JWKS) + the RS (`/v1/models`, `:invoke`, PRM) + the `/vuln` foil |
| `seed.py` | provisions 3 agents; prints the secret + static key **once** |
| `client_example.py` | the agent: discover → verify endpoint → mint token → invoke; reusable helpers |
| `test.py` | happy path + the security negatives |

## API surface

```
Authorization server
  POST /oauth/token                             grant_type=client_credentials
                                                (client_secret_basic/_post OR private_key_jwt)
                                                scope=… resource=…            (RFC 8707)
  GET  /.well-known/oauth-authorization-server  (RFC 8414 metadata)
  GET  /.well-known/jwks.json                   (verify keys)

Model gateway (resource server)
  GET  /.well-known/oauth-protected-resource    (RFC 9728 — resource id + AS)
  GET  /v1/models                               (scope: models:read)
  POST /v1/models/<model>:invoke                (scope: model:invoke + allow-list)   ← SAFE
  POST /vuln/v1/models/<model>:invoke           (static API key, no bindings)        ← foil
```

**RS enforcement order on `:invoke`:** verify JWS via JWKS → `iss` → `aud` ==
gateway resource → `exp` → `scope` ⊇ `model:invoke` → per-client model allow-list
→ invoke. On any 401/403 the RS returns `WWW-Authenticate: Bearer
resource_metadata="…"` so the agent can discover how to authenticate (RFC 9728).

## Run it

```bash
cd 30-agent-model-oauth
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python seed.py          # prints agent-secret's secret + the /vuln static key ONCE
python app.py           # http://127.0.0.1:5000

# in another shell — set the two secrets seed printed:
BASE_URL=http://127.0.0.1:5000 \
  AGENT_SECRET=<cs_…> LEGACY_API_KEY=<sk-legacy-…> python client_example.py
```

The agent, by hand (private_key_jwt): fetch
`/.well-known/oauth-protected-resource`, confirm its `resource` matches the
gateway you expect, sign a client-assertion JWT with `agent_private_key.pem`,
POST it to `/oauth/token` with `resource=https://models.example/api`, then call
`/v1/models/gpt-sim:invoke` with the returned token.

## Endpoint verification — the agent verifies the model, too

Trust is mutual. Before sending a prompt (which often carries secrets), the
agent fetches the gateway's Protected Resource Metadata and **pins the canonical
`resource` id**, then mints its token bound to exactly that id. A token is
therefore usable only at the one gateway it was verified for. *Cryptographic*
endpoint identity — a SPIFFE server SVID / cert pin and a **signed model
provenance** manifest (which weights actually ran, optionally TEE-attested) —
is deliberately deferred to `31`/`33`; see [AGENT_MODEL_AUTH.md](../AGENT_MODEL_AUTH.md) §3b.

## Flow — how the communication starts and finishes

An AI agent calls a remote model the OAuth way. It first **discovers and pins**
the gateway's canonical resource id (so its token can only be used *there*), then
proves its identity **per token request** with `private_key_jwt` (nothing secret
on the wire) to get a **short-lived, audience-bound, scoped** access token, and
the gateway (a Resource Server) re-checks every binding on `:invoke`. The `/vuln`
foil is the anti-pattern it replaces: a static key with none of those bindings.

```
 ┌─────────┐          ┌──────────────────────┐      ┌──────────────────────┐
 │ Agent   │          │ Authorization server │      │ Model gateway (RS)   │
 │ +priv   │          │ /oauth/token, JWKS   │      │ /v1/... , PRM        │
 │  key    │          └──────────┬───────────┘      └──────────┬───────────┘
 └────┬────┘                     │                             │
 ═════╪═ DISCOVER + PIN the gateway (before any prompt) ═══════════════════════
      │ GET /.well-known/oauth-protected-resource ───────────────────────────►│
      │◄─ {resource: https://models.example/api, authorization_servers:[…]} ──│
      │  pin that canonical `resource` id (RFC 9728)                          │
      │                          │                             │
 ═════╪═ MINT a token (client authenticates per request) ══════════════════════
      │ POST /oauth/token        │                             │
      │  grant_type=client_credentials                         │
      │  client_assertion = signed JWT (private_key_jwt, RFC 7523),
      │  scope=model:invoke  resource=https://models.example/api (RFC 8707) ──►│
      │                          │ verify assertion vs client's
      │                          │  REGISTERED public key; jti unseen
      │                          │ mint RS256 JWT: aud=resource,
      │                          │  scope, exp=5min, iss ──────►│
      │◄─ 200 {access_token: eyJ…, token_type:"Bearer", expires_in:300} ──────│
      │                          │                             │
 ═════╪═ INVOKE the model (RS re-checks every binding) ═══════════════════════
      │ POST /v1/models/gpt-sim:invoke  Authorization: Bearer eyJ… ──────────►│
      │                          │        verify JWS via JWKS ─►│ (fetch keys
      │                          │◄────── public keys ──────────│  from AS)
      │                          │        iss ✔ → aud==our resource ✔ →
      │                          │        exp ✔ → scope ⊇ model:invoke ✔ →
      │                          │        gpt-sim ∈ this client's allow-list ✔
      │◄─ 200 {model output} ──────────────────────────────────────────────── │
      │  (any failure → 401/403 + WWW-Authenticate: Bearer                     │
      │   resource_metadata="…" so the agent can discover how to auth)         │

 ═════╪═ FOIL + FINISH ═══════════════════════════════════════════════════════
      │ POST /vuln/v1/models/gpt-sim:invoke  x-api-key: sk-legacy-… ─────────►│
      │◄─ 200  ← static key, NO aud/scope/exp/allow-list: replayable anywhere │
      ▼                          ▼                             ▼
  token pinned to ONE       "finish": token expires in 5 min → mint another;
  gateway + scope + model    nothing standing to leak (no bearer key at rest)
```

The four bindings (`exp`, `aud`, `scope`, per-client model allow-list) each kill
a specific failure of the static key — expiry, cross-upstream replay, over-broad
access, and calling un-granted models. And because the agent authenticates with
`private_key_jwt`, there's **no standing secret** in prompts/logs to leak.

## Threats addressed
| Threat | Defense |
|--------|---------|
| Leaked long-lived key → permanent access | short-lived tokens minted **per request** via `private_key_jwt`/`client_secret`; no standing bearer |
| Token replayed to another upstream (confused deputy) | **audience binding** — RS rejects any `aud` ≠ its resource (RFC 8707/9728) |
| Over-broad agent | **scopes** (`models:read` vs `model:invoke`) + **per-client model allow-list** |
| Stolen client secret | **`private_key_jwt`** — the private key never leaves the agent; nothing shared to steal |
| Replayed client assertion | single-use `jti` cache → second use is `invalid_client` |
| Forged assertion | verified against the client's **registered public key** |
| Agent talking to a spoofed model | endpoint **resource-id pin** via PRM before any prompt is sent |

## Limitations / further hardening
The access token is a **bearer** token: whoever holds it can use it until it
expires. `31-agent-model-dpop` makes it **sender-constrained** (DPoP) so a
*stolen* token is useless without the agent's key. `32-agent-obo` adds
**on-behalf-of** delegation (RFC 8693) so an agent acting for a user can't exceed
that user's authority. `33-model-provenance` adds the **signed model manifest +
attestation** the agent verifies. Also worth adding: per-agent **budget/rate
limits** as an authorization decision, `resource` validation against registered
audiences at the AS, and JWKS **key rotation** (multiple `kid`s).
