# 32 — Agent → model, on-behalf-of a user (token exchange, RFC 8693)

Builds directly on `../31-agent-model-dpop`. Through 30–31 the agent calls the
model as **itself**: a `client_credentials` token carrying the *agent's* own
authority. But an agent almost always acts **for a user**, and it must not be
able to do more than that user may. This step adds **on-behalf-of delegation**:
the agent presents the user's token and receives a **downscoped** access token
whose `sub` is the *user* and `act.sub` is the *agent* — its authority is the
intersection of the user's and the agent's, so the agent **can never exceed the
user it serves**. See exactly what changed:

```bash
diff -ru ../31-agent-model-dpop ./ | less
```

DPoP (31) and audience/scope (30) are unchanged and still enforced — the only
new lesson here is delegation, so the `/vuln` foil differs from `/v1` *only* in
whether the call is attributed to a user.

> Localhost teaching sandbox. The "model" is a deterministic stub; the point is
> the *authorization scope*, not inference. `/oauth/user-token` is a dev stand-in
> for an OIDC login (mechanism 10) — see the note in `app.py`.

## What this step adds

| # | Change | File |
|---|--------|------|
| 1 | **Users** with their own authority (scopes + models), separate from agents | `db.py`, `seed.py` |
| 2 | A **user (subject) token** carrying the user's authority + a `may_act` pin to one agent | `tokens.py`, `app.py` (`/oauth/user-token`) |
| 3 | **`grant_type=token-exchange`** (RFC 8693): verify subject token, check `may_act`, **downscope** to user ∩ agent, mint `sub`=user / `act`=agent | `app.py` (`_grant_token_exchange`) |
| 4 | `/v1:invoke` now **requires** an OBO token and authorizes against the *user's* `authorized_models` | `app.py` (`invoke`, `_require_delegation`) |
| 5 | `/vuln:invoke` accepts the agent's **own** token and authorizes by the *agent's* allow-list — the confused deputy | `app.py` (`vuln_invoke`) |

The token's authority is computed **once, at exchange**, as `user ∩ agent`
(scopes and models). The gateway then enforces the `authorized_models` claim, so
the user's limit rides in the signed token and no user lookup is needed at the RS.

## The lesson: the agent cannot exceed the user

`agent-pk` is allow-listed for `gpt-sim` **and** `embed-sim`; user `carol` may
use `gpt-sim` **only**.

```
on behalf of carol (OBO token, sub=carol act=agent-pk)   agent as itself (its own token)
  POST /v1/…/gpt-sim:invoke    → 200                        POST /v1/…/embed-sim:invoke   → 403
  POST /v1/…/embed-sim:invoke  → 403  ← carol may not,          (delegation_required — no user)
        even though the agent may                            POST /vuln/…/embed-sim:invoke → 200
                                                                 ← confused deputy: the agent's
                                                                   own authority leaks into carol's
                                                                   context (what OBO prevents)
```

## Files

Same layout as 31, plus a **`users`** table and a user-token path. `dpop.py`,
`clientauth.py`, `crypto_keys.py`, `gateway.py` are unchanged from 31.

## API surface (changes from 31 in **bold**)

```
Authorization server
  POST /oauth/token   grant_type=client_credentials                (agent as itself — 30/31)
                    **grant_type=urn:ietf:params:oauth:grant-type:token-exchange**
                    **  subject_token=<user token>  subject_token_type=…:access_token**
                    **  → sub=user, act={sub:agent}, scope+models downscoped to user ∩ agent**
  POST /oauth/user-token   **dev stand-in for OIDC login → a subject token (may_act pinned)**
  GET  /.well-known/oauth-authorization-server   **grant_types_supported += token-exchange**
Model gateway (resource server)
  POST /v1/models/<model>:invoke     **requires an OBO token (act); authorizes user's models**  ← SAFE
  POST /vuln/v1/models/<model>:invoke  **agent's OWN token; authorizes the agent's models**     ← foil
```

**RS enforcement order on `/v1:invoke`:** verify token (JWKS → iss → aud → exp) →
scope → verify DPoP proof + `cnf.jkt` (31) → **token is delegated (`act` present)**
→ **model ∈ token `authorized_models` (the user ∩ agent set)**.

**AS downscope on exchange:** authenticate agent → verify DPoP → verify subject
token (sig / iss / `aud`=AS / `token_use`) → **`may_act.sub` == this agent** →
`scope = user ∩ agent ∩ requested` → `authorized_models = user ∩ agent` → mint
`sub`=user, `act`=agent.

## Run it

```bash
cd 32-agent-obo
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python seed.py          # provisions 2 agents + 2 users; prints agent-secret ONCE
python app.py           # http://127.0.0.1:5000
python client_example.py   # in another shell — OBO downscope vs. the /vuln deputy
```

## Flow — how the communication starts and finishes

Through 30–31 the agent called the model as **itself**. Here it acts **for a
user**: it presents the user's **subject token** and exchanges it (RFC 8693) for
a **downscoped** access token whose `sub` is the user and `act.sub` is the agent.
The exchange computes authority **once**, as `user ∩ agent`, and pins it into the
token's `authorized_models` — so the gateway needs no user lookup, and the agent
can **never exceed the user it serves**. The `/vuln` foil shows the confused
deputy: the agent's *own* token, authorized by the *agent's* allow-list.

```
 ┌─────────┐        ┌──────────────────────┐        ┌──────────────────────┐
 │ Agent   │        │ Authorization server │        │ Model gateway (RS)   │
 │ +DPoP   │        │ /oauth/token,        │        │ /v1/... , /vuln      │
 │  key    │        │ /oauth/user-token    │        └──────────┬───────────┘
 └────┬────┘        └──────────┬───────────┘                   │
 ═════╪═ GET the user's subject token (dev stand-in for OIDC login) ══════════
      │ POST /oauth/user-token (user=carol) ──────►│                          │
      │◄─ subject token: sub=carol, scope+models=carol's authority,          │
      │     may_act={sub: agent-pk}, aud=AS, token_use=user_identity ────────│
      │                          │                                           │
 ═════╪═ EXCHANGE it for an on-behalf-of token (downscope) ═══════════════════
      │ POST /oauth/token                          │                          │
      │  grant_type=…:token-exchange               │                          │
      │  subject_token=<carol's token>  (+ client auth + DPoP proof) ────────►│
      │                          │ authenticate agent; verify DPoP;          │
      │                          │ verify subject token: sig/iss/aud==AS/     │
      │                          │  token_use; may_act.sub == THIS agent ✔    │
      │                          │ downscope: scope = user∩agent∩requested;   │
      │                          │  authorized_models = user∩agent            │
      │◄─ OBO token: sub=carol, act={sub:agent-pk}, cnf.jkt, ────────────────│
      │     authorized_models=[gpt-sim]   (carol may gpt-sim only)            │
      │                          │                                           │
 ═════╪═ INVOKE on behalf of carol (RS authorizes the USER's models) ═════════
      │ POST /v1/models/gpt-sim:invoke  DPoP token + fresh proof ────────────►│
      │                          │        verify token+proof (31); act present?✔
      │                          │        gpt-sim ∈ authorized_models ✔       │
      │◄─ 200 {output} ─────────────────────────────────────────────────────│
      │ POST /v1/models/embed-sim:invoke  (agent MAY, but carol may NOT) ────►│
      │◄─ 403  ← embed-sim ∉ carol's authorized_models (agent can't exceed her)│
      │                          │                                           │
 ═════╪═ FOIL: confused deputy + FINISH ══════════════════════════════════════
      │ POST /v1/…:invoke  with the agent's OWN client_credentials token ────►│
      │◄─ 403 delegation_required  ← /v1 refuses a non-delegated token        │
      │ POST /vuln/…/embed-sim:invoke  agent's own token ────────────────────►│
      │◄─ 200  ← foil: authorized by the AGENT's allow-list, not any user —   │
      │        the agent's authority leaks into a user context (OBO prevents) │
      ▼                          ▼                                           ▼
  acts strictly within      "finish": OBO token expires; a new user request
  user ∩ agent               starts a fresh exchange (authority recomputed)
```

The whole lesson lives in the two `/v1` invokes: on behalf of carol the agent can
reach `gpt-sim` (she may) but is **403 on `embed-sim`** even though the agent
itself is allow-listed for it — because the token's authority was clamped to
`user ∩ agent` at exchange. The `/vuln` path, authorizing by the agent's own
models with no user attribution, is exactly the confused-deputy leak OBO closes.

## Threats addressed
| Threat | Defense |
|--------|---------|
| **Over-broad agent** — the agent does more, for a user, than that user may | token exchange downscopes to `user ∩ agent`; `/v1` authorizes the user's `authorized_models`, not the agent's |
| **Confused deputy** — the agent's own authority laundered into a user's request | `/v1` refuses a bare `client_credentials` token (`delegation_required`); every model call is attributed to a `sub` user |
| **Stolen user token** used by a different agent | `may_act` pins the one agent the user delegated to; another agent presenting it → `invalid_client` |
| **Access token laundered** as a subject token to forge authority | subject tokens are `aud`=AS + `token_use=user_identity`; an access token (`aud`=gateway) is rejected at exchange |
| Requesting **more scope than the user has** | effective scope = user ∩ agent ∩ requested; empty → `invalid_scope` |
| *(inherited from 31)* stolen/replayed access token | DPoP sender-constraint (`cnf.jkt`, fresh proof per call) |
| *(inherited from 30)* wrong audience / scope / forged client assertion | audience binding, scope, `private_key_jwt` verification |

## Limitations / further hardening
This is **single-hop** delegation (`act` one level deep). Real chains — user →
orchestrator agent → sub-agent — nest `act` inside `act`; each hop must only ever
*narrow* authority, and the RS should cap chain depth. The `may_act` pin here is
carried in the user token; a production AS may instead consult a delegation policy
store. The `/oauth/user-token` endpoint stands in for an OIDC login (mechanism 10)
and is unauthenticated **only** because it simulates that login — in production the
subject token is the user's real id/access token, obtained through the browser
flow. Next in the series: `33-model-provenance` closes the *other* direction of
trust — a signed model manifest (+ optional TEE attestation) the agent verifies,
so it knows *which* model actually served the request.
