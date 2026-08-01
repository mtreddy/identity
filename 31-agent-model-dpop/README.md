# 31 — Agent → model, sender-constrained (DPoP, RFC 9449)

Builds directly on `../30-agent-model-oauth`. Mechanism 30's access token is a
**bearer** token — whoever holds the string can use it, so a token leaked
through a prompt, a log, or tool output is replayable by anyone. This step makes
the token **sender-constrained**: it's bound to a key the agent holds, and the
gateway checks a fresh **DPoP proof** on every call, so a *stolen token alone is
inert*. See exactly what changed:

```bash
diff -ru ../30-agent-model-oauth ./ | less
```

The application logic (client auth, audience, scope, model allow-list) is
unchanged from 30; what's added is proof-of-possession — the same DPoP mechanism
as `../13-dpop`, now protecting the model call.

> Localhost teaching sandbox. The "model" is a deterministic stub — the point is
> the *sender-constraint*. The `/vuln` endpoint is intentionally bearer-only.

## What this step adds

| # | Change | File |
|---|--------|------|
| 1 | Agent generates a **DPoP key** and sends a proof when fetching the token | `client_example.py`, `app.py` |
| 2 | Token carries **`cnf.jkt`** (the key thumbprint) and `token_type: DPoP` | `tokens.py`, `app.py` |
| 3 | Gateway requires `Authorization: DPoP <token>` **+ a fresh proof**, and checks proof-key == `cnf.jkt` | `app.py` (`require_dpop`) |
| 4 | `/vuln` becomes the **bearer** version of the call — a copied token replays there | `app.py` (`vuln_invoke`) |

The DPoP proof is a short-lived JWT the agent signs with its key on every
request; it binds the call to the HTTP method + URL (`htm`/`htu`), is single-use
(`jti`), and ties itself to the token (`ath` = hash of the access token). Read
`dpop.py`'s `verify_proof` as the threat model.

## The lesson: a stolen token is inert

```
agent (holds DPoP key)                 attacker (stole the token STRING only)
  POST …:invoke                          POST /vuln/…:invoke   Authorization: Bearer <tok>
    Authorization: DPoP <tok>              → 200  ← replay works (no proof-of-possession)
    DPoP: <proof signed by its key>
  → 200                                  POST /v1/…:invoke     Authorization: DPoP <tok>
                                           DPoP: <proof from attacker's OWN key>
                                           → 401  ← jkt ≠ cnf.jkt; the token isn't theirs
```

## Files

Same layout as 30, plus **`dpop.py`** (DPoP proof create/verify + RFC 7638 JWK
thumbprint, reused from `13-dpop`). The static-API-key foil from 30 is gone — the
foil here is the bearer path, so `db.py`/`seed.py` drop the `api_keys` table and
the `legacy-agent` client.

## API surface (changes from 30 in **bold**)

```
Model gateway (resource server)
  GET  /.well-known/oauth-protected-resource   + dpop_signing_alg_values_supported: [ES256]
  POST /v1/models/<model>:invoke               Authorization: DPoP <tok> + DPoP: <proof>   ← SAFE
  POST /vuln/v1/models/<model>:invoke          Authorization: Bearer <tok> (no proof)      ← foil
Authorization server
  POST /oauth/token                            + DPoP: <proof>  →  token_type=DPoP, cnf.jkt
```

**RS enforcement order on `:invoke`:** verify token (JWKS → iss → aud → exp) →
scope → **verify DPoP proof (sig / htm / htu / iat / jti-replay / ath)** →
**proof key thumbprint == token `cnf.jkt`** → per-client model allow-list.

## Run it

```bash
cd 31-agent-model-dpop
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python seed.py          # prints agent-secret's secret ONCE
python app.py           # http://127.0.0.1:5000
python client_example.py   # in another shell — shows the stolen-token contrast
```

## Flow — how the communication starts and finishes

Same mint→invoke shape as `../30-agent-model-oauth`, now **sender-constrained**.
The agent holds a DPoP key; it sends a signed **proof** when minting the token
(so the token comes back carrying `cnf.jkt` = that key's thumbprint and
`token_type: DPoP`), and a **fresh proof on every** `:invoke`. The gateway
requires the proof key to match `cnf.jkt` — so a token copied from a prompt or
log is inert without the key. The `/vuln` foil is the bearer path where that same
copied token still replays.

```
 ┌─────────┐          ┌──────────────────────┐      ┌──────────────────────┐
 │ Agent   │          │ Authorization server │      │ Model gateway (RS)   │
 │ +priv   │          │ /oauth/token         │      │ /v1/... , PRM        │
 │ +DPoP   │          └──────────┬───────────┘      └──────────┬───────────┘
 │  key    │                     │                             │
 └────┬────┘                     │                             │
 ═════╪═ MINT: token bound to the DPoP key ═══════════════════════════════════
      │ POST /oauth/token  (private_key_jwt, scope, resource)   │
      │  DPoP: proof{htm:POST, htu:/oauth/token, jti, iat, jwk:PUB} ─────────►│
      │                          │ verify client + DPoP proof;  │
      │                          │ jkt = thumbprint(jwk)        │
      │                          │ mint JWT: aud/scope/exp +     │
      │                          │  cnf={"jkt":jktA}, type=DPoP ►│
      │◄─ 200 {access_token: eyJ…(cnf=jktA), token_type:"DPoP"} ──────────────│
      │                          │                             │
 ═════╪═ INVOKE: token + a FRESH proof per call ════════════════════════════════
      │ POST /v1/models/gpt-sim:invoke                          │
      │  Authorization: DPoP eyJ…(cnf=jktA)                     │
      │  DPoP: proof{htm:POST, htu:this URL, jti', iat',        │
      │             ath:hash(access_token), jwk:PUB} ─────────────────────────►│
      │                          │   verify token (JWKS/iss/aud/exp) → scope →
      │                          │   verify proof (sig/htm/htu/iat/jti/ath) →
      │                          │   REQUIRE thumbprint(jwk)==cnf.jkt (jktA) →
      │                          │   model allow-list                │
      │◄─ 200 {model output} ─────────────────────────────────────────────────│
      │                          │                             │
 ═════╪═ THE POINT: a stolen token STRING is inert ═════════════════════════════
      │ attacker has eyJ…(cnf=jktA) but only their OWN key:      │
      │  POST /v1/…:invoke  DPoP <proof from attacker key> ──────────────────►│
      │◄─ 401  (proof jkt=jktB ≠ cnf jktA — the token isn't theirs)           │
      │  POST /vuln/…:invoke  Authorization: Bearer eyJ… (no proof) ─────────►│
      │◄─ 200  ← foil: bearer path, no proof-of-possession → replay works     │
      ▼                          ▼                             ▼
  every call re-proves      "finish": token expires (5 min); keep the DPoP key
  possession of the key      in the agent's memory/enclave, never in a prompt
```

Everything from 30 (audience, scope, model allow-list, `private_key_jwt`) still
holds; DPoP adds the proof-of-possession layer, so leakage of the token *string*
— the most likely failure for an agent — no longer means compromise.

## Threats addressed
| Threat | Defense |
|--------|---------|
| **Stolen/leaked token replayed** (prompt, log, tool output) | token bound to a key (`cnf.jkt`); every call needs a proof signed by it — the token alone is useless |
| Proof captured and **replayed** | single-use `jti` (replay cache) + short `iat` window |
| Proof **reused on a different call** | proof binds `htm`/`htu` (method+URL) and `ath` (the access token) |
| Attacker swaps in **their own** key | proof thumbprint must equal the token's `cnf.jkt` |
| *(inherited from 30)* wrong audience / scope / model / forged client assertion | audience binding, scope, per-client allow-list, `private_key_jwt` verification |

## Limitations / further hardening
DPoP stops *token* theft-replay but not a live attacker who also exfiltrates the
**DPoP private key** — keep that key in the agent's memory/enclave, short-lived,
and never in the prompt. The proof `jti` cache is in-process here; production
needs a shared store (TTL = proof max-age). Next in the series:
`32-agent-obo` adds **on-behalf-of** delegation (RFC 8693) so an agent acting for
a user can't exceed that user's authority; `33-model-provenance` adds the signed
model manifest + attestation the agent verifies. mTLS-bound tokens (RFC 8705,
`../12`) are the alternative sender-constraint when the transport is mTLS.
