# Agent ↔ Model authentication & authorization — design (ADR + pattern)

How an **AI agent** securely calls a **model / tool endpoint** over the network —
and, just as important, how the **agent verifies the model** it's talking to.
This is the design record for a planned mechanism series (`30`+); no code yet.
It fills the two authorization patterns the library still lacks — the
`client_credentials` grant and **RFC 8693 token exchange** — and adds the
agent-specific twist: trust here is **mutual**.

> **Status:** proposed · **Scope:** agent→model access + model→agent verification
> · **Featured authN:** `private_key_jwt` (RFC 7523) and SPIFFE/mTLS workload
> identity · **Out of scope:** A2A peer identity (Agent Card / JWS-JCS signing —
> a separate track), inference internals.

---

## 1. Context

An agent is a stateless model wrapped in a tool-feeding loop (see
`agent-auth-research/NOTES_llm_inference_and_agents.md`). When it "calls a model"
it opens a network request to an inference/tool endpoint — which may be a remote
SaaS gateway, a self-hosted cluster, or a **local** process on the same host. Two
properties make this different from an ordinary API client and drive the whole
design:

1. **Credentials transit untrusted context.** Tokens flow through prompts, tool
   output, logs, and traces. A long-lived bearer key *will* leak (prompt
   injection, a logged header, a poisoned tool result) and, once leaked, is
   replayable anywhere. So tokens must be **short-lived, audience-bound, scoped,
   and sender-constrained** — leakage must not equal access.
2. **The agent must distrust the endpoint too.** A spoofed or swapped model
   endpoint can exfiltrate the prompt (which often carries secrets/PII) and
   return poisoned output that steers the agent. So the agent must **authenticate
   the model endpoint and verify what model actually ran** — trust is *mutual*,
   not one-directional.

---

## 2. Decision — the model endpoint is an OAuth 2.1 **Resource Server**

Adopt the pattern the MCP authorization spec standardizes
(`RESOURCES_agent_identity.md` §2): the model/tool endpoint is its own OAuth
**Resource Server (RS)**; the agent is an OAuth **client**; a separate
**Authorization Server (AS)** issues **short-lived, audience-bound, scoped**
access tokens; the RS enforces *audience + scope + policy* on every call. Layer
**proof-of-possession** (DPoP or mTLS-bound) so a leaked token can't be replayed,
and **delegation** (token exchange) so an agent acting for a user never exceeds
that user's authority.

**The four token invariants** (the reason this beats a static key):

| Invariant | Enforced by | Threat it kills |
|-----------|-------------|-----------------|
| **Short-lived** | `exp` (minutes) | leaked token expires fast |
| **Audience-bound** | `aud` = canonical RS URI (RFC 8707 / 9728) | token can't be *passed through* to a different upstream API (the confused-deputy / MCP "no pass-through" rule) |
| **Least-privilege scoped** | `scope` per model/tool | a compromised agent can't call everything |
| **Sender-constrained** | DPoP (RFC 9449) or mTLS-bound (RFC 8705) | a *stolen* token is useless without the agent's key |

---

## 3. Two directions of trust

The core framing. Most designs cover only the first row; agents need both.

### 3a. Agent → Model (authenticate + authorize the caller)

*Who is the agent, may it invoke this model, and on whose behalf?*

**AuthN of the agent** (how it proves identity to obtain/use a token) — a menu,
featured picks in **bold**:

| Technique | Std | When | Repo basis |
|-----------|-----|------|-----------|
| Static API key (bearer) | — | ❌ the **anti-pattern** — long-lived, over-broad, unbound; use only as the `/vuln` foil | `06` |
| `client_credentials` + secret | OAuth 2.1 | simplest correct M2M baseline | *new* |
| **`private_key_jwt`** | **RFC 7523** | **agent signs a JWT assertion with its private key — no shared secret on the wire** | *new (TODO)* |
| **SPIFFE / mTLS workload identity** | RFC 8705 / SPIFFE | **the agent's platform identity (SVID / client cert) authenticates it; no minted secret at all** | `11`, `15` |

**AuthZ of the request** (what the agent may do):

- **Scopes** — `model:invoke`, `models:read`, `tools:call:<name>` (`09`, `19`).
- **Audience / resource indicators** (RFC 8707) — token minted *for this gateway*.
- **On-behalf-of delegation** (RFC 8693 token exchange) — the agent presents the
  end-user's token + its own identity and receives a **downscoped** token whose
  `sub` = user and `act` = agent. Least privilege: the agent can never do more
  than the user it serves. This is the central agentic control.
- **Policy / budget** — model allow-list, per-agent **cost ceiling**, rate limit,
  time-of-day (`19`'s `policy.py` shape). Spend is an authorization decision for
  agents.

### 3b. Model → Agent (authenticate the endpoint + verify what ran)

*Is this a genuine, authorized, untampered model — and which model/version
actually served my request?* Three layers, increasing assurance:

1. **Endpoint authentication.** The server proves its identity, not just "valid
   TLS." Prefer a **SPIFFE server SVID** or a pinned cert whose identity the
   agent checks against an allow-list (verify the *SPIFFE ID*, not the hostname —
   `15`). With mTLS/SPIFFE this is *mutual* in one handshake: both sides present
   SVIDs, satisfying 3a's channel auth and 3b's endpoint auth together.
2. **Model provenance.** The response carries a **signed model manifest** —
   `model_id`, `version`, weight **digest**, and the AS/vendor signature — so the
   agent verifies it got the model it asked for, not a silently swapped or
   fine-tuned-poisoned one. (`GET /.well-known/model-provenance`, or a signed
   `model` block in the invoke response.)
3. **Runtime attestation** (highest assurance, optional). A **remote-attestation
   quote** (TEE / NVIDIA Confidential Compute) proving the expected model ran in a
   genuine enclave on unmodified firmware — "proof of *what actually ran*." Ties
   to the confidential-computing / KV-cache-isolation thread in the research
   notes. The agent verifies the quote before trusting output for sensitive work.

---

## 4. Local vs remote model — same identity, different trust root

"Remote model" and "local model" are the **same pattern** with a different trust
anchor and transport; the agent code path is identical.

| Deployment | Endpoint auth (3b.1) | Transport | Agent auth (3a) | Notes |
|-----------|----------------------|-----------|-----------------|-------|
| Remote SaaS gateway | vendor cert / SPIFFE ID pin | HTTPS | `private_key_jwt` / OAuth token | classic MCP RS |
| Self-hosted cluster | internal-CA / SPIFFE SVID | mTLS | SPIFFE SVID (mutual) | one handshake covers both directions |
| **Local process** | **local SVID or UNIX-socket peer cred** (uid/pid) + **signed manifest** | loopback / UDS | local token or socket peer creds | a local model **still authenticates itself and is still verified** — "local" ≠ "trusted"; it can be swapped, or a malicious process can squat the port/socket |

The point for the teaching build: keep the agent's verification logic constant
and swap only the trust root, so the reader sees local and remote are one design.

---

## 5. API surface

```
Authorization Server (AS)
  POST /oauth/token
        grant_type=client_credentials                     (secret)
        grant_type=client_credentials                     + client_assertion (private_key_jwt, RFC 7523)
        grant_type=urn:ietf:params:oauth:grant-type:token-exchange   (on-behalf-of, RFC 8693)
        resource=<canonical RS URI>                        (RFC 8707 — audience)
  GET  /.well-known/oauth-authorization-server             (RFC 8414 metadata)
  GET  /.well-known/jwks.json                              (RS verify keys; multi-kid rotation)

Model gateway — Resource Server (RS)
  GET  /.well-known/oauth-protected-resource               (RFC 9728 — points agent at AS + audience)
  GET  /.well-known/model-provenance                       (signed model manifest: id, version, digest)
  GET  /v1/models                                          (scope: models:read)
  POST /v1/models/{model}:invoke                           (scope: model:invoke; DPoP proof; body=prompt)
                                                           (response includes signed `model` provenance block)
  POST /oauth/introspect                                   (RFC 7662 — only if opaque tokens)
```

**RS enforcement order on `:invoke`** (this ordering *is* the lesson):

```
verify JWS via JWKS → aud == canonical RS URI → scope ⊇ required
  → exp/nbf → DPoP/mTLS binding matches token → policy (model allow-list, budget)
  → invoke → sign & attach model provenance
```

**Agent-side verification before it trusts the endpoint:**

```
TLS/mTLS verify server → check server SPIFFE ID / pin against allow-list
  → verify model-manifest signature (+ attestation quote if required)
  → only then send the prompt + token
```

---

## 6. Threat model → control mapping

| Threat | Control |
|--------|---------|
| Token **leaked** via prompt/log/tool output | short-lived + **sender-constrained** (DPoP/mTLS) — a copied token is inert |
| Token **replayed** to a different upstream (confused deputy) | **audience binding** (RFC 8707/9728); RS rejects wrong `aud` — no pass-through |
| **Over-broad agent** (does more than its user) | **OBO token exchange** (RFC 8693) → downscoped `act` token; scopes |
| **Runaway spend** / abuse | per-agent **budget + rate limit** as an authZ decision |
| Shared client **secret leaks** | **`private_key_jwt`** / SPIFFE — nothing shared to steal |
| **Spoofed / squatted** model endpoint (local or remote) | **endpoint authN** — verify SPIFFE ID / cert pin, not hostname |
| **Swapped / poisoned** model weights | **signed model manifest** (digest) the agent verifies |
| Untrusted host ran the inference | **remote attestation** (TEE quote) — proof of what ran |
| Prompt-injection exfiltrates credentials | keep tokens **out of model context**; short TTL; PoP; egress policy |

---

## 7. How it maps to the library (learn-by-diffing)

Reuses `06` (bearer/keys), `07` (JWT verify/JWKS), `09`/`19` (scopes, resource +
`policy.py`), `11` (mTLS), `12` (cert-bound, RFC 8705), `13` (DPoP, RFC 9449),
`15` (SPIFFE SVID + verify-by-ID), `26` (DCR). **Net-new** it introduces:
`client_credentials`, **`private_key_jwt` (RFC 7523)**, **token exchange (RFC
8693)**, **resource indicators / PRM (RFC 8707 / 9728)**, and **model-side
provenance/attestation** — none of which exist in the repo yet.

---

## 8. Proposed mechanisms (after this doc is approved)

| # | Dir | Teaches | Vuln foil |
|---|-----|---------|-----------|
| 30 ✅ | `agent-model-oauth` | **built** — model gateway as RS; agent auth via **`private_key_jwt`** (and `client_credentials`); **audience + scope** + per-client model allow-list; resource-id **endpoint pin** via PRM (crypto server identity deferred to 31/33) | `/vuln` static API key: no `aud`, no scope, no expiry, no endpoint check |
| 31 | `agent-model-dpop` | **sender-constrained** access token (DPoP) — leaked token can't be replayed | replay a bearer token from another client |
| 32 | `agent-obo` | **on-behalf-of** delegation (RFC 8693) — `sub`=user, `act`=agent, downscoped | agent uses its own broad token for a user action |
| 33 | `model-provenance` | **signed model manifest** (+ optional TEE **attestation**) the agent verifies; local-vs-remote parity | `/vuln` unsigned/ swapped model accepted blindly |

Featured throughout: **`private_key_jwt`** and **SPIFFE/mTLS workload identity**
as the agent's credential; `client_credentials`-secret shown as the simpler
baseline; static key only ever as the insecure contrast.

---

## 9. References

MCP Authorization (2025-11-25) · RFC 7523 (JWT client auth / bearer) · RFC 8693
(token exchange) · RFC 8707 (resource indicators) · RFC 9728 (protected-resource
metadata) · RFC 8414 (AS metadata) · RFC 7662 (introspection) · RFC 9449 (DPoP)
· RFC 8705 (mTLS / cert-bound tokens) · RFC 7591 (DCR) · SPIFFE/SPIRE. See
`agent-auth-research/RESOURCES_agent_identity.md` for annotated links.
