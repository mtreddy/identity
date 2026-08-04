# Security design patterns & how they evolved

Every mechanism in this repo authenticates *something* — a user, an app, a
workload, an agent. This document is the cross-cutting answer to "is there a
pattern underneath all of them, and how did these techniques get here?" It reads
the 31 mechanisms not as a list but as **one design skeleton** instantiated at
increasing sophistication, and as an **evolutionary arc** driven by threats.

It's the conceptual companion to [PROVISIONING.md](PROVISIONING.md) (where
identities *come from*) and [AGENT_MODEL_AUTH.md](AGENT_MODEL_AUTH.md) (the
agent-series design record). The repo's two rules — *every change is tied to a
threat*, and *learn by diffing consecutive mechanisms* — mean the numbering is
itself a timeline: each mechanism is the previous one plus a fix for the next
exposed weakness.

---

## 1. The one meta-pattern

Strip away the specifics and every mechanism is the same five-beat **credential
lifecycle**:

```
   issue / provision  →  present  →  verify  →  authorize  →  rotate / revoke / expire
   └─ who mints the       └─ how the └─ prove   └─ decide     └─ how it ends
      identity & secret       caller     it's      what the
      (25, 26, 18, seed)      shows it   genuine   caller may do
```

A password (01) and an on-behalf-of agent token (32) are the *same shape* at
different points on a curve. Once you see the skeleton, the catalog is a study of
how to make each beat stronger:

| Beat | Weak form | Strong form | Seen at |
|------|-----------|-------------|---------|
| issue | hardcoded in `seed.py` | self-service, verified, gated | 25, 26, 18 |
| present | send the secret every call | prove possession of a key | 11–13, 17, 31 |
| verify | look it up in a DB | check a signature statelessly | 07, 10, 30 |
| authorize | "authenticated = allowed" | scope + audience + per-object | 09, 27, 30, 32 |
| end | valid until revoked | short TTL + rotation + deny-list | 08 |

---

## 2. The recurring patterns

Named patterns that show up again and again, with the mechanisms that embody
them:

### Store the proof, not the secret
Never persist the credential; persist a one-way hash of it. **bcrypt** for
low-entropy human passwords (deliberately slow), **SHA-256** for high-entropy
keys/tokens (fast is fine — they can't be brute-forced). A DB leak then yields
nothing usable. — `01` (bcrypt), `06`/`08`/`25`/`26` (SHA-256).

### Gatekeeper (the decorator)
Authorization is *one check wrapped around a handler*, defined once and reused —
the literal code pattern throughout: `login_required` (01), `require_api_key`
(06), `require_jwt` (07), `require_token` (09), `require_dpop` (31),
`require_bound_token` (12), `_require_delegation` (32). Centralizing the decision
is what makes "who may do what" reviewable in one place (see `27`'s notes).

### Least privilege / scoping
A credential grants exactly what's needed, no more: OAuth **scopes** (07/09/19),
**audience** binding (30), per-**object** ownership (27), per-client **model
allow-lists** (30–32), SPIFFE-ID **policy** (15). The valet-key idea — hand out a
key that opens one thing, not the master.

### Proof-of-possession over bearer
Don't accept "holds the string"; require "proves it holds the key." This is the
single biggest structural upgrade in the repo: mTLS client cert (11), cert-bound
token `cnf.x5t#S256` (12, RFC 8705), DPoP `cnf.jkt` (13/31, RFC 9449), WebAuthn
challenge signature (17). A leaked/stolen token becomes inert.

### Time-boxing as containment
When you *can't* revoke cheaply, make it expire fast. Short JWT TTLs (07,
minutes), one-time short-lived codes (09, 25), TOTP's 30-second window (16),
5-minute agent tokens (30). Short TTL *is* the revocation story for stateless
tokens.

### Delegation without secret-sharing
Give a scoped, disposable token — never the password or root credential. OAuth
Authorization Code (09), OIDC identity layer (10), RFC 8693 token exchange /
on-behalf-of (32). The user's password never reaches the app.

### Separation of parties
Keep *resource owner*, *client*, *authorization server*, and *resource server*
distinct so no single party is over-trusted — 09/10/19/24/26/30 all label these
roles explicitly even when co-hosted for the demo.

### Fail closed, leak nothing
One generic error; never an oracle. Generic `401` for any bad key (06), a
**timing equalizer** so "no such user" ≈ "wrong password" (03), **404-not-403**
so object IDs aren't an existence oracle (27), identical "check your email"
whether or not the account exists (25).

### Confused-deputy prevention
A credential can't be redirected to do something it wasn't meant to: **audience
binding** rejects a token replayed to another upstream (30), **OBO downscoping**
to `user ∩ agent` stops an agent exceeding its user (32), **exact `redirect_uri`
allow-list** stops codes going to an attacker (09).

### Defense in depth
No single control is load-bearing. `05` stacks revocable sessions + policy +
logging + error pages; `04` stacks CSRF + headers + hash-prehashing; the
`/vuln`-vs-`/safe` demos (20–23, 27) each show the primary fix *plus* backstops.

### Provisioning as its own attackable surface
*Who issues the identity* is a separate concern with its own threats:
self-service signup + verification for users (25), SCIM for IdP-driven lifecycle
(18), Dynamic Client Registration for clients (26). See PROVISIONING.md.

### Sign what you emit (a tamper-evident audit trail)
Almost every mechanism's README ends with *"ship the logs to alerting"* — but a
log a SIEM receives over the network is only as trustworthy as its sender. `34`
closes that loop: audit events are **HMAC-signed** so the receiver can prove
authenticity + integrity before storing them, and the *same* freshness tools
seen elsewhere defend the pipeline — a **timestamp window** (time-boxing, §2's
containment) plus a remembered **nonce** (the replay defense that DPoP's `jti`
and WebAuthn's challenge use, 13/17/31). It is "store the proof, not the secret"
turned outward: the audit stream is the artifact, so make it unforgeable. The
`/vuln` twin — an unverified webhook that accepts a forged `role.granted admin` —
shows why an authenticated *ingress* isn't enough if the *egress* is trusted
blindly.

These map onto the classic literature: **valet-key**, **claims-based identity**
(JWT/SAML/OIDC), the **ticket** lineage (Kerberos → SAML assertion → JWT),
**federated identity**, **trusted-subsystem vs. delegation/impersonation**
(exactly the `30` → `32` distinction), and **message authentication /
non-repudiation** for a tamper-evident audit trail (`34`).

---

## 3. How the techniques evolved

Seven pressures shaped the arc; each fix exposed the next weakness.

### 3.1 Secret-sharing → proof without sharing
Passwords (01) require *both* sides to know the secret. Every leap since removes
shared secrets: HS256 (07, a verifier can also *mint*) → **RS256 + JWKS** (10,
verifiers hold only the public key) → **`private_key_jwt`** (30, nothing secret
on the wire) → WebAuthn / SPIFFE (17/15, only public keys stored). *Asymmetric
crypto is the throughline.*

### 3.2 Bearer → sender-constrained
For decades "possess the token = use the token" — fine until tokens leak through
logs, proxies, SSRF, or LLM prompts. The fix binds the token to a key:
mTLS (11) → **cert-bound tokens** (12, RFC 8705) → **DPoP** (13, RFC 9449) →
DPoP for agents (31). A stolen token alone stops working.

### 3.3 Long-lived → short-lived + rotation (and back to stateful)
API keys live until revoked (06). JWTs cut lifetime to minutes (07) — but then
*can't* be revoked mid-life, so `08` adds **refresh rotation + reuse detection +
a `jti` deny-list**. Note the pendulum: **stateless (07) → hybrid (08)**, because
immediate revocation needs server state again.

### 3.4 Coarse → fine-grained authorization
"Authenticated = allowed" → **scopes** (07/09) → **audience** binding (30) →
**per-object / per-field / per-function** checks (27 — the OWASP BOLA/BFLA/mass-
assignment/data-exposure bugs that *authentication cannot fix*). `27` is the
punchline of the whole repo: **identity ≠ permission**.

### 3.5 Human → machine → workload → agent
Login (01–05) → API keys / JWT for services (06–08) → OAuth **delegation** for
third-party apps (09–10) → SAML / SCIM enterprise **federation & lifecycle**
(14/18) → **SPIFFE** workload identity for zero-trust meshes (15) → **AI agents
calling models** (30–32), which reassemble the entire toolkit: OAuth
client-credentials + `private_key_jwt` + audience/scope + DPoP + OBO delegation.

### 3.6 Implicit trust → zero-trust
From "inside the perimeter is trusted" to "verify identity on every hop, at every
layer": mTLS in the transport (11), SPIFFE per-workload (15), and OBO ensuring
even a *delegated* agent can't exceed its user (32). Trust also becomes
**mutual** — the agent verifies the model endpoint, not just vice-versa (30+).

### 3.7 Phishing pressure specifically
Password → **TOTP** (16, still phishable: a code can be relayed) →
**WebAuthn / FIDO2** (17, an origin-bound signature that *can't* be relayed).
And federation shed weight: **SAML** (2005-era XML, enterprise) → **OIDC** (JSON,
web/mobile-native) — same flow, lighter format (10 vs 14).

---

## 4. The arc in one sentence

The field has moved, relentlessly, from **shared, long-lived secrets that
authorize broadly and are trusted implicitly** toward **unshared, short-lived,
key-bound proofs that authorize narrowly and are verified at every hop** — and
the agent mechanisms (30–32) are simply that endpoint applied to a new kind of
caller.

```
 01 ─────────────────────────────────────────────────────────────────► 32
 password           API key    JWT      OAuth    mTLS/DPoP   SPIFFE   agent OBO
 shared secret      bearer     signed   deleg-   sender-     workload  scoped
 slow-hashed        + hashed   + scoped ated     constrained zero-trust delegation
   └── secret-sharing ··· proof-of-possession ··· fine-grained ··· zero-trust ──┘
```

## 5. Reading order for the patterns

- **The lifecycle skeleton:** `01` → `06` → `07` → `08` (same shape, growing up).
- **Proof-of-possession:** `11` → `12` → `13` (cert → cert-bound → keys), then `17`.
- **Delegation & federation:** `09` → `10` → `19`, then `14`, then `32`.
- **Identity ≠ permission:** `27` (read this one whenever "but they're logged in"
  feels like enough).
- **Where identities come from:** PROVISIONING.md, `25`, `26`, `18`.
- **Trusting the audit trail itself:** `34` (read this one whenever a mechanism's
  README says "ship the logs to alerting").
