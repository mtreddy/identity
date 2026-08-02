# Security verification flow — keeping vulnerabilities from leaking out

This repo is a **teaching library**: some mechanisms (`20`–`23`, `27`, and the
`/vuln` foils in `30`–`32`) are *intentionally exploitable*. So "no
vulnerabilities exposed" here has a precise meaning:

- **Real vulnerabilities** — a `/safe`, `/v1`, or hardened path that fails to
  block the attack it claims to — must **never** ship. Every mechanism's
  `test.py` asserts these as **security negatives**.
- **Intentional vulnerabilities** — the `/vuln/*` demos — must stay **contained**:
  localhost-only, behind an obvious `/vuln` prefix, against a local SQLite file,
  and documented as such.

This document is the software flow that maintains both. It's the operational
companion to [PATTERNS.md](PATTERNS.md), [TRUST.md](TRUST.md),
[ALGORITHMS.md](ALGORITHMS.md), and [PROVISIONING.md](PROVISIONING.md), and it
codifies the rules already stated in [CLAUDE.md](CLAUDE.md).

---

## The flow

```
 ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
 │ 1. THREAT    │──►│ 2. IMPLEMENT │──►│ 3. TEST THE  │──►│ 4. CONTAIN   │──►│ 5. VERIFY    │
 │    FIRST     │   │  safe        │   │  NEGATIVES   │   │  intentional │   │  (the gate)  │
 │              │   │  defaults    │   │              │   │  vulns       │   │              │
 └──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘
  name the attack    parameterize,       assert the         /vuln prefix,       run-tests.sh
  the change         hash-at-rest,        happy path AND     localhost,          → all green,
  defends against    pin the alg,         every attack       gitignore           negatives
  (README threat)    bind localhost       is REJECTED        artifacts           included
```

### 1 — Threat first
Every change names the attack it defends against (the repo's core rule). If a
change doesn't map to a threat in the mechanism's README **Threats addressed**
table, it doesn't belong. This is what makes "is this secure?" answerable:
*secure against what?*

### 2 — Implement with the safe defaults
The non-negotiables, each tied to a mechanism that exists to justify it:

| Default | Rule | Enforced by / see |
|---------|------|-------------------|
| **Parameterized SQL** | never concatenate input into SQL; bind `?`; allow-list identifiers | `20`; every `db.py` |
| **Hash secrets at rest** | bcrypt for passwords, SHA-256 for high-entropy keys/tokens | `01`, `06`; [ALGORITHMS.md](ALGORITHMS.md) |
| **Pin the algorithm** | JWT/COSE verify with `algorithms=[…]`; never trust the token's `alg` | `07`, `10`, `13`, `30` |
| **Bind to localhost** | servers `app.run(host="127.0.0.1", …)` only | all mechanisms |
| **Gitignore artifacts** | keys, certs, DBs, logs, sessions are regenerable and never committed | `.gitignore`; `seed.py` prints secrets once |
| **Generic errors** | one response for missing/malformed/revoked/unknown; no enumeration oracle | `03`, `06`, `25`, `27` |
| **TLS for bearer secrets** | anything sending a token/key every request runs over TLS | `02`, `06`+; `USE_ADHOC_TLS=1` locally |

### 3 — Test the negatives (the heart of it)
A test that only checks the happy path proves nothing about security. **Every
`test.py` must assert that the attacks fail.** What "the negatives" means by
mechanism family:

| Family | Negatives the test MUST assert |
|--------|--------------------------------|
| Passwords / sessions (01–05) | wrong password → no session; missing CSRF → 400; cookie is `HttpOnly`; rate-limit trips → 429 |
| Tokens (06–08) | no/garbage token → 401; revoked/expired → 401; wrong scope → 403; refresh reuse → family revoked |
| OAuth / OIDC (09, 10, 19) | wrong PKCE verifier → `invalid_grant`; `alg:none` id_token rejected; bad `state`/`nonce`/`aud` rejected; replayed code fails |
| Cert / PoP (11–13, 15) | untrusted CA → handshake fails; revoked fingerprint → 401; stolen token + other key → `jkt`/`cnf` mismatch; replayed DPoP proof → 401 |
| SSO / SCIM (14, 18) | tampered SAML assertion → rejected; wrong audience → rejected; provisioning token required |
| 2FA / passkey (16, 17) | wrong TOTP code → denied; wrong-origin/rp-id or bad signature → rejected; counter regression → clone detected |
| Attack-vs-defense (20–23, 27) | the payload **succeeds on `/vuln`** *and* **is blocked on `/safe`** (both asserted) |
| Agent → model (30–32) | forged client assertion → 401; wrong audience/scope → 401/403; stolen token replays on `/vuln` but 401 on `/v1`; OBO can't exceed the user |

Use the shared `testlib` harness; stdlib only, no pytest. The negative assertions
*are* the security proof — the reason the suite exists.

### 4 — Contain the intentional vulnerabilities
The `/vuln/*` endpoints are teaching material, not a mistake. Keeping them safe:

- **Prefix:** always behind `/vuln` (or a clearly-labelled `DANGER` handler), so
  the vulnerable surface is obvious and never confused with production paths.
- **Localhost:** bound to `127.0.0.1` against a local SQLite file — no external
  reachability.
- **Asserted-as-a-contrast:** the test proves the vuln path is exploitable *and*
  the safe path blocks the same attack — the exploit is the lesson, not an
  accident.
- **Documented:** the README says plainly that `/vuln` is intentionally
  exploitable and not for deployment.

New `/vuln`-style demos (the `TODO.md` backlog) follow this exact shape.

### 5 — Verify (the gate)
```bash
./run-tests.sh                 # all mechanisms, each in its own .venv
./run-tests.sh 09-* 16-totp    # just the affected directories
cd 10-openid-connect && python test.py   # one mechanism, inside its venv
```
`run-tests.sh` picks a Python ≥ 3.10, builds each `NN-*/.venv`, installs that
directory's pinned `requirements.txt`, and runs `test.py`. **All 30 currently
pass — keep it that way.** Run the affected directories before considering a
change done, then the full suite before merge.

---

## Pre-merge checklist

- [ ] The change **names its threat** (README **Threats addressed** / numbered-fix
      table updated).
- [ ] Safe defaults held: parameterized SQL, hashed secrets, **pinned `alg`**,
      `127.0.0.1` bind, artifacts gitignored, generic errors.
- [ ] `test.py` asserts the **security negatives**, not just the happy path.
- [ ] Any `/vuln` surface is prefixed, localhost-only, asserted-as-contrast, and
      documented.
- [ ] No secret, key, cert, or DB is committed (`git status` clean of generated
      artifacts; `seed.py` prints secrets **once**).
- [ ] `./run-tests.sh <affected>` green, then the **full suite** green.
- [ ] README updated (root table + the mechanism's own README, incl. its **Flow**
      section).

---

## What this flow does and does not cover

- **Covers:** functional security correctness — that each mechanism enforces what
  it claims, verified by negative tests, and that intentional vulns stay
  contained. This is the gate every change passes. **It runs automatically in
  CI** (`.github/workflows/tests.yml`) on every push and PR, so a regression that
  exposes a real vulnerability fails the build.
- **Does not cover (by design, for a localhost teaching repo):** automated SAST,
  dependency-CVE scanning, fuzzing, or a hardened deployment posture. Deps are
  pinned in each `requirements.txt`; production hardening notes live in each
  mechanism's **Limitations / further hardening** section and in
  [TRUST.md](TRUST.md) §3. Adding `bandit` (SAST) and `pip-audit` (dependency
  CVEs) as further CI jobs would be the next layer.

> **Scope reminder.** This repo is bound to localhost against local SQLite for
> learning. The `/vuln` endpoints are intentionally exploitable *in that sandbox*
> and must not be deployed. "No vulnerabilities exposed" = the **safe paths hold**
> (asserted) and the **unsafe paths stay contained** (localhost + prefix +
> documented).
