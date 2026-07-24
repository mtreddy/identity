# CLAUDE.md

Guidance for AI assistants working in this repository.

## What this repo is

A **teaching library of identity & authentication mechanisms**. Each mechanism
is a self-contained, runnable Flask + SQLite app in its own numbered directory
(`01-login-password` … `20-sql-injection`). It is not a product and there is no
shared application package — duplication between directories is *intentional*.

Two organizing principles drive almost every decision here:

1. **Learn by diffing.** Within a series (e.g. 01→05, 11→12), each directory is
   a full copy of the previous one plus a few clearly-scoped changes, so
   `diff -ru 04-web-hardening 05-defense-in-depth` is the lesson.
2. **Every change is tied to a threat.** Code and READMEs name the attack a fix
   defends against. A change that doesn't explain its threat doesn't belong.

## Layout

```
README.md          index of all mechanisms + the run/test instructions
TODO.md            backlog: planned mechanisms and per-mechanism enhancements
run-tests.sh       runs every mechanism's test.py, each in its own venv
testlib.py         shared stdlib-only test harness (imported by each test.py)
NN-name/           one self-contained mechanism (20 of them today)
```

Inside a mechanism directory, the recurring files:

| File | Role |
|------|------|
| `app.py` | the Flask server; routes + the mechanism's enforcement points |
| `db.py` | SQLite data layer (schema + queries); always parameterized |
| `seed.py` | creates sample users/clients/resources; prints secrets **once** |
| `test.py` | self-contained checks — happy path **and** security negatives |
| `README.md` | the threat model for this mechanism |
| `requirements.txt` | pinned deps, with comments saying *why* each is needed |
| `client_example.py` | non-browser client driving the flow end to end (API/agent mechanisms) |
| `templates/` | Jinja templates (browser-facing mechanisms) |
| topic modules | `tokens.py`, `oauth.py`, `keys.py`, `pki.py`, `saml.py`, `totp.py`, `webauthn.py`, `dpop.py`, `spiffe.py`, `scim.py`, `policy.py`, `crypto_keys.py`, … — the mechanism's core logic, kept out of `app.py` |

## Mechanism map

- **01–05** — login + password, progressively hardened (13 numbered fixes)
- **06–08** — machine/agent auth: API keys → JWT → refresh/revocation/introspection
- **09–10, 19** — OAuth2 Auth Code + PKCE → OpenID Connect → a scope-enforced resource demo
- **11–13, 15** — certificate/proof-of-possession identity: mTLS, cert-bound tokens (RFC 8705), DPoP (RFC 9449), SPIFFE/SVID
- **14, 18** — enterprise SSO: SAML 2.0, SCIM 2.0 provisioning
- **16–17** — second factor & passwordless: TOTP (RFC 6238), WebAuthn/passkeys
- **20** — SQL injection: `/vuln/*` vs `/safe/*` side by side

`README.md` holds the authoritative table with per-directory descriptions —
**update it whenever a mechanism is added or renumbered.**

## Running and testing

```bash
./run-tests.sh                 # all mechanisms, each in its own .venv
./run-tests.sh 09-* 16-totp    # only the named directories
cd 10-openid-connect && python test.py   # single mechanism, inside its venv
```

`run-tests.sh` picks a Python ≥ 3.10 (override with `PYTHON=...`), creates
`NN-*/.venv`, installs that directory's `requirements.txt`, and runs `test.py`.
All 20 currently pass; **keep it that way** — run the affected directories'
tests before considering a change done.

Running an app by hand:

```bash
cd NN-name
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"   # 02+
python seed.py
python app.py     # http://127.0.0.1:5000
```

Seeded accounts: `alice@example.com` / `correct-horse-battery-staple`,
`bob@example.com` / `hunter2`.

### Environment variables (consistent across mechanisms)

`PORT` (default 5000; macOS AirPlay takes 5000), `SECRET_KEY` (required from 02
on), `FLASK_DEBUG=1`, `TLS_CERT`/`TLS_KEY` or `USE_ADHOC_TLS=1` for local HTTPS,
`COOKIE_SECURE=0` for plain-HTTP smoke tests, plus mechanism-specific ones
(`API_KEY`, `JWT_SECRET`, `ACCESS_TTL`/`REFRESH_TTL`, `CERT_DIR`, `SVID_DIR`,
`OIDC_ISSUER`, `RP_ID`, `ORIGIN`, `SCIM_TOKEN`, …). Servers bind `127.0.0.1`
only. New code should follow the same `os.environ.get("NAME", default)` shape.

### Writing a `test.py`

Use the shared harness; stdlib only, no pytest.

```python
"""test.py — checks for NN-name. Exits nonzero on failure."""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import testlib as T  # noqa: E402

def main():
    T.clean(HERE)                       # delete generated dbs/keys/logs/certs
    proc, base = T.start_server(HERE)   # picks a free port; waits for ready
    T.check("name of the check", condition, "detail shown on failure")
    T.finish(proc)                      # tears down; exit 1 if anything failed
```

`testlib` helpers: `clean`, `start_server` (`env_extra=`, `args=`, `port=`,
`scheme=`, `ready="tcp"` for mTLS servers with no open endpoint), `run` (for
`seed.py`), `http`, `get_json`, `check`, `finish`. Every test must assert the
**security negatives**, not just the happy path — wrong PKCE verifier, `alg:none`
id_token, replayed DPoP proof, untrusted CA, tampered SAML assertion, the SQLi
payloads. That's the point of the test.

## Conventions

- **Python ≥ 3.10**, Flask 3.1.0, SQLite via stdlib `sqlite3`, deps pinned
  exactly in each `requirements.txt` with a comment explaining the need.
- **Prefer the standard library for the mechanism itself.** TOTP, HOTP,
  WebAuthn ceremonies, API-key hashing, and mTLS are hand-rolled on stdlib +
  `cryptography` so the reader sees the algorithm. The exception is where
  hand-rolling is itself the classic vulnerability — XML canonicalization uses
  `signxml`; note the reasoning when you make such a call.
- **Comments explain the security reasoning**, not the syntax. Module docstrings
  open with a short "what this file is and how the pieces fit" paragraph.
- **Parameterized SQL, always** (mechanism 20 exists to justify this).
- Passwords: bcrypt. High-entropy secrets (API keys, tokens): SHA-256 — slow
  hashing only helps low-entropy human passwords.
- Never log passwords or full secrets; `seed.py` prints a secret exactly once
  and stores only its hash.
- Generated artifacts are gitignored and regenerable: `identity.db`/`app.db`,
  `*.log`, `*.pem`/`*.crt`/`*.key`, `certs/`, `svids/`, `.flask_session/`,
  `.venv/`. **Never commit keys, certs, or databases.**

### README convention (per mechanism)

Title `# NN — Name (short parenthetical)`, then: what it builds on (with the
`diff -ru` command when it's a hardening step), a **Files** table, a
**Threats addressed** or numbered-fix table naming each threat, **Run it**, and
**Limitations / further hardening** — which motivates the next mechanism.

## Adding a new mechanism

1. Pick the next number; if it extends an existing one, `cp -R` that directory
   and strip generated artifacts (`.venv`, `__pycache__`, `*.db`, `*.log`,
   `*.pem`) so the diff is clean and readable.
2. Implement it; keep the mechanism's core logic in a named topic module, and
   `app.py` as the wiring.
3. Add `client_example.py` for non-browser flows and `test.py` with happy-path
   plus negative checks.
4. Write the `README.md` threat model.
5. Update the root `README.md` table and tick/adjust `TODO.md`.
6. Run `./run-tests.sh NN-name`, then the full suite.

Commit messages follow `Add mechanism NN: <topic>` for new mechanisms, and a
short imperative summary otherwise (e.g. `TODO: add XSS attack-vs-defense demo
(22-xss)`).

## Notes

- `20-sql-injection`'s `/vuln/*` endpoints are **intentionally exploitable**
  teaching material bound to localhost against a local SQLite file. Future
  `21-csrf` / `22-xss` demos (see `TODO.md`) follow the same vuln-vs-safe shape.
  Keep the vulnerable side obvious, isolated behind a `/vuln` prefix, and
  documented as such.
- `TODO.md` is the roadmap: next up are the OAuth2 Device Authorization Grant
  (RFC 8628) and magic-link / email OTP, plus CSRF/XSS/CORS demos and
  per-mechanism enhancements. Check it before proposing new work.
