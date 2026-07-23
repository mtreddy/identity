# identity

Hands-on identity & authentication mechanisms, each self-contained and
runnable on one machine (Python + Flask + SQLite). Built to *learn by diffing*:
every version is a full copy of the previous one plus a few clearly-scoped
security fixes, each documented with the **threat** it addresses.

## Mechanism 01 — Login + Password

A progressive hardening of email + password login into a protected web app.
Each directory has its own `README.md` with the threat model.

| Directory | Adds | Focus |
|-----------|------|-------|
| [`01-login-password`](01-login-password/) | baseline | Minimal, readable login: bcrypt-hashed passwords, signed-cookie session, protected dashboard |
| [`02-secrets-transport`](02-secrets-transport/) | 1–3 | **Secrets & transport:** secret key from env, debug off, TLS/HTTPS |
| [`03-auth-robustness`](03-auth-robustness/) | 4–6 | **Auth robustness:** hardened cookie flags, brute-force rate limiting, timing/enumeration fix |
| [`04-web-hardening`](04-web-hardening/) | 7–9 | **Web attack surface:** CSRF tokens, bcrypt 72-byte truncation fix, security headers |
| [`05-defense-in-depth`](05-defense-in-depth/) | 10–13 | **Defense in depth:** revocable server-side sessions, password policy, auth logging, error pages |

See exactly what each step changes:

```bash
diff -ru 01-login-password           02-secrets-transport
diff -ru 02-secrets-transport 03-auth-robustness
diff -ru 03-auth-robustness 04-web-hardening
diff -ru 04-web-hardening 05-defense-in-depth
```

### Quick start (any directory)

```bash
cd <directory>
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# 02+ require a secret key:
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python seed.py
python app.py          # then open http://127.0.0.1:5000
```

Test accounts (from `seed.py`):
`alice@example.com` / `correct-horse-battery-staple` ·
`bob@example.com` / `hunter2`

## The 13 hardening items (mechanism 01)

1. Secret key from environment (no hard-coded key)
2. Debug server off by default
3. TLS / HTTPS
4. Hardened session cookie (`Secure`/`HttpOnly`/`SameSite`/expiry)
5. Brute-force / credential-stuffing rate limiting
6. Timing side-channel / user-enumeration fix
7. CSRF protection
8. bcrypt 72-byte truncation fix
9. Security response headers
10. Revocable server-side sessions ("log out everywhere")
11. Password policy (length + breached/common rejection)
12. Authentication logging (never logs passwords)
13. Custom error pages (no stack-trace leakage)

## Mechanism 06 — Machine / agent authentication

How a non-human client (script, service, autonomous agent) authenticates to an
API. JSON over `Authorization: Bearer` — no browser, cookie, or session.

| Directory | Focus |
|-----------|-------|
| [`06-api-keys`](06-api-keys/) | **API keys:** long-lived, hashed-at-rest, revocable per-key credentials sent on every request; per-client resource isolation |
| [`07-jwt`](07-jwt/) | **JWT:** exchange an API key at a token endpoint for a short-lived, signed, scoped token the API verifies statelessly (OAuth2 client-credentials) |

Key idea carried into 06: an API key is 256 bits of randomness, so it's hashed
with **SHA-256 (fast)**, not bcrypt — slow hashing only helps low-entropy human
passwords. See `06-api-keys/README.md` for the full threat model.

## Next mechanisms (planned)
Signup + email verification + password reset · TOTP/2FA · OAuth2 (full
authorization-code flow) · WebAuthn/passkeys · mTLS.
Given the sibling `agent-auth-research` work, machine/agent credential flows
are the current focus.
