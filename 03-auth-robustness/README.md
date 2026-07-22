# 03 — Login + Password · Auth robustness (cookie flags, rate limiting, timing)

Builds on `../02-secrets-transport` (which already added the env
secret key, debug-off, and TLS). This step strengthens the **authentication
mechanism itself**.

```bash
diff -ru ../02-secrets-transport ./ | less
```

## What we fix in this step

| # | Fix | File |
|---|-----|------|
| 4 | Hardened session cookie: `Secure`, `HttpOnly`, `SameSite`, expiry | `app.py` (`app.config`) |
| 5 | Brute-force / credential-stuffing protection (rate limiting) | `app.py` (`@limiter.limit`) |
| 6 | Close login timing side-channel (user enumeration) | `app.py` (`_DUMMY_HASH`) |

### 4. Hardened session cookie
**Threats: session hijacking, XSS cookie theft, CSRF, unbounded session life.**
- `HttpOnly` — scripts can't read the cookie, so an XSS bug can't exfiltrate it.
- `Secure` — the browser only sends it over HTTPS, so it can't leak on plain HTTP.
- `SameSite=Lax` — the cookie isn't attached to cross-site requests, blunting CSRF.
- `PERMANENT_SESSION_LIFETIME` — sessions expire, limiting how long a stolen or
  forgotten session stays valid.

### 5. Brute-force protection (rate limiting)
**Threats: password brute-forcing and credential stuffing.** The base version
accepted unlimited guesses, so an attacker could try millions of passwords, or
replay leaked username/password pairs at scale. We cap login POSTs **per IP**
(10/min) *and* **per account email** (5/min) — the per-account limit stops an
attacker who rotates IPs from hammering one victim. Exceeding a limit returns
HTTP 429 with a friendly retry message.
(In-memory counters here; use a shared store like Redis in production.)

### 6. Timing side-channel / user enumeration
**Threat: account enumeration.** The base code only ran bcrypt when the user
existed, so "no such user" returned faster than "wrong password." By measuring
response time an attacker learns which emails are registered — useful for
targeted phishing or focused brute-forcing. Fix: **always** perform one bcrypt
verification, against a fixed dummy hash when the account doesn't exist, so both
paths cost the same. (The generic error text already avoided leaking it in
words; this closes the timing leak.)

## Run it

```bash
cd 03-auth-robustness
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python seed.py

# Over HTTPS (recommended — Secure cookies work):
USE_ADHOC_TLS=1 python app.py          # https://127.0.0.1:5000

# Over plain HTTP for a quick test, relax the Secure flag so the cookie is sent:
# COOKIE_SECURE=0 python app.py
```

> `SESSION_COOKIE_SECURE` defaults to **on**. A Secure cookie is not sent over
> plain HTTP, so for an HTTP-only smoke test set `COOKIE_SECURE=0`. Leave it on
> (the default) whenever you serve over TLS.

## Still open (later steps)
CSRF tokens, bcrypt 72-byte truncation, security headers (→ 04-web-hardening);
revocable server-side sessions, password policy, auth logging, error pages
(→ 05-defense-in-depth).
